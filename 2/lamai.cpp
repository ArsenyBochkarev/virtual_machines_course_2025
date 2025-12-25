#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <cstring>
#include "lamai.hpp"
#include "runtime.hpp"

extern size_t* __gc_stack_top;
extern size_t* __gc_stack_bottom;

static inline void check(bool condition, char *msg, int32_t offset) {
    if (!condition)
        failure(msg, offset);
}

/* The unpacked representation of bytecode file */
typedef struct {
    char *string_ptr;                  /* A pointer to the beginning of the string table */
    int32_t  *public_ptr;              /* A pointer to the beginning of publics table    */
    char *code_ptr;                    /* A pointer to the bytecode itself               */
    int32_t   stringtab_size;          /* The size (in bytes) of the string table        */
    int32_t   global_area_size;        /* The size (in words) of global area             */
    int32_t   public_symbols_number;   /* The number of public symbols                   */
    char  buffer[MAX_FILE_SIZE];
} bytefile;

/* Gets a string from a string table by an index */
char* get_string(bytefile *f, int pos) {
    return &f->string_ptr[pos];
}

static int32_t code_size = -1;

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file(char *fname, bytefile *file) {
    FILE *f = fopen (fname, "rb");
    long size;

    if (!f)
        failure("%s\n", strerror(errno));

    if (fseek (f, 0, SEEK_END) == -1) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }

    size = ftell (f);
    if (size == -1) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }

    rewind (f);
    if (size != fread (&file->stringtab_size, 1, size, f)) {
        fclose(f);
        failure("%s\n", strerror(errno));
    }
    fclose (f);

    check(file->public_symbols_number > 0, "corrupted public_symbols_number in file. Offset: 0x%x", 0);
    check(size + sizeof(int32_t)*4 < MAX_FILE_SIZE, "Input file too big. Offset: 0x%x", 0);
    file->string_ptr = &file->buffer [file->public_symbols_number * 2 * sizeof(int32_t)];
    file->public_ptr = (int32_t*) file->buffer;
    file->code_ptr = &file->string_ptr [file->stringtab_size];

    code_size = size - file->public_symbols_number * 2 * sizeof(int32_t) + file->stringtab_size;

    return file;
}

struct Value {
    auint repr;

    Value() : repr(0) {};
    Value(auint x) : repr(x) {};
    Value(const Value &x) = default;
    Value& operator=(const Value& other) = default;
    static Value from_int(aint v) {
        return BOX(v);
    }
    static Value from_ptr(void* p) {
        return Value{reinterpret_cast<auint>(p)};
    }
    static Value from_repr(auint repr) {
        return Value{repr};
    }

    aint as_integer() const { 
        return static_cast<aint>(repr) >> 1;
    }
    void* as_ptr() const {
        return reinterpret_cast<void*>(repr);
    }

    lama_type get_type() const {
        return get_type_header_ptr(get_obj_header_ptr(as_ptr()));
    }

    bool is_integer() const { return UNBOXED(repr); }
    bool is_boxed() const { return !UNBOXED(repr); } // AKA is_reference()
    bool is_string() const { return is_boxed() && get_type() == STRING; }
    bool is_array() const { return is_boxed() && get_type() == ARRAY; }
    bool is_sexpr() const { return is_boxed() && get_type() == SEXP; }
    bool is_closure() const { return is_boxed() && get_type() == CLOSURE; }
    bool is_aggregate() const { return is_boxed() && (is_array() || is_sexpr() || is_string()); }

    size_t size() const {
        if (is_integer())
            return 0;
        return Llength(as_ptr());
    }
};

struct VMState {
    alignas(16) auint stack[MAX_STACK_SIZE];
    bytefile *bf;
    char *fname;
    char *code;
    int32_t ip;
    int32_t current_line;
    int32_t global_area_size;
    bool tmp_is_closure;

    struct Frame {
        int32_t return_address;
        int32_t base; // local variables index in stack
        int32_t arg_count;
        int32_t local_count;
        bool is_closure;

        Frame() : arg_count(-1), local_count(-1), return_address(-1), base(-1), is_closure(false) {}
        Frame(int32_t args, int32_t locals_cnt, int32_t b, bool is_frame_closure = false) 
            : arg_count(args), local_count(locals_cnt), return_address(-1), base(b), is_closure(is_frame_closure) {}
        auint get_local(VMState& vm, int32_t index) {
            return __gc_stack_top[base+index];
        }
        auint *get_local_ptr(VMState& vm, int32_t index) {
            return __gc_stack_top + base + index;
        }
        void set_local(VMState& vm, int32_t index, const Value &v) {
            __gc_stack_top[base+index] = v.repr;
        }

        auint get_arg(VMState& vm, int32_t index) {
            return vm.stack[base - arg_count + index];
        }
        auint *get_arg_ptr(VMState& vm, int32_t index) {
            return &vm.stack[base - arg_count + index];
        }
        void set_arg(VMState& vm, int32_t index, const Value &v) {
            vm.stack[base - arg_count + index] = v.repr;
        }

        Value get_captured(VMState &vm, int32_t index) {
            Value closure_val = Value(vm.stack[base - arg_count - 1]);
            data* closure = TO_DATA(closure_val.as_ptr());
            auint* captures = reinterpret_cast<auint*>(closure->contents);
            return Value::from_repr(captures[index + 1]);
        }
        auint *get_captured_ptr(VMState &vm, int32_t index) {
            Value closure_val = Value(vm.stack[base - arg_count - 1]);
            data* closure = TO_DATA(closure_val.as_ptr());
            auint* captures = reinterpret_cast<auint*>(closure->contents);
            return &captures[index + 1];
        }
        void set_captured(VMState& vm, int32_t index, const Value &v) {
            Value closure_val = Value(vm.stack[base - arg_count - 1]);
            data* closure = TO_DATA(closure_val.as_ptr());
            auint* captures = reinterpret_cast<auint*>(closure->contents);
            captures[index + 1] = v.repr;
        }
    };

    inline void push_frame(const Frame &f) {
        check(frames_top < MAX_FRAMES_NUM, "frames overflow. Offset: 0x%x\n", ip);
        frames[frames_top++] = f;
    }
    inline void pop_frame() {
        check(frames_top >= 0, "frames underflow. Offset: 0x%x\n", ip);
        frames_top--;
    }
    int32_t frames_top;
    Frame frames[MAX_FRAMES_NUM];

    inline size_t stack_size() {
        return __gc_stack_bottom - __gc_stack_top;
    }
    inline void push(Value v) {
        check(stack_size() + 1 < MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", ip);
        *(__gc_stack_bottom++) = v.repr;
    }
    inline Value pop() {
        check(stack_size() > 0, "stack underflow. Offset: 0x%x\n", ip);
        Value v{*(__gc_stack_bottom-1)};
        __gc_stack_bottom--;
        return v;
    }
    inline Value peek(int offset = 0) {
        assert(__gc_stack_bottom - offset - 1 >= __gc_stack_top);
        return Value{*(__gc_stack_bottom - offset - 1)};
    }

    inline auint get_global(int idx) const {
        return stack[idx];
    }
    inline auint* get_global_ptr(int idx) {
        return &stack[idx];
    }

    inline void get_int_from_code(int32_t *v, char* code) {
        check(ip + sizeof(int32_t) <= code_size, "reading beyond code segment. Offset: 0x%x\n", ip);
        std::memcpy(v, code + ip, sizeof(int32_t));
        ip += sizeof(int32_t);
    }
    inline void get_char_from_code(int8_t *v, char* code) {
        check(ip + sizeof(int8_t) <= code_size, "reading beyond code segment. Offset: 0x%x\n", ip);
        std::memcpy(v, code + ip, sizeof(int8_t));
        ip += sizeof(int8_t);
    }

    inline Frame *get_current_frame() {
        return (!frames_top) ? nullptr : &frames[frames_top-1];
    }

    inline void execute_binop(uint8_t op) {
        // std::cout << "BINOP\n";
        int32_t res;
        Value b = pop();
        Value a = pop();
        if (op == Bytecode::Binop::LOW_EQ) {
            check(b.is_integer() || a.is_integer(), "one of the operands must be integer. Offset: 0x%x\n", ip);
            if (a.is_integer() && b.is_integer()) {
                int32_t b_int = b.as_integer();
                int32_t a_int = a.as_integer();
                res = (a_int == b_int);
            } else res = 0; // Integers are never equal to values of other types
            push(Value::from_int(res));
            return;
        }
        check(b.is_integer(), "operand must be integer. Offset: 0x%x\n", ip);
        int32_t b_int = b.as_integer();
        check(a.is_integer(), "operand must be integer. Offset: 0x%x\n", ip);
        int32_t a_int = a.as_integer();

        switch (op) {
            case Bytecode::Binop::LOW_ADD: { // ADD
                // Addition with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) + static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_SUB: { // SUB
                // Subtraction with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) - static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_MUL: { // MUL
                // Multiplication with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) * static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_DIV: { // DIV
                check(b_int != 0, "division by zero. Offset: 0x%x\n", ip);
                // Division with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) / static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_MOD: { // MOD
                check(b_int != 0, "division by zero. Offset: 0x%x\n", ip);
                // Division remainder with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) % static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_LT: // LT
                res = (a_int < b_int);
                break;
            case Bytecode::Binop::LOW_LE: // LE
                res = (a_int <= b_int);
                break;
            case Bytecode::Binop::LOW_GT: // GT
                res = (a_int > b_int);
                break;
            case Bytecode::Binop::LOW_GE: // GE
                res = (a_int >= b_int);
                break;
            case Bytecode::Binop::LOW_EQ: // EQ
                assert(false && "EQ case for BINOP should be handled earlier");
            case Bytecode::Binop::LOW_NE: // NE
                res = (a_int != b_int);
                break;
            case Bytecode::Binop::LOW_AND: // Logical AND
                res = (a_int && b_int);
                break;
            case Bytecode::Binop::LOW_OR: // Logical OR
                res = (a_int || b_int);
                break;
        }
        push(Value::from_int(res));
    }
    inline void execute_const() {
        // std::cout << "CONST\n";
        int32_t constant;
        get_int_from_code(&constant, code);
        push(Value::from_int(constant));
    }
    inline void execute_string() {
        // std::cout << "STRING\n";
        int32_t string_index;
        get_int_from_code(&string_index, code); // Get string index from stack
        check(string_index >= 0 && string_index < bf->stringtab_size, "STRING: string index out of bounds. Offset: 0x%x\n", ip);
        char *str = get_string(bf, string_index);
        auto *v = Bstring((aint*)&str);
        push(Value::from_ptr(v));
    }
    inline void execute_sexp() {
        // std::cout << "SEXP\n";
        int32_t tag_index;
        get_int_from_code(&tag_index, code);
        int32_t elem_count;
        get_int_from_code(&elem_count, code);
        check(elem_count >= 0, "SEXP: negative element count. Offset: 0x%x\n", ip);
        check(elem_count < MAX_ARGS_NUM, "SEXP: too many elements. Offset: 0x%x\n", ip);

        check(tag_index >= 0 && tag_index < bf->stringtab_size, "SEXP: tag index out of bounds. Offset: 0x%x\n", ip);
        char *tag = get_string(bf, tag_index);
        aint tag_hash = LtagHash(tag);
        aint args[MAX_ARGS_NUM];
        for (int i = 0; i < elem_count; i++) {
            Value elem = pop();
            args[elem_count - i - 1] = (aint)elem.repr;
        }
        args[elem_count] = tag_hash;
        void* v = Bsexp(args, BOX(elem_count + 1));

        push(Value::from_ptr(v));
    }
    inline void execute_sti() {
        // std::cout << "STI\n";
        Value ref = pop();
        check(ref.is_boxed(), "STI: argument should be reference. Offset: 0x%x\n", ip);

        auint* ref_ptr = reinterpret_cast<auint*>(ref.repr);
        Value val = pop();
        *ref_ptr = val.repr;

        push(val);
    }
    inline void execute_sta() {
        // std::cout << "STA\n";
        Value val = pop();
        Value idx_val = pop();
        if (idx_val.is_integer()) {
            int32_t idx = idx_val.as_integer();
            Value agg = pop();
            check(agg.is_aggregate(), "STA: non-aggregate argument. Offset: 0x%x\n", ip);
            check(idx >= 0 && idx < agg.size(), "STA: aggregate index out of bounds. Offset: 0x%x\n", ip);
            Bsta(agg.as_ptr(), idx_val.repr, val.as_ptr());
        } else {
            check(idx_val.is_boxed(), "STA: second operand should be reference. Offset: 0x%x\n", ip);
            Bsta(idx_val.as_ptr(), idx_val.repr, val.as_ptr());
        }
        push(val);
    }
    inline void execute_jmp() {
        // std::cout << "JMP\n";
        int32_t loc;
        get_int_from_code(&loc, code);
        check(loc <= code_size, "incorrect jump destination. Offset: 0x%x\n", ip);
        ip = loc;
    }
    inline bool execute_end() {
        // std::cout << "RET/END\n";
        Value ret_val = pop();

        Frame *current_frame = get_current_frame();
        auto prev_stack_top = current_frame->base - current_frame->arg_count;
        if (current_frame->is_closure)
            prev_stack_top--;

        pop_frame();
        if (!frames_top)
            return true;

        Frame* caller_frame = get_current_frame();
        ip = caller_frame->return_address;
        __gc_stack_bottom = static_cast<size_t *>(__gc_stack_top + prev_stack_top);

        push(ret_val);
        return false;
    }
    inline void execute_drop() {
        // std::cout << "DROP\n";
        pop();
    }
    inline void execute_dup() {
        // std::cout << "DUP\n";
        push(peek(0));
    }
    inline void execute_swap() {
        // std::cout << "SWAP\n";
        Value a = pop();
        Value b = pop();
        push(b);
        push(a);
    }
    inline void execute_elem() {
        // std::cout << "ELEM\n";
        Value index = pop();
        check(index.is_integer(), "Element's index must be integer. Offset: 0x%x\n", ip);
        Value agg = pop();
        check(agg.is_aggregate(), "Aggregate must be string, SExpr, or an Array. Offset: 0x%x\n", ip);
        auto *result = Belem(agg.as_ptr(), index.repr);
        push(Value::from_ptr(result));
    }

    // LD
    inline void execute_ld_global() {
        // std::cout << "LD G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "LD: global index out of bounds. Offset: 0x%x\n", ip);
        Value target = Value::from_repr(get_global(addr));

        push(target);
    }
    inline void execute_ld_local() {
        // std::cout << "LD L\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->local_count, "LD: local index out of bounds. Offset: 0x%x\n", ip);
        Value target = Value::from_repr(cf->get_local(*this, addr));

        push(target);
    }
    inline void execute_ld_argument() {
        // std::cout << "LD A\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->arg_count, "LD: argument index out of bounds. Offset: 0x%x\n", ip);
        Value target = cf->get_arg(*this, addr);

        push(target);
    }
    inline void execute_ld_captured() {
        // std::cout << "LD C\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        Value closure_val = stack[cf->base - cf->arg_count - 1];
        check(addr >= 0 && addr < closure_val.size(), "LD: captured index out of bounds. Offset: 0x%x\n", ip);

        Value target = cf->get_captured(*this, addr);
        push(target);
    }

    // LDA
    inline void execute_lda_global() {
        // std::cout << "LDA G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "LDA: global index out of bounds. Offset: 0x%x\n", ip);
        auint *target = get_global_ptr(addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_local() {
        // std::cout << "LDA L\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "LDA: local index out of bounds. Offset: 0x%x\n", ip);
        auint *target = cf->get_local_ptr(*this, addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_argument() {
        // std::cout << "LDA A\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "LDA: argument index out of bounds. Offset: 0x%x\n", ip);
        auint *target = cf->get_arg_ptr(*this, addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_captured() {
        // std::cout << "LDA C\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        Value closure_val = stack[cf->base - cf->arg_count - 1];
        check(addr >= 0 && addr < closure_val.size(), "LDA: captured index out of bounds. Offset: 0x%x\n", ip);
        auint *target = cf->get_captured_ptr(*this, addr);
        push(Value::from_ptr(target));
    }

    // ST
    inline void execute_st_global() {
        // std::cout << "ST G\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "ST: global index out of bounds. Offset: 0x%x\n", ip);
        stack[addr] = v.repr;

        push(v);
    }
    inline void execute_st_local() {
        // std::cout << "ST L\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "ST: local index out of bounds. Offset: 0x%x\n", ip);
        cf->set_local(*this, addr, v);

        push(v);
    }
    inline void execute_st_argument() {
        // std::cout << "ST A\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "ST: argument index out of bounds. Offset: 0x%x\n", ip);
        cf->set_arg(*this, addr, v);

        push(v);
    }
    inline void execute_st_captured() {
        // std::cout << "ST C\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        Value closure_val = stack[cf->base - cf->arg_count - 1];
        check(addr >= 0 && addr < closure_val.size(), "ST: captured index out of bounds. Offset: 0x%x\n", ip);
        cf->set_captured(*this, addr, v);

        push(v);
    }

    inline void execute_cjmp(bool is_nz = false) {
        // std::cout << "CJMPz/CJMPnz\n";
        int32_t loc;
        get_int_from_code(&loc, code);
        check(loc <= code_size, "incorrect CJMPz/CJMPnz destination. Offset: 0x%x\n", ip);

        Value cond = pop();
        check(cond.is_integer(), "CJMPz/CJMPnz argument should be integer. Offset: 0x%x\n", ip);
        int32_t int_cond = cond.as_integer();
        if (int_cond == is_nz) /*((int_cond && is_nz) || (!int_cond && !is_nz))*/ {
            check(loc <= code_size, "incorrect CJMPz/CJMPnz destination. Offset: 0x%x\n", ip);
            ip = loc;
        }
    }
    inline void execute_begin() {
        int32_t arg_count;
        get_int_from_code(&arg_count, code);
        int32_t local_count;
        get_int_from_code(&local_count, code);
        check(arg_count >= 0 && local_count >= 0, "BEGIN: incorrect args or locals count. Offset: 0x%x\n", ip);

        Frame *prev_frame = get_current_frame();
        int32_t base = stack_size(); // base is the index in stack pointing to local variables
        // All args are already on the stack:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0

        Frame new_frame(arg_count, local_count, base, tmp_is_closure);
        tmp_is_closure = false;

        check(stack_size() + local_count < MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", ip);
        __gc_stack_bottom = __gc_stack_bottom + local_count;

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.set_local(*this, i, 0);

        push_frame(new_frame);
    }
    inline void execute_cbegin() {
        int32_t arg_count;
        get_int_from_code(&arg_count, code);
        int32_t local_count;
        get_int_from_code(&local_count, code);
        check(arg_count >= 0 && local_count >= 0, "CBEGIN: incorrect args or locals count. Offset: 0x%x\n", ip);

        Frame *prev_frame = get_current_frame();
        int32_t base = stack_size(); // base is the index in stack pointing to local variables
        // - closure: stack[base - arg_count - 1]
        // - args:    stack[base - arg_count] ... stack[base - 1]
        // - locals:  stack[base] ... stack[base + local_count - 1]

        Frame new_frame(arg_count, local_count, base, /*is_frame_closure=*/true);
        // All args are already on the stack:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0

        check(stack_size() + local_count < MAX_STACK_SIZE, "stack overflow. Offset: 0x%x\n", ip);
        __gc_stack_bottom = __gc_stack_bottom + local_count;

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.set_local(*this, i, 0);

        push_frame(new_frame);
    }
    inline void execute_closure() {
        // std::cout << "CLOSURE\n";
        int32_t target;
        get_int_from_code(&target, code);
        check(target >= 0 && target <= code_size, "CLOSURE: invalid target address. Offset: 0x%x\n", ip);

        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CLOSURE: negative capture count. Offset: 0x%x\n", ip);
        check(n < MAX_ARGS_NUM, "CLOSURE: too many arguments. Offset: 0x%x\n", ip);

        aint args[MAX_ARGS_NUM];
        args[0] = static_cast<aint>(target);
        for (int i = 0; i < n; i++) {
            int8_t type;
            get_char_from_code(&type, code); // G: 00, L: 01, A: 02, C: 03
            check(type >= 0 && type <= 3, "CLOSURE: invalid varspec type. Offset: 0x%x\n", ip);

            int32_t addr;
            get_int_from_code(&addr, code);

            Frame *cf = get_current_frame();
            Value v;
            switch (type) {
                case 0: // G(addr)
                    check(addr >= 0 && addr < global_area_size, "CLOSURE: global index out of bounds. Offset: 0x%x\n", ip);
                    v = Value::from_repr(get_global(addr));
                    break;
                case 1: // L(addr)
                    check(addr >= 0 && addr < cf->local_count, "CLOSURE: local index out of bounds. Offset: 0x%x\n", ip);
                    v = Value::from_repr(cf->get_local(*this, addr));
                    break;
                case 2: // A(addr)
                    check(addr >= 0 && addr < cf->arg_count, "CLOSURE: argument index out of bounds. Offset: 0x%x\n", ip);
                    v = Value::from_repr(cf->get_arg(*this, addr));
                    break;
                case 3: { // C(addr)
                    Value closure_val = stack[cf->base - cf->arg_count - 1];
                    check(addr >= 0 && addr < closure_val.size(), "LD: captured index out of bounds. Offset: 0x%x\n", ip);
                    v = cf->get_captured(*this, addr);
                    break;
                }
                default:
                    check(false, "invalid varspec for CLOSURE. Offset: 0x%x\n", ip);
            }
            args[i + 1] = static_cast<aint>(v.repr);
        }
        void* closure_obj = Bclosure(args, BOX(n + 1));
        push(Value::from_ptr(closure_obj));
    }
    inline void execute_callc() {
        // std::cout << "CALLC\n";
        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CALLC: negative arguments number. Offset: 0x%x\n", ip);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        // args:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0
        // - closure

        Value closure_val = peek(n);
        check(closure_val.is_closure(), "first argument to CALLC must be closure. Offset: 0x%x\n", ip);
        data* closure = TO_DATA(closure_val.as_ptr());
        auint* captures = reinterpret_cast<auint*>(closure->contents);

        // Do a JMP, basically
        // All captured variables should already be on the stack
        int32_t target = static_cast<int32_t>(captures[0]);
        check(target >= 0 && target < code_size, "CALLC: invalid target address. Offset: 0x%x\n", ip);
        ip = target;
        tmp_is_closure = true;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && (next_low == 3 || next_low == 2), "destination instruction after CALLC should be CBEGIN or BEGIN. Offset: 0x%x\n", ip);
    }
    inline void execute_call() {
        // std::cout << "CALL\n";
        int32_t target;
        get_int_from_code(&target, code);
        check(target >= 0 && target < code_size, "CALL: invalid target address. Offset: 0x%x\n", ip);

        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CALL: negative arguments number. Offset: 0x%x\n", ip);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        // Do a JMP, basically
        ip = target;
        tmp_is_closure = false;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && next_low == 2, "destination instruction after CALL should be BEGIN. Offset: 0x%x\n", ip);
    }

    inline void execute_tag() {
        // std::cout << "TAG\n";
        int32_t tag_index;
        get_int_from_code(&tag_index, code);
        check(tag_index >= 0 && tag_index < bf->stringtab_size, "TAG: string index out of bounds. Offset: 0x%x\n", ip);

        int32_t expected_elem_count;
        get_int_from_code(&expected_elem_count, code);
        check(expected_elem_count >= 0, "TAG: negative element count. Offset: 0x%x\n", ip);

        auint result = 0;
        Value tested_val = pop();
        if (!tested_val.is_sexpr()) {
            push(Value::from_int(result));
            return;
        }
        char *expected_tag = get_string(bf, tag_index);
        auto tag_hash = LtagHash(expected_tag);
        result = Btag(tested_val.as_ptr(), tag_hash, BOX(expected_elem_count));
        push(Value::from_repr(result));
    }
    inline void execute_array() {
        // std::cout << "ARRAY\n";
        int32_t n;
        get_int_from_code(&n, code);

        Value v = pop();
        auto result = Barray_patt(v.as_ptr(), BOX(n));
        push(Value::from_repr(result));
    }
    inline void execute_fail() {
        // std::cout << "FAIL\n";
        int32_t line;
        get_int_from_code(&line, code);
        int32_t column;
        get_int_from_code(&column, code);
        Value v = pop();

        Bmatch_failure(v.as_ptr(), fname, line, column);
        exit(1);
    }
    inline void execute_line() {
        // std::cout << "LINE\n";
        int32_t line;
        get_int_from_code(&line, code);
        current_line = line;
    }

    inline void execute_patt_str() {
        // std::cout << "PATT =str\n";
        Value b = pop();
        Value a = pop();
        auto result = Bstring_patt(a.as_ptr(), b.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_string() {
        // std::cout << "PATT =#string\n";
        Value v = pop();
        auto result = Bstring_tag_patt(v.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_array() {
        // std::cout << "PATT =#array\n";
        Value v = pop();
        auto result = Barray_tag_patt(v.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_sexp() {
        // std::cout << "PATT =#sexp\n";
        Value v = pop();
        auto result = Bsexp_tag_patt(v.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_ref() {
        // std::cout << "PATT =#ref\n";
        Value v = pop();
        auto result = Bboxed_patt(v.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_val() {
        // std::cout << "PATT =#val\n";
        Value v = pop();
        auto result = Bunboxed_patt(v.as_ptr());
        push(Value::from_repr(result));
    }
    inline void execute_patt_fun() {
        // std::cout << "PATT =#fun\n";
        Value v = pop();
        auto result = Bclosure_tag_patt(v.as_ptr());
        push(Value::from_repr(result));
    }

    inline void execute_read() {
        // std::cout << "CALL Lread\n";
        auto value = Lread();
        push(Value::from_repr(value));
    }
    inline void execute_write() {
        // std::cout << "CALL Lwrite\n";
        Value v = pop();
        check(v.is_integer(), "invalid write argument. Offset: 0x%x\n", ip);
        Lwrite(v.repr);
        push(Value::from_repr(0));
    }
    inline void execute_length() {
        // std::cout << "CALL Llength\n";
        Value v = pop();
        check(v.is_aggregate(), "non-aggregate argument to length builtin. Offset: 0x%x\n", ip);
        auto len = Llength(v.as_ptr());
        push(Value::from_repr(len));
    }
    inline void execute_to_string() {
        // std::cout << "CALL Lstring\n";
        Value v = pop();
        aint arg = static_cast<aint>(v.repr);
        aint args[1] = {arg};
        void* str = Lstring(args);
        push(Value::from_ptr(str));
    }
    inline void execute_make_array() {
        // std::cout << "CALL Barray\n";
        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "BARRAY: negative arguments number. Offset: 0x%x\n", ip);
        check(n < MAX_ARGS_NUM, "BARRAY: too many arguments. Offset: 0x%x\n", ip);

        aint args[MAX_ARGS_NUM];
        for (int i = 0; i < n; i++) {
            Value elem = pop();
            args[n - i - 1] = static_cast<aint>(elem.repr);
        }
        void* v = Barray(args, BOX(n));
        push(Value::from_ptr(v));
    }
};

void interpret(bytefile *bf, char *fname) {
    VMState vm;
    vm.bf = bf;
    vm.ip = 0;
    vm.code = bf->code_ptr;
    vm.global_area_size = bf->global_area_size;
    vm.tmp_is_closure = false;
    vm.fname = fname;
    vm.frames_top = 0;

    check(bf->global_area_size + 2 < MAX_STACK_SIZE, "initial stack size exceeds maximum. Offset: 0x%x\n", 0);
    // We use virtual stack here
    __gc_stack_top = static_cast<size_t *>(&vm.stack[0]);
    __gc_stack_bottom = static_cast<size_t *>(&vm.stack[bf->global_area_size + 2]);

    while(true) {
        uint8_t op = static_cast<uint8_t>(vm.code[vm.ip++]);
        switch (op) {
            case Bytecode::CONST: vm.execute_const(); break;
            case Bytecode::STRING: vm.execute_string(); break;
            case Bytecode::SEXP: vm.execute_sexp(); break;
            case Bytecode::STI: vm.execute_sti(); break;
            case Bytecode::STA: vm.execute_sta(); break;
            case Bytecode::JMP: vm.execute_jmp(); break;
            case Bytecode::RET:
            case Bytecode::END:
                if (vm.execute_end())
                    return;
                break;
            case Bytecode::DROP: vm.execute_drop(); break;
            case Bytecode::DUP: vm.execute_dup(); break;
            case Bytecode::SWAP: vm.execute_swap(); break;
            case Bytecode::ELEM: vm.execute_elem(); break;

            case Bytecode::LD_GLOBAL: vm.execute_ld_global(); break;
            case Bytecode::LD_LOCAL: vm.execute_ld_local(); break;
            case Bytecode::LD_ARGUMENT: vm.execute_ld_argument(); break;
            case Bytecode::LD_CAPTURED: vm.execute_ld_captured(); break;

            case Bytecode::LDA_GLOBAL: vm.execute_lda_global(); break;
            case Bytecode::LDA_LOCAL: vm.execute_lda_local(); break;
            case Bytecode::LDA_ARGUMENT: vm.execute_lda_argument(); break;
            case Bytecode::LDA_CAPTURED: vm.execute_lda_captured(); break;

            case Bytecode::ST_GLOBAL: vm.execute_st_global(); break;
            case Bytecode::ST_LOCAL: vm.execute_st_local(); break;
            case Bytecode::ST_ARGUMENT: vm.execute_st_argument(); break;
            case Bytecode::ST_CAPTURED: vm.execute_st_captured(); break;

            case Bytecode::CJMPZ: vm.execute_cjmp(); break;
            case Bytecode::CJMPNZ: vm.execute_cjmp(/*is_nz=*/true); break;
            case Bytecode::BEGIN: vm.execute_begin(); break;
            case Bytecode::CBEGIN: vm.execute_cbegin(); break;
            case Bytecode::CLOSURE: vm.execute_closure(); break;
            case Bytecode::CALLC: vm.execute_callc(); break;
            case Bytecode::CALL: vm.execute_call(); break;

            case Bytecode::TAG: vm.execute_tag(); break;
            case Bytecode::ARRAY: vm.execute_array(); break;
            case Bytecode::FAIL: vm.execute_fail(); break;
            case Bytecode::LINE: vm.execute_line(); break;

            case Bytecode::PATT_STR: vm.execute_patt_str(); break;
            case Bytecode::PATT_STRING: vm.execute_patt_string(); break;
            case Bytecode::PATT_ARRAY: vm.execute_patt_array(); break;
            case Bytecode::PATT_SEXP: vm.execute_patt_sexp(); break;
            case Bytecode::PATT_REF: vm.execute_patt_ref(); break;
            case Bytecode::PATT_VAL: vm.execute_patt_val(); break;
            case Bytecode::PATT_FUN: vm.execute_patt_fun(); break;

            case Bytecode::CALL_LREAD: vm.execute_read(); break;
            case Bytecode::CALL_LWRITE: vm.execute_write(); break;
            case Bytecode::CALL_LLENGTH: vm.execute_length(); break;
            case Bytecode::CALL_LSTRING: vm.execute_to_string(); break;
            case Bytecode::CALL_BARRAY: vm.execute_make_array(); break;

            default: {
                int high = op & 0xF0;
                if (high == Bytecode::STOP)
                    return;
                // We also need to execute BINOP
                if (high == Bytecode::BINOP_HIGH)
                    vm.execute_binop(op);
                else
                    check(false, "unknown bytecode: ", vm.ip);
            }
        }
    }
}

int main(int argc, char* argv[])
{
    __init();
    bytefile f;
    read_file(argv[1], &f);
    interpret(&f, argv[1]);
    __shutdown();
    return 0;
}
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stack>
#include <memory>
#include <cassert>
#include <sstream>
#include <errno.h>
#include <iostream>
#include <malloc.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>
#include <variant>
#include "lamai.hpp"
#include "runtime.hpp"

extern void* __gc_stack_top;
extern void* __gc_stack_bottom;

/* The unpacked representation of bytecode file */
typedef struct {
    char *string_ptr;              /* A pointer to the beginning of the string table */
    int  *public_ptr;              /* A pointer to the beginning of publics table    */
    char *code_ptr;                /* A pointer to the bytecode itself               */
    int  *global_ptr;              /* A pointer to the global area                   */
    int   stringtab_size;          /* The size (in bytes) of the string table        */
    int   global_area_size;        /* The size (in words) of global area             */
    int   public_symbols_number;   /* The number of public symbols                   */
    char  buffer[0];               
} bytefile;

/* Gets a string from a string table by an index */
char* get_string(bytefile *f, int pos) {
    return &f->string_ptr[pos];
}

static int code_size = -1;

/* Reads a binary bytecode file by name and unpacks it */
bytefile* read_file(char *fname) {
    FILE *f = fopen (fname, "rb");
    long size;
    bytefile *file;

    if (!f) {
        fprintf(stderr, "%s\n", strerror (errno));
        exit(1);
    }

    if (fseek (f, 0, SEEK_END) == -1) {
        fprintf(stderr, "%s\n", strerror (errno));
        fclose(f);
        exit(1);
    }

    size = ftell (f);
    if (size == -1) {
        fprintf(stderr, "%s\n", strerror(errno));
        fclose(f);
        exit(1);
    }

    file = (bytefile*) malloc (sizeof(int)*4 + size);
    if (!file) {
        fprintf(stderr, "*** FAILURE: unable to allocate memory.\n");
        fclose(f);
        exit(1);
    }

    rewind (f);
    if (size != fread (&file->stringtab_size, 1, size, f)) {
        fprintf(stderr, "%s\n", strerror (errno));
        free(file);
        fclose(f);
        exit(1);
    }
    fclose (f);

    file->string_ptr = &file->buffer [file->public_symbols_number * 2 * sizeof(int)];
    file->public_ptr = (int*) file->buffer;
    file->code_ptr = &file->string_ptr [file->stringtab_size];
    file->global_ptr = (int*) malloc (file->global_area_size * sizeof (int));

    // TODO: Think if this is really needed
    // CUSTOM CODE BELOW:
    code_size = size - file->public_symbols_number * 2 * sizeof(int) + file->stringtab_size;

    return file;
}

class RuntimeError : public std::exception {
private:
    std::string message;
    int32_t line_number;
    int32_t bytecode_offset;

public:
    RuntimeError(const std::string& msg, int32_t ln, int32_t offset)
        : message(msg), line_number(ln), bytecode_offset(offset) {
            std::stringstream str_stream;
            str_stream << std::hex << bytecode_offset;
            message += ". Line: " + std::to_string(line_number) + ", bytecode offset: 0x" + str_stream.str();
    }

    const char* what() const noexcept override {
        return message.c_str();
    }

private:
    static std::string to_hex(int n) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%08x", n);
        return std::string(buf);
    }
};

static inline void check(bool condition, const char *msg, int32_t line_number, int32_t offset) {
    if (!condition)
        throw RuntimeError(msg, line_number, offset);
}

struct Value;

struct SExpr {
    std::string tag;
    std::vector<Value> elements;
};
struct ValueWrapper {
    Value *data;
};
struct Array {
    std::vector<Value> elements;
};

constexpr auint uc = static_cast<auint>(-1) >> 1;
struct Value {
    auint repr;

    Value() : repr(0) {};
    Value(auint x) : repr(x) {};
    Value(const Value &x) = default;
    Value& operator=(const Value& other) = default;
    static Value from_int(aint v) {
        // Lowest bit for integers = 1
        auto masked = static_cast<auint>(v) & (uc >> 1);
        auto shifted = masked << 1;
        if (v < 0)
            shifted |= static_cast<auint>(1) << (sizeof(auint) * 8 - 1);
        return Value{shifted | 1};
    }
    static Value from_ptr(void* p) {
        // Lowest bit for ptrs = 0
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

    bool is_integer() const { return (repr & 1) != 0; }
    bool is_boxed() const { return (repr & 1) == 0; } // AKA is_reference()
    bool is_string() const { return is_boxed() && get_type() == STRING; }
    bool is_array() const { return is_boxed() && get_type() == ARRAY; }
    bool is_sexpr() const { return is_boxed() && get_type() == SEXP; }
    bool is_closure() const { return is_boxed() && get_type() == CLOSURE; }
    bool is_aggregate() const { return is_boxed() && (is_array() || is_sexpr() || is_string()); }

    std::string to_string() const {
        if (repr == 0)
            return "()";
        if (is_integer())
            return std::to_string(as_integer());

        void* ptr = as_ptr();
        lama_type type = get_type_header_ptr(get_obj_header_ptr(ptr));
        switch (type) {
            case STRING: {
                char* str = TO_DATA(ptr)->contents;
                return std::string("\"") + str + "\"";
            }

            case ARRAY: {
                data* d = TO_DATA(ptr);
                size_t len = LEN(d->data_header);
                std::string result = "[";
                auint* elements = reinterpret_cast<auint*>(d->contents);

                for (size_t i = 0; i < len; i++) {
                    if (i > 0)
                        result += ", ";
                    Value elem = Value::from_int(elements[i]);
                    result += elem.to_string();
                }
                result += "]";
                return result;
            }

            case SEXP: {
                sexp* s = TO_SEXP(ptr);
                size_t len = LEN(s->data_header);

                char* tag = reinterpret_cast<char*>(s->tag);
                std::string result = tag;

                if (len > 0) {
                    result += " (";
                    auint* elements = reinterpret_cast<auint*>(s->contents);

                    for (size_t i = 0; i < len; i++) {
                        if (i > 0)
                            result += ", ";
                        Value elem = Value::from_int(elements[i]);
                        result += elem.to_string();
                    }
                    result += ")";
                }
                return result;
            }
            case CLOSURE:
                return "<function>";
            default:
                return "<unknown>";
        }
    }

    char* as_string_ptr() const {
        return TO_DATA(as_ptr())->contents;
    }
    auint* as_array_ptr() const {
        return reinterpret_cast<auint*>(TO_DATA(as_ptr())->contents);
    }
    sexp* as_sexpr_ptr() const {
        return TO_SEXP(as_ptr());
    }

    auint* as_reference() const {
        return reinterpret_cast<auint*>(repr);
    }

    size_t size() const {
        if (is_integer())
            return 0;
        data* d = TO_DATA(as_ptr());
        return LEN(d->data_header);
    }

    Value get_element(size_t idx) const {
        assert(is_aggregate() && idx < size());

        if (is_string()) {
            return Value::from_int(static_cast<auint>(as_string_ptr()[idx]));
        } else if (is_array()) {
            return Value{as_array_ptr()[idx]};
        } else if (is_sexpr()) {
            sexp* s = as_sexpr_ptr();
            auint* contents = reinterpret_cast<auint*>(s->contents);
            return Value{contents[idx]};
        }
        assert(false);
        return Value{0};
    }

    // Установка элемента агрегата
    void set_element(size_t idx, Value v) {
        assert(is_aggregate() && idx < size());

        if (is_string()) {
            assert(v.is_integer());
            int32_t char_code = v.as_integer();
            as_string_ptr()[idx] = static_cast<char>(char_code);
        } else if (is_array()) {
            as_array_ptr()[idx] = v.repr;
        } else if (is_sexpr()) {
            sexp* s = as_sexpr_ptr();
            auint* contents = reinterpret_cast<auint*>(s->contents);
            contents[idx] = v.repr;
        }
    }
};

struct VMState {
    std::vector<auint> stack;
    int32_t stack_top;
    bytefile *bf;
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

        Frame(int32_t args, int32_t locals_cnt, int32_t b, bool is_frame_closure = false) 
            : arg_count(args), local_count(locals_cnt), return_address(-1), base(b), is_closure(is_frame_closure) {}
        auint get_local(VMState& vm, int32_t index) {
            return vm.stack[base + index];
        }
        auint *get_local_ptr(VMState& vm, int32_t index) {
            return &vm.stack[base + index];
        }
        void set_local(VMState& vm, int32_t index, const Value &v) {
            vm.stack[base + index] = v.repr;
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
    std::stack<Frame> frames;

    inline void push(Value v) {
        if (stack_top >= stack.size())
            stack.resize(stack.size() * 2);
        stack[stack_top++] = v.repr;
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);
    }
    inline Value pop() {
        check(stack_top > 0, "stack underflow", current_line, ip);
        Value v{stack[stack_top-1]};
        stack_top--;
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);
        return v;
    }
    inline Value peek(int offset = 0) {
        assert(stack_top - offset - 1 >= 0);
        return Value{stack[stack_top - offset - 1]};
    }

    inline auint get_global(int idx) const {
        return stack[idx];
    }
    inline auint* get_global_ptr(int idx) {
        return &stack[idx];
    }

    inline void get_int_from_code(int32_t *v, char* code) {
        check(ip + sizeof(int32_t) <= code_size, "reading beyond code segment", current_line, ip);
        std::memcpy(v, code + ip, sizeof(int32_t));
        ip += sizeof(int32_t);
    }
    inline void get_char_from_code(int8_t *v, char* code) {
        check(ip + sizeof(int8_t) <= code_size, "reading beyond code segment", current_line, ip);
        std::memcpy(v, code + ip, sizeof(int8_t));
        ip += sizeof(int8_t);
    }

    inline Frame *get_current_frame() {
        return frames.empty() ? nullptr : &frames.top();
    }

    inline void execute_binop(uint8_t op) {
        // std::cout << "BINOP\n";
        int32_t res;
        Value b = pop();
        Value a = pop();
        if (op == Bytecode::Binop::LOW_EQ) {
            check(b.is_integer() || a.is_integer(), "one of the operands must be integer", current_line, ip);
            if (a.is_integer() && b.is_integer()) {
                int32_t b_int = b.as_integer();
                int32_t a_int = a.as_integer();
                res = (a_int == b_int);
            } else res = 0; // Integers are never equal to values of other types
            push(Value::from_int(res));
            return;
        }
        check(b.is_integer(), "operand must be integer", current_line, ip);
        int32_t b_int = b.as_integer();
        check(a.is_integer(), "operand must be integer", current_line, ip);
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
                check(b_int != 0, "division by zero", current_line, ip);
                // Division with wraparound through 64-bit values
                int64_t temp = static_cast<int64_t>(a_int) / static_cast<int64_t>(b_int);
                res = static_cast<int32_t>(temp);
                break;
            }
            case Bytecode::Binop::LOW_MOD: { // MOD
                check(b_int != 0, "division by zero", current_line, ip);
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
        check(string_index >= 0 && string_index < bf->stringtab_size, "STRING: string index out of bounds", current_line, ip);
        char *str = get_string(bf, string_index);
        auto *v = get_object_content_ptr(alloc_string(strlen(str)));
        strcpy(TO_DATA(v)->contents, str);
        push(Value::from_ptr(v));
    }
    inline void execute_sexp() {
        // std::cout << "SEXP\n";
        int32_t tag_index;
        get_int_from_code(&tag_index, code);
        int32_t elem_count;
        get_int_from_code(&elem_count, code);
        check(elem_count >= 0, "SEXP: negative element count", current_line, ip);

        check(tag_index >= 0 && tag_index < bf->stringtab_size, "SEXP: tag index out of bounds", current_line, ip);
        char *tag = get_string(bf, tag_index);
        auto *v = get_object_content_ptr(alloc_sexp(elem_count));
        sexp* sexp_obj = TO_SEXP(v);
        sexp_obj->tag = reinterpret_cast<auint>(tag);

        // Getting elements from stack
        auint* content_ptr = reinterpret_cast<auint*>(sexp_obj->contents);
        for (int i = 0; i < elem_count; i++) {
            Value elem = pop();
            content_ptr[elem_count - i - 1] = elem.repr;
        }
        push(Value::from_ptr(v));
    }
    inline void execute_sti() {
        // std::cout << "STI\n";
        Value ref = pop();
        check(ref.is_boxed(), "STI: argument should be reference", current_line, ip);

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
            check(agg.is_aggregate(), "STA: non-aggregate argument", current_line, ip);

            if (agg.is_string()) {
                check(val.is_integer(), "STA: value must be integer for string", current_line, ip);
                char *str_ptr = agg.as_string_ptr();
                check(idx >= 0 && idx < strlen(str_ptr), "STA: string index out of bounds", current_line, ip);
                int32_t char_code = val.as_integer();
                str_ptr[idx] = static_cast<char>(char_code);
            } else if (agg.is_array()) {
                auint *arr_ptr = agg.as_array_ptr();
                check(idx >= 0 && idx < agg.size(), "STA: array index out of bounds", current_line, ip);
                arr_ptr[idx] = val.repr;
            } else {
                sexp *sexpr_ptr = agg.as_sexpr_ptr();
                check(idx >= 0 && idx < agg.size(), "STA: S-expression index out of bounds", current_line, ip);
                sexpr_ptr->contents[idx] = val.repr;
            }
        } else {
            check(idx_val.is_boxed(), "STA: second operand should be reference", current_line, ip);
            auint* ref_ptr = idx_val.as_reference();
            *ref_ptr = val.repr;
        }
        push(val);
    }
    inline void execute_jmp() {
        // std::cout << "JMP\n";
        int32_t loc;
        get_int_from_code(&loc, code);
        check(loc <= code_size, "incorrect jump destination", current_line, ip);
        ip = loc;
    }
    inline bool execute_end() {
        // std::cout << "RET\n";
        Value ret_val = pop(); // Not really necessary, but do this just to support the format

        Frame *current_frame = get_current_frame();
        stack_top = current_frame->base - current_frame->arg_count;
        if (current_frame->is_closure)
            stack_top--;

        frames.pop();
        if (frames.empty())
            return true;

        Frame* caller_frame = get_current_frame();
        ip = caller_frame->return_address;
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);

        push(ret_val); // TODO: remove this and `pop` above if we need some acceleration
        return false;
    }
    inline bool execute_ret() {
        // std::cout << "RET\n";
        Value ret_val = pop(); // Not really necessary, but do this just to support the format

        Frame *current_frame = get_current_frame();
        stack_top = current_frame->base - current_frame->arg_count;
        if (current_frame->is_closure)
            stack_top--;

        frames.pop();
        if (frames.empty())
            return true;

        Frame* caller_frame = get_current_frame();
        ip = caller_frame->return_address;
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);

        push(ret_val); // TODO: remove this and `pop` above if we need some acceleration
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
        check(index.is_integer(), "Element's index must be integer", current_line, ip);
        int32_t idx = index.as_integer();
        Value agg = pop();
        check(agg.is_aggregate(), "Aggregate must be string, SExpr, or an Array", current_line, ip);

        if (agg.is_sexpr()) {
            sexp *sexpr_ptr = agg.as_sexpr_ptr();
            check(idx < agg.size(), "Element index is greater than elements size", current_line, ip);
            auint* contents = reinterpret_cast<auint*>(sexpr_ptr->contents);
            push(contents[idx]);
        } else if (agg.is_array()) {
            auint *arr_ptr = agg.as_array_ptr();
            check(idx < agg.size(), "Element index is greater than elements size", current_line, ip);
            push(arr_ptr[idx]);
        } else if (agg.is_string()) {
            char *str_ptr = agg.as_string_ptr();
            check(idx < strlen(str_ptr), "Element index is greater than string's size", current_line, ip);
            push(Value::from_int(static_cast<auint>(str_ptr[idx])));
        }
    }

    // LD
    inline void execute_ld_global() {
        // std::cout << "LD G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "LD: global index out of bounds", current_line, ip);
        Value target = Value::from_repr(get_global(addr));

        push(target);
    }
    inline void execute_ld_local() {
        // std::cout << "LD L\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->local_count, "LD: local index out of bounds", current_line, ip);
        Value target = Value::from_repr(cf->get_local(*this, addr));

        push(target);
    }
    inline void execute_ld_argument() {
        // std::cout << "LD A\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->arg_count, "LD: argument index out of bounds", current_line, ip);
        Value target = cf->get_arg(*this, addr);

        push(target);
    }
    inline void execute_ld_captured() {
        // std::cout << "LD C\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        Value closure_val = stack[cf->base - cf->arg_count - 1];
        check(addr >= 0 && addr < closure_val.size(), "LD: captured index out of bounds", current_line, ip);

        Value target = cf->get_captured(*this, addr);
        push(target);
    }

    // LDA
    inline void execute_lda_global() {
        // std::cout << "LDA G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "LDA: global index out of bounds", current_line, ip);
        auint *target = get_global_ptr(addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_local() {
        // std::cout << "LDA L\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "LDA: local index out of bounds", current_line, ip);
        auint *target = cf->get_local_ptr(*this, addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_argument() {
        // std::cout << "LDA A\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "LDA: argument index out of bounds", current_line, ip);
        auint *target = cf->get_arg_ptr(*this, addr);

        push(Value::from_ptr(target));
    }
    inline void execute_lda_captured() {
        // std::cout << "LDA C\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        Value closure_val = stack[cf->base - cf->arg_count - 1];
        check(addr >= 0 && addr < closure_val.size(), "LDA: captured index out of bounds", current_line, ip);
        auint *target = cf->get_captured_ptr(*this, addr);
        push(Value::from_ptr(target));
    }

    // ST
    inline void execute_st_global() {
        // std::cout << "ST G\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < global_area_size, "ST: global index out of bounds", current_line, ip);
        stack[addr] = v.repr;

        push(v);
    }
    inline void execute_st_local() {
        // std::cout << "ST L\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "ST: local index out of bounds", current_line, ip);
        cf->set_local(*this, addr, v);

        push(v);
    }
    inline void execute_st_argument() {
        // std::cout << "ST A\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "ST: argument index out of bounds", current_line, ip);
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
        check(addr >= 0 && addr < closure_val.size(), "ST: captured index out of bounds", current_line, ip);
        cf->set_captured(*this, addr, v);

        push(v);
    }

    inline void execute_cjmpz() {
        // std::cout << "CJMPz\n";
        int32_t loc;
        get_int_from_code(&loc, code);
        check(loc <= code_size, "incorrect CJMPz destination", current_line, ip);

        Value cond = pop();
        check(cond.is_integer(), "CJMPz argument should be integer", current_line, ip);
        int32_t int_cond = cond.as_integer();
        if (!int_cond) {
            check(loc <= code_size, "incorrect jump destination", current_line, ip);
            ip = loc;
        }
    }
    inline void execute_cjmpnz() {
        // std::cout << "CJMPnz\n";
        int32_t loc;
        get_int_from_code(&loc, code);
        check(loc <= code_size, "incorrect CJMPnz destination", current_line, ip);

        Value cond = pop();
        check(cond.is_integer(), "CJMPnz argument should be integer", current_line, ip);
        int32_t int_cond = cond.as_integer();
        if (int_cond) {
            check(loc <= code_size, "incorrect jump destination", current_line, ip);
            ip = loc;
        }
    }
    inline void execute_begin() {
        int32_t arg_count;
        get_int_from_code(&arg_count, code);
        int32_t local_count;
        get_int_from_code(&local_count, code);
        check(arg_count >= 0 && local_count >= 0, "BEGIN: incorrect args or locals count", current_line, ip);

        Frame *prev_frame = get_current_frame();
        int32_t base = stack_top; // base should point to local variables
        // All args are already on the stack:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0

        Frame new_frame(arg_count, local_count, base, tmp_is_closure);
        tmp_is_closure = false;

        int32_t new_stack_top = stack_top + local_count;
        if (new_stack_top > stack.size())
            stack.resize(std::max(static_cast<size_t>(new_stack_top), stack.size() * 2), 0);
        stack_top = new_stack_top;

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.set_local(*this, i, 0);

        frames.push(new_frame);
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);
    }
    inline void execute_cbegin() {
        int32_t arg_count;
        get_int_from_code(&arg_count, code);
        int32_t local_count;
        get_int_from_code(&local_count, code);
        check(arg_count >= 0 && local_count >= 0, "CBEGIN: incorrect args or locals count", current_line, ip);

        Frame *prev_frame = get_current_frame();
        int32_t base = stack_top;
        // - closure: stack[base - arg_count - 1]
        // - args:    stack[base - arg_count] ... stack[base - 1]
        // - locals:  stack[base] ... stack[base + local_count - 1]

        Frame new_frame(arg_count, local_count, base, /*is_frame_closure=*/true);
        // All args are already on the stack:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0

        int32_t new_stack_top = stack_top + local_count;
        if (new_stack_top > stack.size())
            stack.resize(std::max(static_cast<size_t>(new_stack_top), stack.size() * 2), 0);
        stack_top = new_stack_top;

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.set_local(*this, i, 0);

        frames.push(new_frame);
        __gc_stack_bottom = static_cast<void *>(&stack[0] + stack_top);
    }
    inline void execute_closure() {
        // std::cout << "CLOSURE\n";
        int32_t target;
        get_int_from_code(&target, code);
        check(target >= 0 && target <= code_size, "CLOSURE: invalid target address", current_line, ip);

        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CLOSURE: negative capture count", current_line, ip);

        auto *closure_obj = get_object_content_ptr(alloc_closure(n + 1)); // +1 for code_offset
        auint* captures_ptr = reinterpret_cast<auint*>(TO_DATA(closure_obj)->contents);
        captures_ptr[0] = static_cast<auint>(target);
        for (int i = 0; i < n; i++) {
            int8_t type;
            get_char_from_code(&type, code); // G: 00, L: 01, A: 02, C: 03
            check(type >= 0 && type <= 3, "CLOSURE: invalid varspec type", current_line, ip);

            int32_t addr;
            get_int_from_code(&addr, code);

            Frame *cf = get_current_frame();
            Value v;
            switch (type) {
                case 0: // G(addr)
                    check(addr >= 0 && addr < global_area_size, "CLOSURE: global index out of bounds", current_line, ip);
                    v = Value::from_repr(get_global(addr));
                    break;
                case 1: // L(addr)
                    check(addr >= 0 && addr < cf->local_count, "CLOSURE: local index out of bounds", current_line, ip);
                    v = Value::from_repr(cf->get_local(*this, addr));
                    break;
                case 2: // A(addr)
                    check(addr >= 0 && addr < cf->arg_count, "CLOSURE: argument index out of bounds", current_line, ip);
                    v = Value::from_repr(cf->get_arg(*this, addr));
                    break;
                case 3: { // C(addr)
                    Value closure_val = stack[cf->base - cf->arg_count - 1];
                    check(addr >= 0 && addr < closure_val.size(), "LD: captured index out of bounds", current_line, ip);
                    v = cf->get_captured(*this, addr);
                    break;
                }
                default:
                    check(false, "invalid varspec for CLOSURE", current_line, ip);
            }
            captures_ptr[i + 1] = v.repr;
        }
        push(Value::from_ptr(closure_obj));
    }
    inline void execute_callc() {
        // std::cout << "CALLC\n";
        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CALLC: negative arguments count", current_line, ip);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        // args:
        // - arg N-1
        // - arg N-2
        // ...
        // - arg 0
        // - closure

        Value closure_val = peek(n);
        check(closure_val.is_closure(), "first argument to CALLC must be closure", current_line, ip);
        data* closure = TO_DATA(closure_val.as_ptr());
        auint* captures = reinterpret_cast<auint*>(closure->contents);

        // Do a JMP, basically
        // All captured variables should already be on the stack
        int32_t target = static_cast<int32_t>(captures[0]);
        check(target <= code_size, "incorrect CALLC destination", current_line, ip);
        ip = target;
        tmp_is_closure = true;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && (next_low == 3 || next_low == 2), "destination instruction after CALLC should be CBEGIN or BEGIN", current_line, ip);
    }
    inline void execute_call() {
        // std::cout << "CALL\n";
        int32_t target;
        get_int_from_code(&target, code);
        check(target >= 0 && target < code_size, "CALL: invalid target address", current_line, ip);

        int32_t n;
        get_int_from_code(&n, code);
        check(n >= 0, "CALL: negative arguments count", current_line, ip);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        // Do a JMP, basically
        check(target <= code_size, "incorrect call destination", current_line, ip);
        ip = target;
        tmp_is_closure = false;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && next_low == 2, "destination instruction after CALL should be BEGIN", current_line, ip);
    }

    inline void execute_tag() {
        // std::cout << "TAG\n";
        int32_t tag_index;
        get_int_from_code(&tag_index, code);

        int32_t expected_elem_count;
        get_int_from_code(&expected_elem_count, code);

        int32_t result = 0;
        Value tested_val = pop();
        if (tested_val.is_sexpr()) {
            check(expected_elem_count >= 0, "TAG: negative element count", current_line, ip);
            sexp *sexpr = tested_val.as_sexpr_ptr();
            check(tag_index >= 0 && tag_index < bf->stringtab_size, "TAG: string index out of bounds", current_line, ip);
            char *actual_tag = reinterpret_cast<char*>(sexpr->tag);
            char *expected_tag = get_string(bf, tag_index);
            if (strcmp(actual_tag, expected_tag) == 0 && LEN(sexpr->data_header) == expected_elem_count)
                result = 1;
        }

        push(Value::from_int(result));
    }
    inline void execute_array() {
        // std::cout << "ARRAY\n";
        int32_t n;
        get_int_from_code(&n, code);

        Value v = pop();
        bool result = false;
        if (v.is_array())
            result = (v.size() == static_cast<size_t>(n));
        push(Value::from_int(result));

    }
    inline void execute_fail() {
        // std::cout << "FAIL\n";
        int32_t line;
        get_int_from_code(&line, code);

        int32_t column;
        get_int_from_code(&column, code);

        Value v = pop();
        std::cerr << "Match failure at line " << line << ", column " << column << "\n";
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
        push(Value::from_int(result));
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
        aint value;
        std::cout << "> ";
        std::cin >> value;
        check(!std::cin.fail(), "invalid input", current_line, ip);
        push(Value::from_int(value));
    }
    inline void execute_write() {
        // std::cout << "CALL Lwrite\n";
        Value v = pop();
        check(v.is_integer(), "invalid write argument", current_line, ip);
        std::cout << v.as_integer() << "\n";
        push(Value(0));
    }
    inline void execute_length() {
        // std::cout << "CALL Llength\n";
        Value v = pop();
        check(v.is_aggregate(), "non-aggregate argument to length builtin", current_line, ip);
        int32_t len;
        if (v.is_sexpr())
            len = v.size();
        else if (v.is_array())
            len = v.size();
        else
            len = strlen(v.as_string_ptr());
        push(Value::from_int(len));
    }
    inline void execute_to_string() {
        // std::cout << "CALL Lstring\n";
        Value v = pop();
        std::string result = v.to_string();
        auto *str = get_object_content_ptr(alloc_string(strlen(result.c_str())));
        strcpy(TO_DATA(str)->contents, result.c_str());
        push(Value::from_ptr(str));
    }
    inline void execute_make_array() {
        // std::cout << "CALL Barray\n";
        int32_t n;
        get_int_from_code(&n, code);
        auto *v = get_object_content_ptr(alloc_array(n));
        auint* content_ptr = reinterpret_cast<auint*>(TO_DATA(v)->contents);
        for (int i = 0; i < n; i++) {
            Value elem = pop();
            content_ptr[n - i - 1] = elem.repr;
        }
        push(Value::from_ptr(v));
    }
};

void interpret(bytefile *bf) {
    VMState vm;
    vm.bf = bf;
    vm.ip = 0;
    vm.code = bf->code_ptr;
    vm.global_area_size = bf->global_area_size;
    vm.tmp_is_closure = false;

    vm.stack.resize(bf->global_area_size + 2, 0); // globals + 2 main arguments
    vm.stack_top = bf->global_area_size + 2;
    __gc_stack_top = static_cast<void *>(&vm.stack[0]);
    __gc_stack_bottom = static_cast<void *>(&vm.stack[0] + vm.stack_top);

    // FIXME: should we push global frame here?

    while(true) {
        uint8_t op = static_cast<uint8_t>(vm.code[vm.ip++]);
        // std::stringstream str_stream;
        // str_stream << std::hex << static_cast<int>(op);
        // std::cout << "op = " << str_stream.str() << "\n";

        switch (op) {
            case Bytecode::CONST: vm.execute_const(); break;
            case Bytecode::STRING: vm.execute_string(); break;
            case Bytecode::SEXP: vm.execute_sexp(); break;
            case Bytecode::STI: vm.execute_sti(); break;
            case Bytecode::STA: vm.execute_sta(); break;
            case Bytecode::JMP: vm.execute_jmp(); break;
            case Bytecode::END:
                if (vm.execute_end())
                    return;
                break;
            case Bytecode::RET:
                if (vm.execute_ret())
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

            case Bytecode::CJMPZ: vm.execute_cjmpz(); break;
            case Bytecode::CJMPNZ: vm.execute_cjmpnz(); break;
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
                    check(false, "unknown bytecode: ", vm.current_line, vm.ip);
            }
        }
    }
}

void free_bytefile(bytefile* file) {
    if (file) {
        if (file->global_ptr)
            free(file->global_ptr);
        free(file);
    }
}

int main(int argc, char* argv[])
{
    __init();
    try {
        bytefile* f = read_file(argv[1]);
        interpret(f);
        free_bytefile(f);
        __shutdown();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        __shutdown();
        return 1;
    }
}
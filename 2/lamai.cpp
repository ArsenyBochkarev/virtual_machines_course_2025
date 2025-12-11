#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stack>
#include <errno.h>
#include <iostream>
#include <malloc.h>
#include <cstring>
#include <vector>
#include <algorithm>
#include <string>
#include <variant>
#include "./Lama/runtime/runtime.h"

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

/* Gets a name for a public symbol */
char* get_public_name(bytefile *f, int i) {
    return get_string(f, f->public_ptr[i*2]);
}

/* Gets an offset for a publie symbol */
int get_public_offset(bytefile *f, int i) {
    return f->public_ptr[i*2+1];
}

static int code_size = -1;

/* Reads a binary bytecode file by name and unpacks it */
// TODO: Diagnose errors properly (from byterun.c)
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

    file = (bytefile*) malloc (sizeof(int)*4 + (size = ftell (f)));
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

struct SExpr;
struct ValueWrapper;
struct Array;
struct Closure;

using Value = std::variant<
    std::monostate,
    int32_t,
    std::string,
    ValueWrapper,
    Array,
    SExpr,
    Closure>;

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
struct Closure {
    Closure(const std::vector<Value> &c, int32_t co) : captured(c), code_offset(co) {};
    std::vector<Value> captured;
    int32_t code_offset;
};

static inline bool is_integer(const Value& v) {
    return std::holds_alternative<int32_t>(v);
}
static inline int32_t get_integer(const Value& v) {
    return std::get<int32_t>(v);
}

static inline bool is_sexpr(const Value& v) {
    return std::holds_alternative<SExpr>(v);
}
static inline SExpr get_sexpr(const Value& v) {
    return std::get<SExpr>(v);
}

static inline bool is_string(const Value& v) {
    return std::holds_alternative<std::string>(v);
}
static inline std::string get_string(const Value& v) {
    return std::get<std::string>(v);
}

static inline bool is_reference(const Value& v) {
    return std::holds_alternative<ValueWrapper>(v);
}
static inline Value* get_reference(const Value& v) {
    return std::get<ValueWrapper>(v).data;
}

static inline bool is_array(const Value& v) {
    return std::holds_alternative<Array>(v);
}
static inline Array get_array(const Value& v) {
    return std::get<Array>(v);
}

static inline bool is_aggregate(const Value& v) {
    return is_sexpr(v) || is_array(v) || is_string(v);
}

static inline bool is_closure(const Value& v) {
    return std::holds_alternative<Closure>(v);
}
static inline Closure get_closure(const Value& v) {
    return std::get<Closure>(v);
}

std::string value_to_string(const Value& v) {
    if (std::holds_alternative<std::monostate>(v))
        return "()";
    else if (is_integer(v))
        return std::to_string(get_integer(v));
    else if (is_string(v))
        return get_string(v);
    else if (is_sexpr(v)) {
        SExpr sexpr = get_sexpr(v);
        std::string result = "(" + sexpr.tag;
        for (const auto& elem : sexpr.elements) {
            result += " " + value_to_string(elem);
        }
        result += ")";
        return result;
    } else if (is_array(v)) {
        Array arr = get_array(v);
        std::string result = "[";
        for (size_t i = 0; i < arr.elements.size(); i++) {
            if (i > 0)
                result += ", ";
            result += value_to_string(arr.elements[i]);
        }
        result += "]";
        return result;
    } else if (is_reference(v))
        return "&" + value_to_string(*get_reference(v));

    assert(false && "unknown value");
}

struct Frame {
    std::vector<Value> locals;
    std::vector<Value> saved_args;
    std::vector<Value> captured_vars;
    bool is_closure;
    int32_t arg_count;
    int32_t local_count;
    int32_t return_address;

    Frame(int32_t args, int32_t locals_cnt, bool is_frame_closure = false) 
        : arg_count(args), local_count(locals_cnt), return_address(-1), is_closure(is_frame_closure) {
        locals.resize(args + locals_cnt);
    }

    Value get_arg(int32_t index) {
        assert(index >= 0 && index < arg_count && "argument index out of bounds");
        return locals[index];
    }
    void set_arg(int32_t index, const Value &v) {
        assert(index >= 0 && index < arg_count && "argument index out of bounds");
        locals[index] = v;
    }
    // For calls
    void save_arg(const Value &v) {
        saved_args.push_back(v);
    }

    Value get_local(int32_t index) {
        assert(index >= 0 && index < local_count && "local index out of bounds");
        return locals[arg_count + index];
    }
    void set_local(int32_t index, const Value &v) {
        assert(index >= 0 && index < arg_count && "argument index out of bounds");
        locals[arg_count + index] = v;
    }

    // For closures
    Value get_captured(int32_t index) {
        assert(index >= 0 && index < captured_vars.size() && "captured index out of bounds");
        return captured_vars[index];
    }
    void set_captured(int32_t index, const Value &v) {
        assert(index >= 0 && index < captured_vars.size() && "captured index out of bounds");
        captured_vars[index] = v;
    }
    void add_captured(const Value &v) {
        captured_vars.push_back(v);
    }
};

typedef struct {
    std::stack<Value> stack;
    std::vector<Value> locals;
    std::vector<Value> globals;
    std::stack<Frame> frames;
    int ip;
    int current_line;
} VMState;

static inline void push(VMState *vm, Value v) {
    vm->stack.push(v);
}

static inline Value pop(VMState *vm) {
    auto tmp = vm->stack.top();
    vm->stack.pop();
    return tmp;
}

static inline Value get_global(VMState *vm, int idx) {
    return vm->globals[idx];
}

static inline void get_int_from_code(int32_t *v, char *code, int ip) {
    std::memcpy(v, code + ip, sizeof(int32_t));
}

static inline void get_char_from_code(int8_t *v, char *code, int ip) {
    std::memcpy(v, code + ip, sizeof(int8_t));
}

static inline Frame *get_current_frame(VMState *vm) {
    return vm->frames.empty() ? nullptr : &vm->frames.top();
}

void interpret(bytefile *bf) {
    VMState vm;
    vm.globals.resize(bf->global_area_size);
    vm.ip = 0;

    // FIXME: should we push global frame here?

    char* code = bf->code_ptr;
    while(true) {
        unsigned char op = code[vm.ip++];
        // std::cout << "op = " << op << "\n";
        int high = (op >> 4) & 0xF;
        int low = op & 0xF;

        switch (high) {
            case 0: { // BINOP
                Value b = pop(&vm);
                assert(is_integer(b) && "Operand must be integer");
                int32_t b_int = get_integer(b);
                Value a = pop(&vm);
                assert(is_integer(a) && "Operand must be integer");
                int32_t a_int = get_integer(a);
                int32_t res;

                switch (low) {
                    case 1: { // ADD
                        // Addition with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) + static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 2: { // SUB
                        // Subtraction with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) - static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 3: { // MUL
                        // Multiplication with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) * static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 4: { // DIV
                        assert(b_int != 0 && "Division by zero\n");
                        // Division with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) / static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 5: { // MOD
                        assert(b_int != 0 && "Division by zero\n");
                        // Division remainder with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) % static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 6: // LT
                        res = a_int < b_int ? 1 : 0;
                        break;
                    case 7: // LE
                        res = a_int <= b_int ? 1 : 0;
                        break;
                    case 8: // GT
                        res = a_int > b_int ? 1 : 0;
                        break;
                    case 9: // GE
                        res = a_int >= b_int ? 1 : 0;
                        break;
                    case 10: // EQ
                        res = a_int == b_int ? 1 : 0;
                        break;
                    case 11: // NE
                        res = a_int != b_int ? 1 : 0;
                        break;
                    case 12: // Logical AND
                        res = (a_int && b_int) ? 1 : 0;
                        break;
                    case 13: // Logical OR
                        res = (a_int || b_int) ? 1 : 0;
                        break;
                }
                push(&vm, res);
                break;
            }

            case 1:
                switch (low) {
                    case 0: { // CONST
                        int32_t constant;
                        get_int_from_code(&constant, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        push(&vm, Value{constant});
                        break;
                    }
                    case 1: { // STRING
                        int32_t string_index;
                        get_int_from_code(&string_index, code, vm.ip); // Get string index from stack
                        std::string str = get_string(bf, string_index);
                        vm.ip += sizeof(int32_t);
                        push(&vm, Value{str});
                        break;
                    }
                    case 2: { // SEXP
                        int32_t tag_index;
                        get_int_from_code(&tag_index, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        int32_t elem_count;
                        get_int_from_code(&elem_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        std::string tag = get_string(bf, tag_index);
    
                        // Getting elements from stack
                        std::vector<Value> elements;
                        for (int i = 0; i < elem_count; i++)
                            elements.push_back(pop(&vm));
                        std::reverse(elements.begin(), elements.end());

                        vm.stack.push(Value{SExpr{tag, elements}});
                        break;
                    }
                    case 3: { // STI
                        Value ref = pop(&vm);
                        assert(is_reference(ref) && "STI: argument should be reference");
                        Value* ref_ptr = get_reference(ref);
                        Value val = pop(&vm);
                        *ref_ptr = val;

                        push(&vm, val);
                        break;
                    }
                    case 4: { // STA
                        // TODO
                        break;
                    }
                    case 5: // JMP
                        int32_t loc;
                        get_int_from_code(&loc, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        assert(loc <= code_size && "incorrect jump destination");
                        vm.ip = loc;
                        break;
                    case 6:
                    case 7: { // END, RET
                        Value ret_val = pop(&vm); // Not really necessary, but do this just to support the format
                        vm.frames.pop();
                        if (vm.frames.empty())
                            return;

                        Frame* caller_frame = get_current_frame(&vm);
                        vm.ip = caller_frame->return_address;
                        push(&vm, ret_val); // TODO: remove this and `pop` above if we need some acceleration
                        break;
                    }
                    case 8: // DROP
                        pop(&vm);
                        break;
                    case 9: { // DUP
                        Value v = vm.stack.top();
                        push(&vm, v);
                        break;
                    }
                    case 10: { // SWAP
                        Value a = pop(&vm);
                        Value b = pop(&vm);
                        push(&vm, b);
                        push(&vm, a);
                        break;
                    }
                    case 11: { // ELEM
                        Value agg = pop(&vm);
                        assert(is_aggregate(agg) && "Aggregate must be string, SExpr, or an Array");
                        Value index = pop(&vm);
                        assert(is_integer(index) && "Element's index must be integer");
                        int32_t idx = get_integer(index);

                        if (is_sexpr(agg)) {
                            SExpr sexpr = get_sexpr(agg);
                            assert(idx < sexpr.elements.size() && "Element index is greater than elements size");
                            push(&vm, sexpr.elements[idx]);
                        } else if (is_array(agg)) {
                            Array arr = get_array(agg);
                            assert(idx < arr.elements.size() && "Element index is greater than elements size");
                            push(&vm, arr.elements[idx]);
                        } else if (is_string(agg)) {
                            std::string str = get_string(agg);
                            assert(idx < str.size() && "Element index is greater than string's size");
                            push(&vm, Value{str[idx]});
                        }
                        break;
                    }
                }
                break;

            case 2:
            case 3: {
                // LD, LDA
                int addr;
                get_int_from_code(&addr, code, vm.ip);
                vm.ip += sizeof(int32_t);
                Value target;

                Frame *cf = get_current_frame(&vm);
                switch (low) {
                    case 0: { // G(addr)
                        assert(addr >= 0 && addr < vm.globals.size() && "LD/LDA: global index out of bounds");
                        target = get_global(&vm, addr);
                        break;
                    }
                    case 1: { // L(addr)
                        assert(addr >= 0 && addr < cf->local_count && "LD/LDA: local index out of bounds");
                        target = cf->get_local(addr);
                        break;
                    }
                    case 2: { // A(addr)
                        assert(addr >= 0 && addr < cf->arg_count && "LD/LDA: argument index out of bounds");
                        target = cf->get_arg(addr);
                        break;
                    }
                    case 3:
                        assert(addr >= 0 && addr < cf->captured_vars.size() && "LD/LDA: captured index out of bounds");
                        target = cf->get_captured(addr);
                        break;
                    default:
                        assert(false && "LD/LDA: unknown addressing mode");
                }

                if (high == 2) // LD
                    push(&vm, target);
                else if (high == 3) // LDA
                    push(&vm, Value{ValueWrapper{&target}}); // We should push a reference here
                break;
            }

            case 4: { // ST
                Value v = pop(&vm);
                int32_t addr;
                get_int_from_code(&addr, code, vm.ip);
                vm.ip += sizeof(int32_t);

                switch (low) {
                    case 0: { // G(addr)
                        assert(addr >= 0 && addr < vm.globals.size() && "ST: global index out of bounds");
                        vm.globals[addr] = v;
                        break;
                    }
                    case 1: { // L(addr)
                        Frame *cf = get_current_frame(&vm);
                        assert(addr >= 0 && addr < cf->locals.size() && "ST: local index out of bounds");
                        cf->set_local(addr, v);
                        break;
                    }
                    case 2: { // A(addr)
                        Frame *cf = get_current_frame(&vm);
                        assert(addr >= 0 && addr < cf->arg_count && "ST: argument index out of bounds");
                        cf->set_arg(addr, v);
                        break;
                    }
                    case 3: {
                        Frame *cf = get_current_frame(&vm);
                        assert(addr >= 0 && addr < cf->arg_count && "ST: captured index out of bounds");
                        cf->set_captured(addr, v);
                        break;
                    }
                    default:
                        assert(false && "ST: unknown addressing mode");
                }
                push(&vm, v);
                break;
            }
            case 5:
                switch (low) {
                    case 0:
                    case 1: { // CJMPz, CJMPnz
                        int32_t loc;
                        get_int_from_code(&loc, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Value cond = pop(&vm);
                        assert(is_integer(cond) && "CJMPz/CJMPnz argument should be integer");
                        int32_t int_cond = get_integer(cond);
                        if ((low == 0 && int_cond == 0) || (low == 1 && int_cond != 0)) {
                            assert(loc <= code_size && "incorrect jump destination");
                            vm.ip = loc;
                        }
                        break;
                    }
                    case 2:
                    case 3: { // BEGIN, CBEGIN
                        int32_t arg_count;
                        get_int_from_code(&arg_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        int32_t local_count;
                        get_int_from_code(&local_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Frame *prev_frame = get_current_frame(&vm);
                        Frame new_frame(arg_count, local_count, /*is_frame_closure=*/low == 3);
                        if (prev_frame) {
                            assert(arg_count == prev_frame->saved_args.size() && "saved args length != arg_count");
                            for (int i = arg_count - 1; i >= 0; i--)
                                new_frame.set_arg(i, prev_frame->saved_args[i]); // TODO: check arguments order

                            if (low == 3) // We also need to passthrough captured vars for CBEGIN
                                for (int i = 0; i < prev_frame->captured_vars.size(); i++)
                                    new_frame.add_captured(prev_frame->get_captured(i));
                        }
                        // Empty values for new_frame's locals
                        for (int i = 0; i < local_count; i++)
                            new_frame.get_local(i) = Value{std::monostate{}};

                        vm.frames.push(new_frame);
                        break;
                    }
                    case 4: { // CLOSURE
                        int32_t target;
                        get_int_from_code(&target, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        std::vector<Value> captured_vars;
                        for (int i = 0; i < n; i++) {
                            int8_t type;
                            get_char_from_code(&type, code, vm.ip);
                            vm.ip += sizeof(int8_t); // G: 00, L: 01, A: 02, C: 03

                            int32_t addr;
                            get_int_from_code(&addr, code, vm.ip);
                            vm.ip += sizeof(int32_t);

                            Frame *cf = get_current_frame(&vm);
                            Value v;
                            switch (type) {
                                case 0: // G(addr)
                                    v = get_global(&vm, addr);
                                    break;
                                case 1: // L(addr)
                                    v = cf->get_local(addr);
                                    break;
                                case 2: // A(addr)
                                    v = cf->get_arg(addr);
                                    break;
                                case 3: // C(addr)
                                    v = cf->get_captured(addr);
                                    break;
                                default:
                                    assert(false && "invalid varspec for CLOSURE");
                            }
                            captured_vars.push_back(v);
                        }
                        Value c(Closure(captured_vars, target));
                        push(&vm, c);
                        break;
                    }
                    case 5: { // CALLC
                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Value closure_val = pop(&vm);
                        assert(is_closure(closure_val) && "first argument to CALLC must be closure");
                        Closure closure = get_closure(closure_val);
                        Frame *current_frame = get_current_frame(&vm);
                        // Also save captured variables created in CLOSURE bytecode
                        for (int i = 0; i < closure.captured.size(); i++)
                            current_frame->add_captured(closure.captured[i]);
                        current_frame->return_address = vm.ip;

                        current_frame->saved_args.clear();
                        for (int i = 0; i < n; i++)
                            current_frame->save_arg(pop(&vm));

                        // Do a JMP, basically
                        int32_t target = closure.code_offset;
                        assert(target <= code_size && "incorrect CALLC destination");
                        vm.ip = target;

                        int next_op = code[vm.ip];
                        int next_high = (next_op >> 4) & 0xF;
                        int next_low = next_op & 0xF;
                        assert(next_high == 5 && next_low == 3 && "destination instruction after CALLC should be CBEGIN");
                        break;
                    }
                    case 6: { // CALL
                        int32_t target;
                        get_int_from_code(&target, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Frame *current_frame = get_current_frame(&vm);
                        current_frame->return_address = vm.ip;

                        current_frame->saved_args.clear();
                        for (int i = 0; i < n; i++)
                            current_frame->save_arg(pop(&vm));

                        // Do a JMP, basically
                        assert(target <= code_size && "incorrect call destination");
                        vm.ip = target;

                        int next_op = code[vm.ip];
                        int next_high = (next_op >> 4) & 0xF;
                        int next_low = next_op & 0xF;
                        assert(next_high == 5 && next_low == 2 && "destination instruction after CALLC should be CBEGIN");
                        break;
                    }
                    case 7: { // TAG
                        int32_t tag_index;
                        get_int_from_code(&tag_index, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t expected_elem_count;
                        get_int_from_code(&expected_elem_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t result = 0;
                        Value tested_val = pop(&vm);
                        if (is_sexpr(tested_val)) {
                            SExpr sexpr = get_sexpr(tested_val);
                            assert(tag_index >= 0 && tag_index < bf->stringtab_size && "string index out of bounds");
                            std::string expected_tag = get_string(bf, tag_index);
                            if (sexpr.tag == expected_tag && sexpr.elements.size() == expected_elem_count)
                                result = 1;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 8: { // ARRAY
                        int32_t expected_elem_count;
                        get_int_from_code(&expected_elem_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t result = 0;
                        Value tested_val = pop(&vm);
                        if (is_array(tested_val)) {
                            Array arr = get_array(tested_val);
                            if (arr.elements.size() == expected_elem_count)
                                result = 1;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 9: { // FAIL
                        int32_t line;
                        get_int_from_code(&line, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t column;
                        get_int_from_code(&column, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Value v = pop(&vm);
                        std::cerr << "Match failure at line " << line << ", column " << column << "\n";
                        exit(1);
                        break;
                    }
                    case 10: // LINE
                        int32_t line;
                        get_int_from_code(&line, code, vm.ip); // Not really necessary, do this just to support the format
                        vm.ip += sizeof(int32_t);
                        vm.current_line = line;
                        break;
                }
                break;

            case 6:
                switch (low) {
                    case 0: { // PATT =str
                        int32_t result = 0;
                        Value b = pop(&vm);
                        Value a = pop(&vm);
                        if (is_string(a) && is_string(b)) {
                            std::string str_a = get_string(a);
                            std::string str_b = get_string(b);
                            result = (str_a == str_b) ? 1 : 0;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 1: { // PATT #string
                        Value v = pop(&vm);
                        int32_t result = is_string(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 2: { // PATT #array
                        Value v = pop(&vm);
                        int32_t result = is_array(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 3: { // PATT #sexp
                        Value v = pop(&vm);
                        int32_t result = is_sexpr(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 4: { // PATT #ref
                        Value v = pop(&vm);
                        int32_t result = is_reference(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 5: { // PATT #val
                        Value v = pop(&vm);
                        int32_t result = is_integer(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 6: { // PATT #fun
                        Value v = pop(&vm);
                        int32_t result = is_closure(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                }
                break;

            case 7:
                switch (low) {
                    case 0: { // CALL Lread
                        int32_t value;
                        std::cin >> value;
                        assert(!std::cin.fail() && "invalid input");
                        push(&vm, Value{value});
                        break;
                    }
                    case 1: { // CALL Lwrite
                        Value v = pop(&vm);
                        assert(is_integer(v) && "invalid write argument");
                        std::cout << get_integer(v) << "\n";
                        push(&vm, Value{std::monostate{}});
                        break;
                    }
                    case 2: {
                        // CALL Llength
                        Value v = pop(&vm);
                        assert(is_aggregate(v) && "non-aggregate argument to length builtin");
                        int32_t len;
                        if (is_sexpr(v))
                            len = get_sexpr(v).elements.size();
                        else if (is_array(v))
                            len = get_array(v).elements.size();
                        else
                            len = get_string(v).size();
                        push(&vm, Value{len});
                        break;
                    }
                    case 3: { // CALL Lstring
                        Value v = pop(&vm);
                        std::string result = value_to_string(v);
                        push(&vm, Value{result});
                        break;
                    }
                    case 4: { // CALL Barray
                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        std::vector<Value> elements;
                        for (int i = 0; i < n; i++)
                            elements.push_back(pop(&vm));
                        std::reverse(elements.begin(), elements.end());
                        push(&vm, Value{Array{elements}});
                        break;
                    }
                }
                break;

            case 15:
                return;
            default:
                assert(false && "unknown bytecode");
        }
    }
}

/* Dumps the contents of the file */
void dump_file (FILE *f, bytefile *bf) {
    int i;

    fprintf(f, "String table size       : %d\n", bf->stringtab_size);
    fprintf(f, "Global area size        : %d\n", bf->global_area_size);
    fprintf(f, "Number of public symbols: %d\n", bf->public_symbols_number);
    fprintf(f, "Public symbols          :\n");

    for (i=0; i < bf->public_symbols_number; i++)
        fprintf(f, "   0x%.8x: %s\n", get_public_offset (bf, i), get_public_name (bf, i));

    fprintf(f, "Code:\n");
    interpret(bf);
}

int main(int argc, char* argv[])
{
    bytefile *f = read_file(argv[1]);
    dump_file(stdout, f);
    return 0;
}
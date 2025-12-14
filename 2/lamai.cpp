#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stack>
#include <memory>
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

using StringPtr = std::shared_ptr<std::string>;
using ArrayPtr = std::shared_ptr<Array>;
using SExprPtr = std::shared_ptr<SExpr>;

using Value = std::variant<
    std::monostate,
    int32_t,
    StringPtr,
    ValueWrapper,
    ArrayPtr,
    SExprPtr,
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
    Closure(const std::shared_ptr<std::vector<Value>> &c_ptr, int32_t co) : captured(c_ptr), code_offset(co) {};
    std::shared_ptr<std::vector<Value>> captured;
    int32_t code_offset;
};

static inline bool is_integer(const Value& v) {
    return std::holds_alternative<int32_t>(v);
}
static inline int32_t get_integer(const Value& v) {
    return std::get<int32_t>(v);
}

static inline bool is_sexpr(const Value& v) {
    return std::holds_alternative<SExprPtr>(v);
}
static inline SExprPtr get_sexpr(const Value& v) {
    return std::get<SExprPtr>(v);
}

static inline bool is_string(const Value& v) {
    return std::holds_alternative<StringPtr>(v);
}
static inline StringPtr get_string_ptr(const Value& v) {
    return std::get<StringPtr>(v);
}

static inline bool is_reference(const Value& v) {
    return std::holds_alternative<ValueWrapper>(v);
}
static inline Value* get_reference(const Value& v) {
    return std::get<ValueWrapper>(v).data;
}

static inline bool is_array(const Value& v) {
    return std::holds_alternative<ArrayPtr>(v);
}
static inline ArrayPtr get_array(const Value& v) {
    return std::get<ArrayPtr>(v);
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
        return "\"" + *get_string_ptr(v) + "\"";
    else if (is_sexpr(v)) {
        SExpr sexpr = *get_sexpr(v);
        if (sexpr.elements.empty())
            return sexpr.tag; // Nil should have no parentheses

        std::string result = sexpr.tag + " (";
        for (size_t i = 0; i < sexpr.elements.size(); i++) {
            if (i > 0)
                result += ", ";
            result += value_to_string(sexpr.elements[i]);
        }
        result += ")";
        return result;
    } else if (is_array(v)) {
        Array arr = *get_array(v);
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
    std::shared_ptr<std::vector<Value>> captured_vars;
    bool is_closure;
    int32_t arg_count;
    int32_t local_count;
    int32_t return_address;

    Frame(int32_t args, int32_t locals_cnt, bool is_frame_closure = false) 
        : arg_count(args), local_count(locals_cnt), return_address(-1), is_closure(is_frame_closure) {
        locals.resize(args + locals_cnt);
    }

    Value get_arg(int32_t index) {
        return locals[index];
    }
    Value* get_arg_ptr(int32_t index) {
        return &locals[index];
    }
    // Used in BEGIN/CBEGIN
    void set_arg(int32_t index, const Value &v) {
        locals[index] = v;
    }
    // Used in CALL/CALLC
    void save_arg(const Value &v) {
        saved_args.push_back(v);
    }

    Value get_local(int32_t index) {
        return locals[arg_count + index];
    }

    Value* get_local_ptr(int32_t index) {
        return &locals[arg_count + index];
    }
    void set_local(int32_t index, const Value &v) {
        locals[arg_count + index] = v;
    }

    // For closures
    Value get_captured(int32_t index) {
        return (*captured_vars)[index];
    }
    Value* get_captured_ptr(int32_t index) {
        return &(*captured_vars)[index];
    }
    void set_captured(int32_t index, const Value &v) {
        (*captured_vars)[index] = v;
    }
    void add_captured(const Value &v) {
        captured_vars->push_back(v);
    }
};

typedef struct {
    std::stack<Value> stack;
    std::vector<Value> locals;
    std::vector<Value> globals;
    std::stack<Frame> frames;
    int ip;
    int current_line;
    std::shared_ptr<std::vector<Value>> temp_captured;
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
static inline Value* get_global_ptr(VMState *vm, int idx) {
    return &vm->globals[idx];
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
                // std::cout << "BINOP\n";
                int32_t res;
                Value b = pop(&vm);
                Value a = pop(&vm);
                if (low == 10) {
                    assert(is_integer(b) || is_integer(a) && "one of the operands must be integer");
                    if (is_integer(a) && is_integer(b)) {
                        int32_t b_int = get_integer(b);
                        int32_t a_int = get_integer(a);
                        res = (a_int == b_int);
                    } else res = 0; // Integers are never equal to values of other types
                    push(&vm, res);
                    break;
                }
                assert(is_integer(b) && "operand must be integer");
                int32_t b_int = get_integer(b);
                assert(is_integer(a) && "operand must be integer");
                int32_t a_int = get_integer(a);

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
                        assert(b_int != 0 && "division by zero");
                        // Division with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) / static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 5: { // MOD
                        assert(b_int != 0 && "division by zero");
                        // Division remainder with wraparound through 64-bit values
                        int64_t temp = static_cast<int64_t>(a_int) % static_cast<int64_t>(b_int);
                        res = static_cast<int32_t>(temp);
                        break;
                    }
                    case 6: // LT
                        res = (a_int < b_int);
                        break;
                    case 7: // LE
                        res = (a_int <= b_int);
                        break;
                    case 8: // GT
                        res = (a_int > b_int);
                        break;
                    case 9: // GE
                        res = (a_int >= b_int);
                        break;
                    case 10: // EQ
                        assert(false && "EQ case for BINOP should be handled earlier");
                    case 11: // NE
                        res = (a_int != b_int);
                        break;
                    case 12: // Logical AND
                        res = (a_int && b_int);
                        break;
                    case 13: // Logical OR
                        res = (a_int || b_int);
                        break;
                }
                push(&vm, res);
                break;
            }

            case 1:
                switch (low) {
                    case 0: { // CONST
                        // std::cout << "CONST\n";
                        int32_t constant;
                        get_int_from_code(&constant, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        push(&vm, Value{constant});
                        break;
                    }
                    case 1: { // STRING
                        // std::cout << "STRING\n";
                        int32_t string_index;
                        get_int_from_code(&string_index, code, vm.ip); // Get string index from stack
                        std::string str = get_string(bf, string_index);
                        vm.ip += sizeof(int32_t);
                        push(&vm, Value{std::make_shared<std::string>(str)});
                        break;
                    }
                    case 2: { // SEXP
                        // std::cout << "SEXP\n";
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

                        vm.stack.push(Value{std::make_shared<SExpr>(SExpr{tag, elements})});
                        break;
                    }
                    case 3: { // STI
                        // std::cout << "STI\n";
                        Value ref = pop(&vm);
                        assert(is_reference(ref) && "STI: argument should be reference");
                        Value* ref_ptr = get_reference(ref);
                        Value val = pop(&vm);
                        *ref_ptr = val;

                        push(&vm, val);
                        break;
                    }
                    case 4: { // STA
                        // std::cout << "STA\n";
                        Value val = pop(&vm);
                        Value idx_val = pop(&vm);
                        if(is_integer(idx_val)) {
                            int32_t idx = get_integer(idx_val);
                            Value agg = pop(&vm);
                            assert(is_aggregate(agg) && "STA: non-aggregate argument");

                            if (is_string(agg)) {
                                assert(is_integer(val) && "STA: value must be integer for string");
                                StringPtr str_ptr = get_string_ptr(agg);
                                assert(idx >= 0 && idx < str_ptr->size() && "STA: string index out of bounds");
                                int32_t char_code = get_integer(val);
                                (*str_ptr)[idx] = static_cast<char>(char_code);
                            } else if (is_array(agg)) {
                                ArrayPtr arr_ptr = get_array(agg);
                                assert(idx >= 0 && idx < arr_ptr->elements.size() && "STA: array index out of bounds");
                                arr_ptr->elements[idx] = val;
                            } else {
                                SExprPtr sexpr_ptr = get_sexpr(agg);
                                assert(idx >= 0 && idx < sexpr_ptr->elements.size() && "STA: S-expression index out of bounds");
                                sexpr_ptr->elements[idx] = val; 
                            }
                        } else {
                            assert(is_reference(idx_val) && "STA: second operand should be reference");
                            Value* ref_ptr = get_reference(idx_val);
                            *ref_ptr = val;
                        }
                        push(&vm, val);
                        break;
                    }
                    case 5: { // JMP
                        // std::cout << "JMP\n";
                        int32_t loc;
                        get_int_from_code(&loc, code, vm.ip);
                        vm.ip += sizeof(int32_t);
                        assert(loc <= code_size && "incorrect jump destination");
                        vm.ip = loc;
                        break;
                    }
                    case 6:
                    case 7: { // END, RET
                        // std::cout << "END, RET\n";
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
                        // std::cout << "DROP\n";
                        pop(&vm);
                        break;
                    case 9: { // DUP
                        // std::cout << "DUP\n";
                        Value v = vm.stack.top();
                        push(&vm, v);
                        break;
                    }
                    case 10: { // SWAP
                        // std::cout << "SWAP\n";
                        Value a = pop(&vm);
                        Value b = pop(&vm);
                        push(&vm, b);
                        push(&vm, a);
                        break;
                    }
                    case 11: { // ELEM
                        // std::cout << "ELEM\n";
                        Value index = pop(&vm);
                        assert(is_integer(index) && "Element's index must be integer");
                        int32_t idx = get_integer(index);
                        Value agg = pop(&vm);
                        assert(is_aggregate(agg) && "Aggregate must be string, SExpr, or an Array");

                        if (is_sexpr(agg)) {
                            SExprPtr sexpr_ptr = get_sexpr(agg);
                            assert(idx < sexpr_ptr->elements.size() && "Element index is greater than elements size");
                            push(&vm, sexpr_ptr->elements[idx]);
                        } else if (is_array(agg)) {
                            ArrayPtr arr_ptr = get_array(agg);
                            assert(idx < arr_ptr->elements.size() && "Element index is greater than elements size");
                            push(&vm, arr_ptr->elements[idx]);
                        } else if (is_string(agg)) {
                            StringPtr str_ptr = get_string_ptr(agg);
                            assert(idx < str_ptr->size() && "Element index is greater than string's size");
                            push(&vm, Value{static_cast<int32_t>((*str_ptr)[idx])});
                        }
                        break;
                    }
                }
                break;

            case 2:
            case 3: {
                // LD, LDA
                // std::cout << "LD, LDA\n";
                int addr;
                get_int_from_code(&addr, code, vm.ip);
                vm.ip += sizeof(int32_t);

                Frame *cf = get_current_frame(&vm);
                Value *target;
                switch (low) {
                    case 0: { // G(addr)
                        assert(addr >= 0 && addr < vm.globals.size() && "LD/LDA: global index out of bounds");
                        target = get_global_ptr(&vm, addr);
                        break;
                    }
                    case 1: { // L(addr)
                        assert(addr >= 0 && addr < cf->local_count && "LD/LDA: local index out of bounds");
                        target = cf->get_local_ptr(addr);
                        break;
                    }
                    case 2: { // A(addr)
                        assert(addr >= 0 && addr < cf->arg_count && "LD/LDA: argument index out of bounds");
                        target = cf->get_arg_ptr(addr);
                        break;
                    }
                    case 3: { // C(addr)
                        assert(addr >= 0 && addr < cf->captured_vars->size() && "LD/LDA: captured index out of bounds");
                        target = cf->get_captured_ptr(addr);
                        break;
                    }
                    default:
                        assert(false && "LD/LDA: unknown addressing mode");
                }

                if (high == 2) // LD
                    push(&vm, *target);
                else // LDA
                    push(&vm, Value{ValueWrapper{target}}); // We should push a reference here
                break;
            }

            case 4: { // ST
                // std::cout << "ST\n";
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
                        assert(addr >= 0 && addr < cf->local_count && "ST: local index out of bounds");
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
                        assert(addr >= 0 && addr < cf->captured_vars->size() && "ST: captured index out of bounds");
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
                        // std::cout << "CJMPz, CJMPnz\n";
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
                            for (int i = 0; i < arg_count; i++)
                                new_frame.set_arg(i, prev_frame->saved_args[i]);
                        }

                        // We also need to passthrough captured vars for CBEGIN
                        if (low == 3) { // CBEGIN
                            new_frame.captured_vars = vm.temp_captured;
                            vm.temp_captured.reset();
                        }

                        // Empty values for new_frame's locals
                        for (int i = 0; i < local_count; i++)
                            new_frame.get_local(i) = Value{std::monostate{}};

                        vm.frames.push(new_frame);
                        break;
                    }
                    case 4: { // CLOSURE
                        // // std::cout << "CLOSURE\n";
                        int32_t target;
                        get_int_from_code(&target, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        std::shared_ptr<std::vector<Value>> captured_vars = std::make_shared<std::vector<Value>>();
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
                            captured_vars->push_back(v);
                        }
                        Value c(Closure(captured_vars, target));
                        push(&vm, c);
                        break;
                    }
                    case 5: { // CALLC
                        // std::cout << "CALLC\n";
                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        Frame *current_frame = get_current_frame(&vm);
                        current_frame->return_address = vm.ip;

                        current_frame->saved_args.clear();
                        for (int i = 0; i < n; i++)
                            current_frame->save_arg(pop(&vm));
                        std::reverse(current_frame->saved_args.begin(), current_frame->saved_args.end());

                        Value closure_val = pop(&vm);
                        assert(is_closure(closure_val) && "first argument to CALLC must be closure");
                        Closure closure = get_closure(closure_val);

                        // Also save captured variables created in CLOSURE bytecode
                        vm.temp_captured = closure.captured;

                        // Do a JMP, basically
                        int32_t target = closure.code_offset;
                        assert(target <= code_size && "incorrect CALLC destination");
                        vm.ip = target;

                        int next_op = code[vm.ip];
                        int next_high = (next_op >> 4) & 0xF;
                        int next_low = next_op & 0xF;
                        assert(next_high == 5 && (next_low == 3 || next_low == 2) && "destination instruction after CALLC should be CBEGIN or BEGIN");
                        break;
                    }
                    case 6: { // CALL
                        // std::cout << "CALL\n";
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
                        std::reverse(current_frame->saved_args.begin(), current_frame->saved_args.end());

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
                        // std::cout << "TAG\n";
                        int32_t tag_index;
                        get_int_from_code(&tag_index, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t expected_elem_count;
                        get_int_from_code(&expected_elem_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t result = 0;
                        Value tested_val = pop(&vm);
                        if (is_sexpr(tested_val)) {
                            SExpr sexpr = *get_sexpr(tested_val);
                            assert(tag_index >= 0 && tag_index < bf->stringtab_size && "string index out of bounds");
                            std::string expected_tag = get_string(bf, tag_index);
                            if (sexpr.tag == expected_tag && sexpr.elements.size() == expected_elem_count)
                                result = 1;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 8: { // ARRAY
                        // std::cout << "ARRAY\n";
                        int32_t expected_elem_count;
                        get_int_from_code(&expected_elem_count, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        int32_t result = 0;
                        Value tested_val = pop(&vm);
                        if (is_array(tested_val)) {
                            Array arr = *get_array(tested_val);
                            if (arr.elements.size() == expected_elem_count)
                                result = 1;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 9: { // FAIL
                        // std::cout << "FAIL\n";
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
                        // std::cout << "LINE\n";
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
                        // std::cout << "PATT =str\n";
                        int32_t result = 0;
                        Value b = pop(&vm);
                        Value a = pop(&vm);
                        if (is_string(a) && is_string(b)) {
                            std::string str_a = *get_string_ptr(a);
                            std::string str_b = *get_string_ptr(b);
                            result = (str_a == str_b) ? 1 : 0;
                        }

                        push(&vm, Value{result});
                        break;
                    }
                    case 1: { // PATT #string
                        // std::cout << "PATT =#string\n";
                        Value v = pop(&vm);
                        int32_t result = is_string(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 2: { // PATT #array
                        // std::cout << "PATT =#array\n";
                        Value v = pop(&vm);
                        int32_t result = is_array(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 3: { // PATT #sexp
                        // std::cout << "PATT =#sexp\n";
                        Value v = pop(&vm);
                        int32_t result = is_sexpr(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 4: { // PATT #ref
                        // std::cout << "PATT =#ref\n";
                        Value v = pop(&vm);
                        int32_t result = is_reference(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 5: { // PATT #val
                        // std::cout << "PATT =#val\n";
                        Value v = pop(&vm);
                        int32_t result = is_integer(v) ? 1 : 0;
                        push(&vm, Value{result});
                        break;
                    }
                    case 6: { // PATT #fun
                        // std::cout << "PATT =#fun\n";
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
                        // std::cout << "CALL Lread\n";
                        int32_t value;
                        std::cout << "> ";
                        std::cin >> value;
                        assert(!std::cin.fail() && "invalid input");
                        push(&vm, Value{value});
                        break;
                    }
                    case 1: { // CALL Lwrite
                        // std::cout << "CALL Lwrite\n";
                        Value v = pop(&vm);
                        assert(is_integer(v) && "invalid write argument");
                        std::cout << get_integer(v) << "\n";
                        push(&vm, Value{std::monostate{}});
                        break;
                    }
                    case 2: {
                        // CALL Llength
                        // std::cout << "CALL Llength\n";
                        Value v = pop(&vm);
                        assert(is_aggregate(v) && "non-aggregate argument to length builtin");
                        int32_t len;
                        if (is_sexpr(v))
                            len = get_sexpr(v)->elements.size();
                        else if (is_array(v))
                            len = get_array(v)->elements.size();
                        else
                            len = get_string_ptr(v)->size();
                        push(&vm, Value{len});
                        break;
                    }
                    case 3: { // CALL Lstring
                        // std::cout << "CALL Lstring\n";
                        Value v = pop(&vm);
                        std::string result = value_to_string(v);
                        push(&vm, Value{std::make_shared<std::string>(result)});
                        break;
                    }
                    case 4: { // CALL Barray
                        // std::cout << "CALL Barray\n";
                        int32_t n;
                        get_int_from_code(&n, code, vm.ip);
                        vm.ip += sizeof(int32_t);

                        std::vector<Value> elements;
                        for (int i = 0; i < n; i++)
                            elements.push_back(pop(&vm));
                        std::reverse(elements.begin(), elements.end());
                        push(&vm, Value{std::make_shared<Array>(Array{elements})});
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

    // fprintf(f, "String table size       : %d\n", bf->stringtab_size);
    // fprintf(f, "Global area size        : %d\n", bf->global_area_size);
    // fprintf(f, "Number of public symbols: %d\n", bf->public_symbols_number);
    // fprintf(f, "Public symbols          :\n");

    // for (i=0; i < bf->public_symbols_number; i++)
    //     fprintf(f, "   0x%.8x: %s\n", get_public_offset (bf, i), get_public_name (bf, i));

    // fprintf(f, "Code:\n");
    interpret(bf);
}

int main(int argc, char* argv[])
{
    bytefile *f = read_file(argv[1]);
    dump_file(stdout, f);
    return 0;
}
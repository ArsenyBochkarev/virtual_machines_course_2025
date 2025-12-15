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
struct Closure {
    Closure(const std::shared_ptr<std::vector<Value>> &c_ptr, int32_t co) : captured(c_ptr), code_offset(co) {};
    std::shared_ptr<std::vector<Value>> captured;
    int32_t code_offset;
};

using StringPtr = std::shared_ptr<std::string>;
using ArrayPtr = std::shared_ptr<Array>;
using SExprPtr = std::shared_ptr<SExpr>;

struct Value {
private:
    std::variant<std::monostate, int32_t, StringPtr, ValueWrapper, ArrayPtr, SExprPtr, Closure> data;

public:
    Value() : data(std::monostate{}) {}
    Value(std::monostate) : data(std::monostate{}) {}
    Value(int32_t v) : data(v) {}
    Value(const StringPtr& v) : data(v) {}
    Value(ValueWrapper v) : data(v) {}
    Value(const ArrayPtr& v) : data(v) {}
    Value(const SExprPtr& v) : data(v) {}
    Value(const Closure& v) : data(v) {}

    bool is_integer() const { return std::holds_alternative<int32_t>(data); }
    bool is_string() const { return std::holds_alternative<StringPtr>(data); }
    bool is_reference() const { return std::holds_alternative<ValueWrapper>(data); }
    bool is_array() const { return std::holds_alternative<ArrayPtr>(data); }
    bool is_sexpr() const { return std::holds_alternative<SExprPtr>(data); }
    bool is_closure() const { return std::holds_alternative<Closure>(data); }
    bool is_aggregate() const { return is_sexpr() || is_array() || is_string(); }
    bool is_empty() const { return std::holds_alternative<std::monostate>(data); }

    int32_t as_integer() const { 
        return std::get<int32_t>(data); 
    }
    StringPtr as_string_ptr() const { 
        return std::get<StringPtr>(data); 
    }
    Value* as_reference() const { 
        return std::get<ValueWrapper>(data).data; 
    }
    ArrayPtr as_array_ptr() const { 
        return std::get<ArrayPtr>(data); 
    }
    SExprPtr as_sexpr_ptr() const { 
        return std::get<SExprPtr>(data); 
    }
    Closure as_closure() const { 
        return std::get<Closure>(data); 
    }

    std::string to_string() const {
        if (std::holds_alternative<std::monostate>(data))
            return "()";
        else if (is_integer())
            return std::to_string(as_integer());
        else if (is_string())
            return "\"" + *as_string_ptr() + "\"";
        else if (is_sexpr()) {
            SExpr sexpr = *as_sexpr_ptr();
            if (sexpr.elements.empty())
                return sexpr.tag; // Nil should have no parentheses

            std::string result = sexpr.tag + " (";
            for (size_t i = 0; i < sexpr.elements.size(); i++) {
                if (i > 0)
                    result += ", ";
                result += sexpr.elements[i].to_string();
            }
            result += ")";
            return result;
        } else if (is_array()) {
            Array arr = *as_array_ptr();
            std::string result = "[";
            for (size_t i = 0; i < arr.elements.size(); i++) {
                if (i > 0)
                    result += ", ";
                result += arr.elements[i].to_string();
            }
            result += "]";
            return result;
        } else if (is_reference())
            return "&" + as_reference()->to_string();

        assert(false && "unknown value in to_string()");
    }
};

struct Frame {
    std::vector<Value> locals;
    std::vector<Value> saved_args;
    std::shared_ptr<std::vector<Value>> captured_vars;
    int32_t arg_count;
    int32_t local_count;
    int32_t return_address;

    Frame(int32_t args, int32_t locals_cnt) 
        : arg_count(args), local_count(locals_cnt), return_address(-1) {
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

struct VMState {
    std::stack<Value> stack;
    std::vector<Value> locals;
    std::vector<Value> globals;
    std::stack<Frame> frames;
    bytefile *bf;
    char *code;
    int32_t ip;
    int32_t current_line;
    std::shared_ptr<std::vector<Value>> temp_captured;

    inline void push(const Value &v) {
        stack.push(v);
    }
    inline Value pop() {
        auto tmp = stack.top();
        stack.pop();
        return tmp;
    }

    inline Value get_global(int idx) const {
        return globals[idx];
    }
    inline Value* get_global_ptr(int idx) {
        return &globals[idx];
    }

    inline void get_int_from_code(int32_t *v, char* code) {
        std::memcpy(v, code + ip, sizeof(int32_t));
        ip += sizeof(int32_t);
    }
    inline void get_char_from_code(int8_t *v, char* code) {
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
            push(res);
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
        push(res);
    }
    inline void execute_const() {
        // std::cout << "CONST\n";
        int32_t constant;
        get_int_from_code(&constant, code);
        push(Value{constant});
    }
    inline void execute_string() {
        // std::cout << "STRING\n";
        int32_t string_index;
        get_int_from_code(&string_index, code); // Get string index from stack
        std::string str = get_string(bf, string_index);
        push(Value{std::make_shared<std::string>(str)});
    }
    inline void execute_sexp() {
        // std::cout << "SEXP\n";
        int32_t tag_index;
        get_int_from_code(&tag_index, code);
        int32_t elem_count;
        get_int_from_code(&elem_count, code);

        std::string tag = get_string(bf, tag_index);

        // Getting elements from stack
        std::vector<Value> elements;
        for (int i = 0; i < elem_count; i++)
            elements.push_back(pop());
        std::reverse(elements.begin(), elements.end());

        stack.push(Value{std::make_shared<SExpr>(SExpr{tag, elements})});
    }
    inline void execute_sti() {
        // std::cout << "STI\n";
        Value ref = pop();
        check(ref.is_reference(), "STI: argument should be reference", current_line, ip);
        Value* ref_ptr = ref.as_reference();
        Value val = pop();
        *ref_ptr = val;

        push(val);
    }
    inline void execute_sta() {
        // std::cout << "STA\n";
        Value val = pop();
        Value idx_val = pop();
        if(idx_val.is_integer()) {
            int32_t idx = idx_val.as_integer();
            Value agg = pop();
            check(agg.is_aggregate(), "STA: non-aggregate argument", current_line, ip);

            if (agg.is_string()) {
                check(val.is_integer(), "STA: value must be integer for string", current_line, ip);
                StringPtr str_ptr = agg.as_string_ptr();
                check(idx >= 0 && idx < str_ptr->size(), "STA: string index out of bounds", current_line, ip);
                int32_t char_code = val.as_integer();
                (*str_ptr)[idx] = static_cast<char>(char_code);
            } else if (agg.is_array()) {
                ArrayPtr arr_ptr = agg.as_array_ptr();
                check(idx >= 0 && idx < arr_ptr->elements.size(), "STA: array index out of bounds", current_line, ip);
                arr_ptr->elements[idx] = val;
            } else {
                SExprPtr sexpr_ptr = agg.as_sexpr_ptr();
                check(idx >= 0 && idx < sexpr_ptr->elements.size(), "STA: S-expression index out of bounds", current_line, ip);
                sexpr_ptr->elements[idx] = val; 
            }
        } else {
            check(idx_val.is_reference(), "STA: second operand should be reference", current_line, ip);
            Value* ref_ptr = idx_val.as_reference();
            *ref_ptr = val;
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
        // std::cout << "END\n";
        Value ret_val = pop(); // Not really necessary, but do this just to support the format
        frames.pop();
        if (frames.empty())
            return true;

        Frame* caller_frame = get_current_frame();
        ip = caller_frame->return_address;
        push(ret_val); // TODO: remove this and `pop` above if we need some acceleration
        return false;
    }
    inline bool execute_ret() {
        // std::cout << "RET\n";
        Value ret_val = pop(); // Not really necessary, but do this just to support the format
        frames.pop();
        if (frames.empty())
            return true;

        Frame* caller_frame = get_current_frame();
        ip = caller_frame->return_address;
        push(ret_val); // TODO: remove this and `pop` above if we need some acceleration
        return false;
    }
    inline void execute_drop() {
        // std::cout << "DROP\n";
        pop();
    }
    inline void execute_dup() {
        // std::cout << "DUP\n";
        Value v = stack.top();
        push(v);
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
            SExprPtr sexpr_ptr = agg.as_sexpr_ptr();
            check(idx < sexpr_ptr->elements.size(), "Element index is greater than elements size", current_line, ip);
            push(sexpr_ptr->elements[idx]);
        } else if (agg.is_array()) {
            ArrayPtr arr_ptr = agg.as_array_ptr();
            check(idx < arr_ptr->elements.size(), "Element index is greater than elements size", current_line, ip);
            push(arr_ptr->elements[idx]);
        } else if (agg.is_string()) {
            StringPtr str_ptr = agg.as_string_ptr();
            check(idx < str_ptr->size(), "Element index is greater than string's size", current_line, ip);
            push(Value{static_cast<int32_t>((*str_ptr)[idx])});
        }
    }

    // LD
    inline void execute_ld_global() {
        // std::cout << "LD G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < globals.size(), "LD/LDA: global index out of bounds", current_line, ip);
        Value target = *get_global_ptr(addr);

        push(target);
    }
    inline void execute_ld_local() {
        // std::cout << "LD L\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->local_count, "LD: local index out of bounds", current_line, ip);
        Value target = *cf->get_local_ptr(addr);

        push(target);
    }
    inline void execute_ld_argument() {
        // std::cout << "LD A\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->arg_count, "LD: argument index out of bounds", current_line, ip);
        Value target = *cf->get_arg_ptr(addr);

        push(target);
    }
    inline void execute_ld_captured() {
        // std::cout << "LD C\n";
        int32_t addr;
        get_int_from_code(&addr, code);
        Frame *cf = get_current_frame();

        check(addr >= 0 && addr < cf->captured_vars->size(), "LD: captured index out of bounds", current_line, ip);
        Value target = *cf->get_captured_ptr(addr);

        push(target);
    }

    // LDA
    inline void execute_lda_global() {
        // std::cout << "LDA G\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < globals.size(), "LDA: global index out of bounds", current_line, ip);
        Value *target = get_global_ptr(addr);

        push(Value{ValueWrapper{target}}); // We should push a reference here
    }
    inline void execute_lda_local() {
        // std::cout << "LDA L\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "LDA: local index out of bounds", current_line, ip);
        Value *target = cf->get_local_ptr(addr);

        push(Value{ValueWrapper{target}}); // We should push a reference here
    }
    inline void execute_lda_argument() {
        // std::cout << "LDA A\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "LDA: argument index out of bounds", current_line, ip);
        Value *target = cf->get_arg_ptr(addr);

        push(Value{ValueWrapper{target}}); // We should push a reference here
    }
    inline void execute_lda_captured() {
        // std::cout << "LDA C\n";
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->captured_vars->size(), "LDA: captured index out of bounds", current_line, ip);
        Value *target = cf->get_captured_ptr(addr);

        push(Value{ValueWrapper{target}}); // We should push a reference here
    }

    // ST
    inline void execute_st_global() {
        // std::cout << "ST G\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        check(addr >= 0 && addr < globals.size(), "ST: global index out of bounds", current_line, ip);
        globals[addr] = v;

        push(v);
    }
    inline void execute_st_local() {
        // std::cout << "ST L\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->local_count, "ST: local index out of bounds", current_line, ip);
        cf->set_local(addr, v);

        push(v);
    }
    inline void execute_st_argument() {
        // std::cout << "ST A\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->arg_count, "ST: argument index out of bounds", current_line, ip);
        cf->set_arg(addr, v);

        push(v);
    }
    inline void execute_st_captured() {
        // std::cout << "ST C\n";
        Value v = pop();
        int32_t addr;
        get_int_from_code(&addr, code);

        Frame *cf = get_current_frame();
        check(addr >= 0 && addr < cf->captured_vars->size(), "ST: captured index out of bounds", current_line, ip);
        cf->set_captured(addr, v);

        push(v);
    }

    inline void execute_cjmpz() {
        // std::cout << "CJMPz\n";
        int32_t loc;
        get_int_from_code(&loc, code);

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

        Frame *prev_frame = get_current_frame();
        Frame new_frame(arg_count, local_count);
        if (prev_frame) {
            check(arg_count == prev_frame->saved_args.size(), "saved args length != arg_count", current_line, ip);
            for (int i = 0; i < arg_count; i++)
                new_frame.set_arg(i, prev_frame->saved_args[i]);
        }

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.get_local(i) = Value{std::monostate{}};

        frames.push(new_frame);
    }
    inline void execute_cbegin() {
        int32_t arg_count;
        get_int_from_code(&arg_count, code);
        int32_t local_count;
        get_int_from_code(&local_count, code);

        Frame *prev_frame = get_current_frame();
        Frame new_frame(arg_count, local_count);
        if (prev_frame) {
            check(arg_count == prev_frame->saved_args.size(), "saved args length != arg_count", current_line, ip);
            for (int i = 0; i < arg_count; i++)
                new_frame.set_arg(i, prev_frame->saved_args[i]);
        }

        // We also need to passthrough captured vars for CBEGIN
        new_frame.captured_vars = temp_captured;
        temp_captured.reset();

        // Empty values for new_frame's locals
        for (int i = 0; i < local_count; i++)
            new_frame.get_local(i) = Value{std::monostate{}};

        frames.push(new_frame);
    }
    inline void execute_closure() {
        // std::cout << "CLOSURE\n";
        int32_t target;
        get_int_from_code(&target, code);
        int32_t n;
        get_int_from_code(&n, code);

        std::shared_ptr<std::vector<Value>> captured_vars = std::make_shared<std::vector<Value>>();
        for (int i = 0; i < n; i++) {
            int8_t type;
            get_char_from_code(&type, code); // G: 00, L: 01, A: 02, C: 03

            int32_t addr;
            get_int_from_code(&addr, code);

            Frame *cf = get_current_frame();
            Value v;
            switch (type) {
                case 0: // G(addr)
                    v = get_global(addr);
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
                    check(false, "invalid varspec for CLOSURE", current_line, ip);
            }
            captured_vars->push_back(v);
        }
        Value c(Closure(captured_vars, target));
        push(c);
    }
    inline void execute_callc() {
        // std::cout << "CALLC\n";
        int32_t n;
        get_int_from_code(&n, code);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        current_frame->saved_args.clear();
        for (int i = 0; i < n; i++)
            current_frame->save_arg(pop());
        std::reverse(current_frame->saved_args.begin(), current_frame->saved_args.end());

        Value closure_val = pop();
        check(closure_val.is_closure(), "first argument to CALLC must be closure", current_line, ip);
        Closure closure = closure_val.as_closure();

        // Also save captured variables created in CLOSURE bytecode
        temp_captured = closure.captured;

        // Do a JMP, basically
        int32_t target = closure.code_offset;
        check(target <= code_size, "incorrect CALLC destination", current_line, ip);
        ip = target;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && (next_low == 3 || next_low == 2), "destination instruction after CALLC should be CBEGIN or BEGIN", current_line, ip);
    }
    inline void execute_call() {
        // std::cout << "CALL\n";
        int32_t target;
        get_int_from_code(&target, code);
        int32_t n;
        get_int_from_code(&n, code);

        Frame *current_frame = get_current_frame();
        current_frame->return_address = ip;

        current_frame->saved_args.clear();
        for (int i = 0; i < n; i++)
            current_frame->save_arg(pop());
        std::reverse(current_frame->saved_args.begin(), current_frame->saved_args.end());

        // Do a JMP, basically
        check(target <= code_size, "incorrect call destination", current_line, ip);
        ip = target;

        int next_op = code[ip];
        int next_high = (next_op >> 4) & 0xF;
        int next_low = next_op & 0xF;
        check(next_high == 5 && next_low == 2, "destination instruction after CALLC should be CBEGIN", current_line, ip);
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
            SExpr sexpr = *tested_val.as_sexpr_ptr();
            check(tag_index >= 0 && tag_index < bf->stringtab_size, "string index out of bounds", current_line, ip);
            std::string expected_tag = get_string(bf, tag_index);
            if (sexpr.tag == expected_tag && sexpr.elements.size() == expected_elem_count)
                result = 1;
        }

        push(Value{result});
    }
    inline void execute_array() {
        // std::cout << "ARRAY\n";
        int32_t expected_elem_count;
        get_int_from_code(&expected_elem_count, code);

        int32_t result = 0;
        Value tested_val = pop();
        if (tested_val.is_array()) {
            Array arr = *tested_val.as_array_ptr();
            if (arr.elements.size() == expected_elem_count)
                result = 1;
        }

        push(Value{result});
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
        int32_t result = 0;
        Value b = pop();
        Value a = pop();
        if (a.is_string() && b.is_string()) {
            std::string str_a = *a.as_string_ptr();
            std::string str_b = *b.as_string_ptr();
            result = (str_a == str_b);
        }

        push(Value{result});
    }
    inline void execute_patt_string() {
        // std::cout << "PATT =#string\n";
        Value v = pop();
        int32_t result = v.is_string();
        push(Value{result});
    }
    inline void execute_patt_array() {
        // std::cout << "PATT =#array\n";
        Value v = pop();
        int32_t result = v.is_array();
        push(Value{result});
    }
    inline void execute_patt_sexp() {
        // std::cout << "PATT =#sexp\n";
        Value v = pop();
        int32_t result = v.is_sexpr();
        push(Value{result});
    }
    inline void execute_patt_ref() {
        // std::cout << "PATT =#ref\n";
        Value v = pop();
        int32_t result = v.is_reference();
        push(Value{result});
    }
    inline void execute_patt_val() {
        // std::cout << "PATT =#val\n";
        Value v = pop();
        int32_t result = v.is_integer();
        push(Value{result});
    }
    inline void execute_patt_fun() {
        // std::cout << "PATT =#fun\n";
        Value v = pop();
        int32_t result = v.is_closure();
        push(Value{result});
    }

    inline void execute_read() {
        // std::cout << "CALL Lread\n";
        int32_t value;
        std::cout << "> ";
        std::cin >> value;
        check(!std::cin.fail(), "invalid input", current_line, ip);
        push(Value{value});
    }
    inline void execute_write() {
        // std::cout << "CALL Lwrite\n";
        Value v = pop();
        check(v.is_integer(), "invalid write argument", current_line, ip);
        std::cout << v.as_integer() << "\n";
        push(Value{std::monostate{}});
    }
    inline void execute_length() {
        // std::cout << "CALL Llength\n";
        Value v = pop();
        check(v.is_aggregate(), "non-aggregate argument to length builtin", current_line, ip);
        int32_t len;
        if (v.is_sexpr())
            len = v.as_sexpr_ptr()->elements.size();
        else if (v.is_array())
            len = v.as_array_ptr()->elements.size();
        else
            len = v.as_string_ptr()->size();
        push(Value{len});
    }
    inline void execute_to_string() {
        // std::cout << "CALL Lstring\n";
        Value v = pop();
        std::string result = v.to_string();
        push(Value{std::make_shared<std::string>(result)});
    }
    inline void execute_make_array() {
        // std::cout << "CALL Barray\n";
        int32_t n;
        get_int_from_code(&n, code);

        std::vector<Value> elements;
        for (int i = 0; i < n; i++)
            elements.push_back(pop());
        std::reverse(elements.begin(), elements.end());
        push(Value{std::make_shared<Array>(Array{elements})});
    }
};

void interpret(bytefile *bf) {
    VMState vm;
    vm.globals.resize(bf->global_area_size);
    vm.bf = bf;
    vm.ip = 0;
    vm.code = bf->code_ptr;

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

int main(int argc, char* argv[])
{
    try {
        bytefile* f = read_file(argv[1]);
        interpret(f);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
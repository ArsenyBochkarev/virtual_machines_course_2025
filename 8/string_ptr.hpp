#ifndef STRING_PTR_HPP
#define STRING_PTR_HPP

#include <cstring>
#include <cassert>
#include <cstdint>
#include <ostream>
#include <iostream>
#include <utility>


static constexpr uintptr_t UNIQUE_BIT = 1;
static constexpr uintptr_t PTR_MASK = ~UNIQUE_BIT;

class string_ptr {
    uintptr_t raw; // Rightmost bit will be used as uniqueness tag

#ifdef STRING_PTR_DEBUG
public:
#endif
    bool is_unique() const {
        return (raw & UNIQUE_BIT) != 0;
    }
#ifdef STRING_PTR_DEBUG
private:
#endif
    void set_unique_bit(bool unique) {
        if (unique)
            raw |= UNIQUE_BIT;
        else
            raw &= PTR_MASK;
    }

    char *get_ptr() const {
        return reinterpret_cast<char *>(raw & PTR_MASK); // Clear uniqueness tag before returning ptr
    }
    void set_ptr(const char *ptr, bool unique) {
        uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
        raw = p | unique;
    }

public:
    string_ptr() {
        set_ptr(nullptr, false); // NULL is not unique
    }

    // Allocate and make unique
    string_ptr(const char *str) {
        if (!str)
            set_ptr(nullptr, false);
        else
            set_ptr(strdup(str), true); // strdup guarantees lowest bit is free to use
    }
    string_ptr& operator=(const char *str) {
        string_ptr tmp(str); // This will properly deallocate existing string (if needed)
        swap(tmp);
        return *this;
    }

    // Both become non-unique
    string_ptr(string_ptr& other) {
        set_ptr(other.get_ptr(), false);
        other.set_unique_bit(false);
    }
    string_ptr& operator=(string_ptr& other) {
        if (this == &other)
            return *this;
        string_ptr tmp(other);
        swap(tmp);
        return *this;
    }

    // Moving preserves uniqueness
    string_ptr(string_ptr&& other) {
        raw = other.raw;
        other.set_ptr(nullptr, false);
    }
    string_ptr& operator=(string_ptr&& other) {
        if (this == &other)
            return *this;
        string_ptr tmp(std::move(other));
        swap(tmp);
        return *this;
    }

    ~string_ptr() {
        if (is_unique()) {
#ifdef STRING_PTR_DEBUG
            std::cout << "Debug: deallocating memory for string: \"" << get_ptr() << "\"\n";
#endif
            free(get_ptr());
        }
    }

    void swap(string_ptr& other) noexcept {
        std::swap(raw, other.raw);
    }

    const char *operator*() const {
        char *res = get_ptr();
        return (res ? res : "");
    }

    friend std::ostream& operator<<(std::ostream& os, const string_ptr& rc) {
        return os << (rc.is_unique() ? "unique " : "non-unique ") << "string: \"" << *rc << "\"";
    }
};

#endif // STRING_PTR_HPP
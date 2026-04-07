#include <array>
#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

#define STRING_PTR_DEBUG
#include "string_ptr.hpp"
#undef STRING_PTR_DEBUG


void test(std::string test_name, std::function<void()> test_func) {
    std::cout << "=== test " + test_name + " begin ===\n";
    test_func();
    std::cout << "=== test " + test_name + " end ===\n\n\n";
}

void test_initialization() {
    string_ptr empty_ptr;
    assert(!empty_ptr.is_unique()); // NULL is not unique
    assert(strcmp(*empty_ptr, "") == 0);

    string_ptr a("hello");
    assert(a.is_unique());
    assert(strcmp(*a, "hello") == 0);
    // "hello" should be freed
}

void test_copy_semantics() {
    // This test causes memory leak

    string_ptr a("copy me");
    assert(a.is_unique());

    string_ptr b(a);
    assert(!a.is_unique());
    assert(!b.is_unique());
    assert(strcmp(*a, "copy me") == 0);
    assert(strcmp(*b, "copy me") == 0);

    string_ptr c("target");
    c = a;
    // "target" should be freed
    assert(!c.is_unique());
    assert(!a.is_unique());
    assert(strcmp(*c, "copy me") == 0);
    // "copy me" should not be freed since it's not unique
}

void test_move_semantics() {
    string_ptr a("move me");
    assert(a.is_unique());

    string_ptr b(std::move(a));
    assert(b.is_unique());
    assert(!a.is_unique()); // `a` is now NULL (non-unique)
    assert(strcmp(*b, "move me") == 0);
    assert(strcmp(*a, "") == 0);

    string_ptr c("target");
    // "target" should be freed
    c = std::move(b);
    assert(c.is_unique());
    assert(!b.is_unique());
    assert(strcmp(*c, "move me") == 0);
    // "move me" should be freed
}

void test_self_assignment() {
    string_ptr a("self assign");
    a = a;
    assert(a.is_unique());
    assert(strcmp(*a, "self assign") == 0);

    a = std::move(a);
    assert(a.is_unique());
    assert(strcmp(*a, "self assign") == 0);
    // "self assign" should be freed
}

void test_bubble_sort() {
    std::array<string_ptr, 5> arr = {
        "c",
        "bcaa",
        "aaa",
        "xd",
        "gg"
    };

    for (const auto& s : arr)
        assert(s.is_unique());

    for (size_t i = 0; i < arr.size(); ++i) {
        for (size_t j = 0; j < arr.size() - 1 - i; ++j) {
            if (strcmp(*arr[j], *arr[j+1]) > 0) {
                string_ptr tmp = std::move(arr[j]);
                arr[j] = std::move(arr[j+1]);
                arr[j+1] = std::move(tmp);
                // No deallocation should happen here since we use move semantics
            }
        }
    }

    assert(strcmp(*arr[0], "aaa") == 0);
    assert(strcmp(*arr[1], "bcaa") == 0);
    assert(strcmp(*arr[2], "c") == 0);
    assert(strcmp(*arr[3], "gg") == 0);
    assert(strcmp(*arr[4], "xd") == 0);

    for (const auto& s : arr)
        assert(s.is_unique());
    // All string_ptrs from arr should be freed
}

void test_scope_and_reassignment() {
    {
        string_ptr msg("begin scope");
        std::cout << msg << "\n";
        msg = "in the middle of scope"; 
        // "begin scope" should be freed
        std::cout << msg << "\n";
        // "in the middle of scope" should be freed
    }
    string_ptr msg("outside of scope");
    std::cout << msg << "\n";
    // "outside of scope" should be freed
}

void test_vector_usage() {
    std::vector<string_ptr> vec;
    vec.push_back(string_ptr("some str"));
    vec.push_back(string_ptr("other"));
    vec.push_back(string_ptr("this is the last item in this vector"));

    for(const auto& item : vec)
        std::cout << item << "\n";
    vec.clear();
    // All string_ptrs from vec should be freed


    string_ptr elem1 = "some str";
    vec.push_back(elem1);
    vec.push_back(string_ptr("other"));
    vec.push_back(string_ptr("this is the last item in this vector"));

    for(const auto& item : vec)
        std::cout << item << "\n";
    vec.clear();
    // "some str" here should not be freed
    // All other string_ptrs from vec should be freed


    vec.emplace_back(elem1);
    vec.emplace_back(string_ptr("emplace back was used in this test"));
    vec.emplace_back(string_ptr("last item"));

    for(const auto& item : vec)
        std::cout << item << "\n";
    vec.clear();
    // "some str" here should not be freed
    // All other string_ptrs from vec should be freed
}

int main() {
    test("test_initialization", test_initialization);
    test("test_copy_semantics", test_copy_semantics); // Comment this line to remove memory leak
    test("test_move_semantics", test_move_semantics);
    test("test_self_assignment", test_self_assignment);
    test("test_bubble_sort", test_bubble_sort);
    test("test_scope_and_reassignment", test_scope_and_reassignment);
    test("test_vector_usage", test_vector_usage); // Comment this line to remove memory leak

    return 0;
}
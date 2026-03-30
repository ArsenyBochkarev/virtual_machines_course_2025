#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <thread>
#include <vector>
#include <mutex>
#include <string>

#include "pools.hpp"
#include "sigsegv_handler.hpp"


using namespace std;

const unsigned NUM_THREADS = 16;
const unsigned N = 10000000;

static void get_usage(struct rusage& usage) {
    if (getrusage(RUSAGE_SELF, &usage)) {
        perror("Cannot get usage");
        exit(EXIT_FAILURE);
    }
}

struct Node {
    Node* next;
    unsigned node_id;
};

static inline Node* create_list(unsigned n) {
  Node* list = nullptr;
  for (unsigned i = 0; i < n; i++)
    list = new Node({list, i});
  return list;
}

static inline void delete_list(Node* list) {
  while (list) {
    Node* node = list;
    list = list->next;
    delete node;
  }
}

static inline Node* create_list_using_pool(unsigned n, Pool& p) {
  Node* list = nullptr;
  for (unsigned i = 0; i < n; i++) {
    Node* new_node= static_cast<Node*>(p.allocate(sizeof(Node)));
    new_node->node_id = i; new_node->next = list;
    list = new_node;
  }
  return list;
}

static void print_stats(struct rusage& start, struct rusage& finish, unsigned n) {
    struct timeval diff;
    timersub(&finish.ru_utime, &start.ru_utime, &diff);
    uint64_t time_used = diff.tv_sec * 1000000 + diff.tv_usec;
    cout << "Time used: " << time_used << " usec\n";

    uint64_t mem_used = (finish.ru_maxrss - start.ru_maxrss) * 1024;
    cout << "Memory used: " << mem_used << " bytes\n";

    auto mem_required = n * sizeof(Node);
    auto overhead = (double(mem_used) - double(mem_required)) * double(100) / mem_used;
    cout << "Overhead: " << std::fixed << std::setw(4) << std::setprecision(3)
        << overhead << "%\n";
}

static void thread_std(unsigned n) {
    delete_list(create_list(n));
}
static void test_std() {
    cout << "Standard Allocator:\n";
    struct rusage start, finish;
    get_usage(start); {
        vector<thread> threads;
        for (unsigned i = 0; i < NUM_THREADS; i++)
            threads.emplace_back(thread_std, N);
        for (auto& t : threads)
            t.join();
    }
    get_usage(finish);
    print_stats(start, finish, NUM_THREADS * N);
}

std::mutex mtx;
static void thread_global_mutex(unsigned n, Pool& p) {
    Node* list = nullptr;
    for (unsigned i = 0; i < n; i++) {
        mtx.lock();
        Node* new_node = static_cast<Node*>(p.allocate(sizeof(Node)));
        mtx.unlock();

        new_node->node_id = i;
        new_node->next = list;
        list = new_node;
    }
}
static void test_global_mutex() {
    cout << "Global mutexed pool:\n";
    struct rusage start, finish;
    get_usage(start); {
        size_t total_capacity = NUM_THREADS * N * sizeof(Node);
        Pool pool(total_capacity, sizeof(Node), "Global mutexed pool"); // Not really a global one, but we must destroy the full pool instead of single list

        vector<thread> threads;
        for (unsigned i = 0; i < NUM_THREADS; i++)
            threads.emplace_back(thread_global_mutex, N, std::ref(pool));
        for (auto& t : threads)
            t.join();
    }
    get_usage(finish);
    print_stats(start, finish, NUM_THREADS * N);
}

static void thread_global_lockfree(unsigned n, LockFreePool& p) {
    Node* list = nullptr;
    for (unsigned i = 0; i < n; i++) {
        Node* new_node = static_cast<Node*>(p.allocate(sizeof(Node)));
        new_node->node_id = i;
        new_node->next = list;
        list = new_node;
    }
}
static void test_global_lockfree() {
    cout << "Global lock-free pool:\n";
    struct rusage start, finish;
    get_usage(start); {
        size_t total_capacity = NUM_THREADS * N * sizeof(Node);
        LockFreePool pool(total_capacity, sizeof(Node), "Global lock-free pool"); // Same as for the previous pool

        vector<thread> threads;
        for (unsigned i = 0; i < NUM_THREADS; i++)
            threads.emplace_back(thread_global_lockfree, N, std::ref(pool));
        for (auto& t : threads)
            t.join();
    }

    get_usage(finish);
    print_stats(start, finish, NUM_THREADS * N);
}

static void thread_local_pool(unsigned n, int thread_id) {
    string pool_name = "Thread-local pool " + to_string(thread_id);
    Pool p(n * sizeof(Node), sizeof(Node), pool_name.c_str());

    Node* list = nullptr;
    for (unsigned i = 0; i < n; i++) {
        Node* new_node = static_cast<Node*>(p.allocate(sizeof(Node)));
        new_node->node_id = i;
        new_node->next = list;
        list = new_node;
    }
}
static void test_local_pools() {
    cout << "Thread-local pools:\n";
    struct rusage start, finish;
    get_usage(start);

    vector<thread> threads;
    for (unsigned i = 0; i < NUM_THREADS; i++)
        threads.emplace_back(thread_local_pool, N, i);
    for (auto& t : threads)
        t.join();

    get_usage(finish);
    print_stats(start, finish, NUM_THREADS * N);
}

int main() {
    register_sigsegv_handler();

    test_std();
    // Uncomment below to run other tests
    // test_global_mutex();
    // test_global_lockfree();
    // test_local_pools();

    // Uncomment below to check SIGSEGV works
    // Pool pool(100 * sizeof(Node), sizeof(Node), "Doomed pool");
    // create_list_using_pool(12345, pool);

    return EXIT_SUCCESS;
}
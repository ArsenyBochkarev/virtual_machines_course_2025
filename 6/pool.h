#include <iostream>
#include <iomanip>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>


class Pool {
    char* base_addr;
    char* first_free;
    size_t total_size;
    size_t guard_size;

public:
    Pool(size_t capacity, size_t max_alloc_size);
    ~Pool() {
        munmap(base_addr, total_size);
    }

    inline void* allocate(size_t size) {
        return (first_free -= size);
    }
};

#define DMALLOC_DISABLE 1
#include "dmalloc.hh"
#include <cassert>
#include <cstring>
#include <map>
using namespace std;
#include <iostream>
#include <unordered_map>

// Initializes values within global stats variable and the pointer metadata
struct dmalloc_stats global_stats;
struct pointer_data ptr_data;

// Maps a pointer to a vector containing all the data associated with the pointer (used for leak reporting)
std::map<void*, pointer_data> mp;

// Map to store data about pointers (advanced leak reporting)
std::unordered_map<void*, size_t> mp2;

/**
 * dmalloc(sz,file,line)
 *      malloc() wrapper. Dynamically allocate the requested amount `sz` of memory and 
 *      return a pointer to it 
 * 
 * @arg size_t sz : the amount of memory requested 
 * @arg const char *file : a string containing the filename from which dmalloc was called 
 * @arg long line : the line number from which dmalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dmalloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    // If allocated size is greater than max int, then malloc fails and we update stats and return null pointer
    if (sz > INT32_MAX) {
        global_stats.fail_size += sz;
        global_stats.nfail += 1;
        return nullptr;
    }

    // Initializes the metadata struct (header flag is random, size is 0, footer flag is 0)
    struct metadata meta =  {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    // Increments both the active and total allocations by 1
    global_stats.nactive += 1;
    global_stats.ntotal += 1;

    // Increments the active and total sizes by the size of memory requested in malloc
    global_stats.active_size += sz;
    global_stats.total_size += sz;

    // Stores the address of the beginning of the malloc'ed memory
    void* malloc_mem_p = base_malloc(sz + sizeof(meta) + sizeof(size_t));
    // Add padding here. If the the size mod 16 is not 0, then we want to add the remainder (because malloc always returns a 16-byte aligned pointer)
    
    // Initializing the fields within the metadata
    meta.size = sz;
    meta.header_flag = 53;
    meta.footer_flag = 54;
 
    // Stores the metadata struct at the address we just malloc'ed for
    *(metadata*)malloc_mem_p = meta;
    
    // Use pointer arithmetic to get to the beginning of the payload and return that
    void* payload_p = (void*)((metadata*)malloc_mem_p + 1);
    
    // Assigns memory after payload to be a secret value
    size_t secret_value = 56;
    *((char*)payload_p + sz) = secret_value;

    // Case for updating the heap max
    if ((uintptr_t)(payload_p) + sz > global_stats.heap_max) {
        global_stats.heap_max = (uintptr_t)(payload_p) + sz;
    }
    // Case for updating the heap min
    if ((global_stats.heap_min == 0) || (uintptr_t)(payload_p) < global_stats.heap_min) {
        global_stats.heap_min = (uintptr_t)(payload_p);
    }

    // Filling pointer data struct with all leak report data
    struct pointer_data p_data =  {
        file, line, sz
    };

    // Inserting into hash map to have pointer data (used for leak reporting)
    mp.insert({payload_p, p_data});

    // Inserting into unordered map (used for advanced leak reporting; 1 because hasn't been freed)
    mp2.insert({payload_p, 1});
    return payload_p;
}

/**
 * dfree(ptr, file, line)
 *      free() wrapper. Release the block of heap memory pointed to by `ptr`. This should 
 *      be a pointer that was previously allocated on the heap. If `ptr` is a nullptr do nothing. 
 * 
 * @arg void *ptr : a pointer to the heap 
 * @arg const char *file : a string containing the filename from which dfree was called 
 * @arg long line : the line number from which dfree was called 
 */
void dfree(void* ptr, const char* file, long line) {
    (void) file, (void) line;  
    if (ptr == nullptr) {
        return;
    }
    global_stats.nactive -= 1;
    
    // If the pointer has been freed, then we want to remove from our map (leak reporting)
    mp.erase(ptr);

    // Ensuring that ptr points to somewhere on the heap
    if ((uintptr_t)ptr < global_stats.heap_min || (uintptr_t)ptr > global_stats.heap_max) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n", file, line, ptr);
        return;
    }

    // Ensures that the pointer that we are freeing is properly aligned (test 23 leak sanitizer)
    if ((uintptr_t)ptr % alignof(ptr) != 0) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
    }

    // Retrieves the pointer to the address of the beginning of the metadata
    metadata* metadata_ptr = (metadata*)ptr - 1;

    // Checks invalid free
    if ((*(metadata_ptr)).header_flag != 53) {
        for (const auto &elem : mp2) {
            void* malloc_ptr = elem.first;
            size_t freed_or_not = elem.second;
            auto it = mp.find(malloc_ptr);
            struct pointer_data allocated_data = it->second;
            // Access the file name
            const char* file_n = allocated_data.file_name;
            // Access the line number
            long line_no = allocated_data.line_number;
            // Access the size (# of bytes)
            size_t sz = allocated_data.size;

            // Checks if the pointer hasn't been freed & it's within bounds of the current pointer we're iterating on
            if (freed_or_not == 1 && (ptr <= (char*)malloc_ptr + sz && ptr > (char*)malloc_ptr)) {
                size_t offset = (char*)ptr - (char*)malloc_ptr;
                fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
                fprintf(stderr, "%s:%ld: %p is %ld bytes inside a %ld byte region allocated here\n", file_n, line_no, ptr, offset, sz);
                return;
            }
        }
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        return;
    }
    // Checks double free
    if (metadata_ptr->free_flag == 1) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
        return;
    }

    // Checks the footer to see if a boundary write error was made BEFORE the payload
    if ((*(metadata_ptr)).footer_flag != 54) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        return;
    }
    // Checks the boundary value to see if a boundary write error was made AFTER the payload
    if (*((char*)ptr + (*metadata_ptr).size) != 56) {
        fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
        return;
    }
    // General free case
    else {
        // Retrieves the actual value of the metadata
        size_t malloc_size = (*metadata_ptr).size;
        (*metadata_ptr).free_flag = 1;
        global_stats.active_size -= malloc_size;
        base_free(metadata_ptr);
    }
}

/**
 * dcalloc(nmemb, sz, file, line)
 *      calloc() wrapper. Dynamically allocate enough memory to store an array of `nmemb` 
 *      number of elements with each element being `sz` bytes. The memory should be initialized 
 *      to zero  
 * 
 * @arg size_t nmemb : the number of items that space is requested for
 * @arg size_t sz : the size in bytes of the items that space is requested for
 * @arg const char *file : a string containing the filename from which dcalloc was called 
 * @arg long line : the line number from which dcalloc was called 
 * 
 * @return a pointer to the heap where the memory was reserved
 */
void* dcalloc(size_t nmemb, size_t sz, const char* file, long line) {
    size_t capacity = nmemb * sz;
    if (sz != 0 && nmemb != 0 && capacity / nmemb != sz) {
        global_stats.nfail += 1;
        return nullptr;
    }
    void* ptr = dmalloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}

/**
 * get_statistics(stats)
 *      fill a dmalloc_stats pointer with the current memory statistics  
 * 
 * @arg dmalloc_stats *stats : a pointer to the the dmalloc_stats struct we want to fill
 */
void get_statistics(dmalloc_stats* stats) {
    memset(stats, 255, sizeof(dmalloc_stats));
    stats->nactive = global_stats.nactive;
    stats->active_size = global_stats.active_size;
    stats->ntotal = global_stats.ntotal;
    stats->total_size = global_stats.total_size;
    stats->nfail = global_stats.nfail;
    stats->fail_size = global_stats.fail_size;
    stats->heap_min = global_stats.heap_min;
    stats->heap_max = global_stats.heap_max;
    // Your code here.
}

/**
 * print_statistics()
 *      print the current memory statistics to stdout       
 */
void print_statistics() {
    dmalloc_stats stats;
    get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

/**  
 * print_leak_report()
 *      Print a report of all currently-active allocated blocks of dynamic
 *      memory.
 */
void print_leak_report() {
    for (const auto &elem : mp) {
        void* ptr = elem.first;
        struct pointer_data allocated_data = elem.second;
        // Access the file name
        const char* file_n = allocated_data.file_name;
        // Access the line number
        long line_no = allocated_data.line_number;
        // Access the size (# of bytes)
        size_t sz = allocated_data.size;
        fprintf(stdout, "LEAK CHECK: %s:%ld: allocated object %p with size %ld\n", file_n, line_no, ptr, sz);
    }
}
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "parsing/parser.h"

/* load the shared object in this process, and run some math to find the offset
 * of the symbol in libc */
uint64_t parse_libc_sym(char* sym) {
    // find relative location of "dlopen()" in our own process
    void (*func_ptr)() = dlsym(RTLD_NEXT, sym);
    if (!func_ptr) {
        fprintf(stderr, "[-] Error finding specified symbol %s in libc\n", sym);
        return 1;
    }

    pid_t pid = getpid();
    MapEntry libc_entry = parse_libc_loc(pid);

    // subtract the start of where libc is loaded in memory from where the
    // symbol is loaded to get the absolute offset
    return ((uint64_t)func_ptr - libc_entry.start);
}

/* compares two buffers and returns the indicies that contain unchanged values */
int* compare_bufs(
    char* buf1,
    char* buf2,
    unsigned int size,
    unsigned int* resultsize
) {
    int* result = malloc(size * sizeof(unsigned int));
    int count = 0;

    if (result == NULL) {
        // allocation failed
        *resultsize = 0;
        return NULL;
    }

    for (int i = 0; i < size; i++) {
        if (buf1[i] == buf2[i]) {
            result[count] = i;
            count++;
        }
    }

    result = realloc(result, count * sizeof(unsigned int));

    *resultsize = count;
    return result;
}

// todo!
// - ull type conversion from chars
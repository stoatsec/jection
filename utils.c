#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>

#include "parsing/parser.h"

/* load the shared object in this process, and run some math to find the offset of the symbol in libc */
unsigned long long parse_libc_sym(char* sym) {
    
    // find relative location of "dlopen()" in our own process
    void (*func_ptr)() = dlsym(RTLD_NEXT, sym);
    if (!func_ptr) {
        fprintf(stderr, "[-] Error finding specified symbol %s in libc\n", sym);
        return 1;
    }
    
    pid_t pid = getpid();
    MapEntry libc_entry = parse_libc_loc(pid);
    
    // subtract the start of where libc is loaded in memory from where the symbol is loaded to get the absolute offset
    return ((unsigned long long)func_ptr - libc_entry.start);
}
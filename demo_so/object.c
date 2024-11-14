#include <stdio.h>

void init(void) __attribute__((constructor));

void init(void) {
    printf("demo shared object initialized\n");
}

// gcc -shared -fPIC object.c -o libjection.so
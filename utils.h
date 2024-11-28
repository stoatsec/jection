#pragma once
#include <stdint.h>
#include <unistd.h>

uint64_t parse_libc_sym(char* sym);
int* compare_bufs(
    char* buf1,
    char* buf2,
    unsigned int size,
    unsigned int* resultsize
);
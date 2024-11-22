#pragma once
#include <unistd.h>

static unsigned long long syscall_stub[] = {
    0xcc050f // syscall and int3
};

static unsigned long long rax_call_stub[] = {
    0xccd0ff // call rax and int3
};

int addrspc_alloc(pid_t pid, size_t map_size, unsigned long long* address);
int addrspc_dealloc(pid_t pid, size_t map_size, unsigned long long address);
int inject_so(pid_t pid, char* path);
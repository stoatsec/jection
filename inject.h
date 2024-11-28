#pragma once
#include <stdint.h>
#include <unistd.h>

static uint64_t syscall_stub[] = {
    0xcc050f // syscall and int3
};

static uint64_t rax_call_stub[] = {
    0xccd0ff // call rax and int3
};

int addrspc_alloc(pid_t pid, size_t map_size, uint64_t* address);
int addrspc_dealloc(pid_t pid, size_t map_size, uint64_t address);
int inject_so(pid_t pid, char* path);
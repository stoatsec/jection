#pragma once
#include <unistd.h>

int addrspc_alloc(pid_t pid, size_t map_size, unsigned long long* address);
int addrspc_dealloc(pid_t pid, size_t map_size, unsigned long long address);
int inject_so(pid_t pid, unsigned char* path);
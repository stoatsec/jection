#ifndef INJECT
#define INJECT

#include <unistd.h>

int addrspc_alloc(pid_t pid, size_t map_size, unsigned long long* address);

#endif
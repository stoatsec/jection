#pragma once

#include <stdio.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 30

#define READ 1
#define WRITE 2
#define EXECUTE 4

typedef struct {
    unsigned long long start;
    unsigned long long end;
    char* path;
    char flags[4];
} MapEntry;

MapEntry parse_rwx(pid_t pid, unsigned long buffer_len);
MapEntry parse_map_perms(const char* line);
MapEntry parse_libc_loc(pid_t pid);
static int check_validity(MapEntry entry, unsigned long buffer_size);
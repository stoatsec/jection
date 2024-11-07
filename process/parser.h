#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>

#define MAX_LINE_LENGTH 30

#define READ 1
#define WRITE 2
#define EXECUTE 4

typedef struct {
    unsigned long start;
    unsigned long end;
    char flags[4];
} MapEntry;

MapEntry read_maps_file(int pid, unsigned long buffer_len);
MapEntry parse_map_entry(const char* line);
int check_validity(MapEntry entry, unsigned long buffer_size);

#endif
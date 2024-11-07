#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

/* parses the /proc/<PID>/maps file to find entries that have executable permissions and an address space large enough to fit our own code */
MapEntry read_maps_file(int pid, unsigned long buffer_len) { // buffer len will be the size of the buffer containing our opcodes
    char filename[MAX_LINE_LENGTH] = "/proc/%i/maps";
    sprintf(filename, "/proc/%i/maps", pid);
    
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening maps file");
        exit(1);
    }

    char buffer[4096];
    MapEntry entry;
    
    while (fgets(buffer, sizeof(buffer), file)) {
        buffer[strcspn(buffer, "\n")] = 0;
        
        entry = parse_map_entry(buffer);
        if (check_validity(entry, buffer_len)) {
            fclose(file);
            return entry;
        }
    }

    fclose(file);
    perror("no valid entries found in the maps file");
    exit(1);
}

/* extract the start and end addresses of the allocation, as well as the permission flags */
MapEntry parse_map_entry(const char* line) {
    MapEntry entry;
    
    // parse the start and end address of the page, and the first 3 characters representing permission flags
    sscanf(line, "%lx-%lx %3s", 
           &entry.start, &entry.end, entry.flags);
    return entry;
}

/* returns true (1) if the map entry has read and execute, or read write and execute perms */
int check_validity(MapEntry entry, unsigned long buffer_size) {
    unsigned long range_size = entry.end - entry.start;
    if (range_size < buffer_size*sizeof(unsigned char)) {
        return 0; // buffer too large, the input buffer will not fit inside the mapped size
    }
    
    int flags = 0;
    if (entry.flags[0] == 'r') flags |= READ;
    if (entry.flags[1] == 'w') flags |= WRITE;
    if (entry.flags[2] == 'x') flags |= EXECUTE;
    
    return (flags == (READ | WRITE | EXECUTE)) || 
           (flags == (READ | EXECUTE)); // compare the bitmasks
}
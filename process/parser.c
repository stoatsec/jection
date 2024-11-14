#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parser.h"

/* parses the /proc/<PID>/maps file to find entries that have executable permissions and an address space large enough to fit our own code */
MapEntry parse_rwx(pid_t pid, unsigned long buffer_len) { // buffer len will be the size of the buffer containing our opcodes
    char filename[MAX_LINE_LENGTH] = "/proc/%i/maps";
    sprintf(filename, "/proc/%i/maps", pid);
    
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening maps file");
        exit(1);
    }

    char line[4096];
    MapEntry entry;
    
    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;
        
        entry = parse_map_perms(line);
        if (check_validity(entry, buffer_len)) {
            fclose(file);
            return entry;
        }
    }

    fclose(file);
    perror("no valid entries found in the maps file");
    exit(1);
}

/* parses the /proc/<PID>/maps file to find the location of libc */
MapEntry parse_libc_loc(pid_t pid) {
    char filename[MAX_LINE_LENGTH] = "/proc/%i/maps";
    sprintf(filename, "/proc/%i/maps", pid);

    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening maps file");
        exit(1);
    }

    char line[4096];
    MapEntry entry;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        entry = parse_map_perms(line);
        if (strstr(line, "libc.so")) {
            entry.path = strchr(line, '/'); // retrieve file path and store in the map entry
            
            fclose(file);
            return entry;
        }
    }
    
    fclose(file);
    perror("libc not loaded in target process");
    exit(1);
}

/* extract the start and end addresses of the allocation, as well as the permission flags */
MapEntry parse_map_perms(const char* line) {
    MapEntry entry;
    
    // parse the start and end address of the page, and the first 3 characters representing permission flags
    sscanf(line, "%llx-%llx %3s", 
           &entry.start, &entry.end, entry.flags);
    return entry;
}

/* returns true (1) if the map entry has read and execute, or read write and execute perms */
int check_validity(MapEntry entry, unsigned long buffer_size) {
    unsigned long long range_size = entry.end - entry.start;
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

/*
int parse_dlopen(const char* libc_path) {
    
    FILE* file = fopen(libc_path, "rb");
    if (!file) {
        perror("Failed to libc share object");
        return 1;
    }
    
    // elf header
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, file) != 1) {
        perror("Failed to read ELF header");
        fclose(file);
        return 1;
    }
    
    // check elf file validity
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        fclose(file);
        return 1;
    }
    
    Elf64_Sym *symtab = NULL;
    Elf64_Shdr* sechdrs = NULL;
    
    int num_sections = ehdr.e_shnum;
    sechdrs = malloc(num_sections * sizeof(Elf64_Shdr));
    
    // locate dynsym
    int dynsym_idx = -1;
    for (int i = 0; i < num_sections; i++) {
        if (sechdrs[i].sh_type == SHT_DYNSYM) {
            dynsym_idx = i;
            break;
        }
    }
    
    if (dynsym_idx == -1) {
        fprintf(stderr, "dynamic symbol table not found\n");
        fclose(file);
        free(sechdrs);
        return 1;
    }
}
*/
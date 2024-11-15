#include <sys/user.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>

#include "inject.h"
#include "process/trace.h"


int main(int argc, char** argv) {
   	if(argc < 2) {
        printf("Usage: %s <PID> [FLAGS]", argv[0]);
		return 1;
	}
    
    char *endptr;
    pid_t pid = (pid_t)strtol(argv[1], &endptr, 10);
        
    if (endptr == argv[1]) {
        perror("Error: Invalid PID\n");
        return 1;
    }
    
    // check if pid is currently running
        
    if (kill(pid, 0) != 0) {
        printf("Process with PID %ld is not running\n", (long)pid);
        exit(1);
    }
    
    attach(pid);
    
    for (int i = 2; i < argc; i++) {  
        
        if (strcmp(argv[i], "-h") == 0) {
            printf("USAGE: jection <PID> [FLAGS]\n\n");
            printf("FLAGS:\n");
            printf("-l <libpath> -- injects a library from an absolute path into the target PID\n");
            printf("-r <address> -- reads memory from the specified address\n");
            printf("-p <address> <data> -- writes data to specified address\n");
            printf("-h -- displays this dialogue\n");
        }
        
        else if (strcmp(argv[i], "-l") == 0) {      
            
            char* libpath;
            if (i + 1 != argc) {
                libpath = argv[i + 1]; 
            } else {
                printf("Error: -l flag requires one argument (libpath)\n");
                return 1;
            }
            
            int status = inject_so(pid, libpath);

            if (status != 0) {
                return 1;
            }
            
            i++;
        }
        
        else if (strcmp(argv[i], "-p") == 0) {
            if (i + 2 >= argc) {
                printf("Error: -p flag requires two arguments (address and data)\n");
                return 1;
            }
            
            unsigned long long address = strtoull(argv[i + 1], NULL, 16);
            char data = strtoull(argv[i + 2], NULL, 16);
            
            pokemem(pid, address, &data, 1);
            printf("[+] Writing data 0x%hhx to address %llx\n", data, address);

            i += 2;
        }
        
        else if (strcmp(argv[i], "-r") == 0) {
            if (i + 1 >= argc) {
                printf("Error: -r flag requires one argument (address)\n");
                return 1;
            }
            
            unsigned long long address = strtoull(argv[i + 1], NULL, 16);
            unsigned char data;
            
            readmem(pid, address, &data, 1);
            printf("[+] Data at address %llx: 0x%hhx\n", address, data);

            i++;
        }
    }
    
    detach(pid);
        
    return 0;
}

// todo!
// - set registers from cli
// - one-off shellcode injection
// - shared object removal
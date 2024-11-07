#include <stdio.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include "injector/inject.h"
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
    
    unsigned long long realreal;
    if (addrspc_alloc(pid, 4096, &realreal) == -1) {
        perror("alloc failed lol oopsie");
        exit(1);
    }

    printf("addr: %llx", realreal); 
    
    detach(pid);

}
#include <sys/types.h>
#include <wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "trace.h"


// uses ptrace syscall to handle the running process

void attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("Failed to attach to process");
        exit(1);
    }
    
    int status;
   	if(waitpid(pid, &status, WUNTRACED) != pid) {
		perror("Failed to run waitpid(). Process was not ready to be traced");
		exit(1);
	}
}

void detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("Process failed to detach");
        exit(1);
    }
}

/* read memory starting at a set address into a buffer */
void readmem(pid_t pid, unsigned long addr, unsigned char* data, size_t len) {
    int index = 0; 
    
    while (index < len) {
        addr += sizeof(unsigned char);        
        errno = 0;
        data[index] = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);    
        if (errno != 0) {
            perror("Failed to read target process memory");
            exit(1);
        }
        
        index++;
    }
}

/* continues the traced process */
void continue_process(pid_t pid) {
   	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
	{
		perror("Failed to continue target process");
		exit(1);
	}
}

/* write memory from a buffer starting at a set address */
void pokemem(pid_t pid, unsigned long addr, unsigned char* data, size_t len) {
    
    int index = 0; 
    
    while (index < len) {
        addr += sizeof(unsigned char);        
        if (ptrace(PTRACE_POKEDATA, pid, addr, data[index]) == -1) {
            perror("Failed to poke target process memory");
            exit(1);
        } // I'll make this work with a larger type for performance later
                
        index++;
    }
}

/* reads the attached process' registers into regs */
void get_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        perror("Failed to read target process registers");
        exit(1);
    }
}

/* sets target process' registers to the values specified in the user regs struct */
void set_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("Failed to set target process registers");
        exit(1);
    }
}
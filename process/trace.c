#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>

#include "trace.h"

// uses ptrace syscall to handle the running process

void attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("Failed to attach to process");
        exit(-1);
    }

    int status;
    if (waitpid(pid, &status, WUNTRACED) != pid) {
        perror("Failed to run waitpid(). Process was not ready to be traced");
        exit(-1);
    }
}

void detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("Process failed to detach");
        exit(-1);
    }
}

/* read memory starting at a set address into a buffer */
void readmem_ul(pid_t pid, uint64_t addr, uint64_t* data, size_t len) {
    int index = 0;

    while (index < len) {
        errno = 0;
        data[index] = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (errno != 0) {
            perror("Failed to read target process memory");
            exit(-1);
        }

        addr += sizeof(uint64_t);
        index++;
    }
}

/*
    void pokemem(pid_t pid, unsigned long long addr, void *data,
                size_t len, size_t type) {

        int index = 0;
        unsigned long long pokedata = 0;

        while (index < len) {

            memcpy(&pokedata, data + (index * len), type);

            if (ptrace(PTRACE_POKEDATA, pid, addr, pokedata) == -1) {
                perror("Failed to poke target process memory");
                exit(-1);
            }

            addr += sizeof(unsigned long long);
            index++;
        }
    }

    void readmem(pid_t pid, unsigned long long addr, void* data, size_t len,
   size_t type) {

        int index = 0;
        unsigned long long* bufptr = (unsigned long long*) data;

        while (index < len) {
            errno = 0;
            bufptr[index] = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
            if (errno != 0) {
                perror("Failed to read target process memory");
                exit(-1);
            }

            addr += type;
            index++;
        }
    }
*/

/* write memory from a buffer starting at a set address */
void pokemem_ul(pid_t pid, uint64_t addr, uint64_t* data, size_t len) {
    int index = 0;

    while (index < len) {
        if (ptrace(PTRACE_POKEDATA, pid, addr, data[index]) == -1) {
            perror("Failed to poke target process memory");
            exit(-1);
        }

        addr += sizeof(uint64_t);
        index++;
    }
}

/* read chars from memory starting at a set address into a buffer */
void readmem_char(pid_t pid, uint64_t addr, char* data, size_t len) {
    int index = 0;

    while (index < len) {
        errno = 0;

        data[index] = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (errno != 0) {
            perror("Failed to read target process memory");
            exit(-1);
        }

        addr += sizeof(char);
        index++;
    }
}

/* write chars to memory from a buffer starting at a set address */
void pokemem_char(pid_t pid, uint64_t addr, char* data, size_t len) {
    int index = 0;

    while (index < len) {
        if (ptrace(PTRACE_POKEDATA, pid, addr, data[index]) == -1) {
            perror("Failed to poke target process memory");
            exit(-1);
        }

        addr += sizeof(char);
        index++;
    }
}

/* continues the traced process */
void continue_process(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("Failed to continue target process");
        exit(-1);
    }
}

/* reads the attached process' registers into regs */
void get_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        perror("Failed to read target process registers");
        exit(-1);
    }
}

/* sets target process' registers to the values specified in the user regs
 * struct */
void set_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("Failed to set target process registers");
        exit(-1);
    }
}

/* continue execution until the next syscall */
void wait_syscall(pid_t pid) {
    int status;

    while (1) {
        int syscall = ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            return;

        } else if (WIFEXITED(status)) {
            fprintf(stderr, "Attached process exited");
            exit(0);
        }

        continue_process(pid);
    }
}
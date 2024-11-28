#pragma once
#include <stdint.h>
#include <unistd.h>

void attach(pid_t pid);
void detach(pid_t pid);
void readmem_ul(pid_t pid, uint64_t addr, uint64_t* data, size_t len);
void pokemem_ul(pid_t pid, uint64_t addr, uint64_t* data, size_t len);
void readmem_char(pid_t pid, uint64_t addr, char* data, size_t len);
void pokemem_char(pid_t pid, uint64_t addr, char* data, size_t len);
void continue_process(pid_t pid);
void get_registers(pid_t pid, struct user_regs_struct* regs);
void set_registers(pid_t pid, struct user_regs_struct* regs);
void wait_syscall(pid_t pid);
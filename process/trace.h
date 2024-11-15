#pragma once
#include <unistd.h>

void attach(pid_t pid);
void detach(pid_t pid);
void readmem(pid_t pid, unsigned long addr, unsigned char* data, size_t len);
void pokemem(pid_t pid, unsigned long addr, char* data, size_t len);
void continue_process(pid_t pid);
void get_registers(pid_t pid, struct user_regs_struct* regs);
void set_registers(pid_t pid, struct user_regs_struct* regs);
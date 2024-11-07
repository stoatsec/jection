#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../process/parser.h"
#include "../process/trace.h"

/* allocates space to store our code in on the target process, and writes the block's starting address to the address parameter */
int addrspc_alloc(pid_t pid, size_t map_size, unsigned long long* address) {
    
    unsigned char stub_buffer[] = {
        0x0f, 0x05, 0xcc // syscall and int3
    };
    
    struct user_regs_struct regs, backup_regs;
    unsigned long size = sizeof(stub_buffer);
    MapEntry entry = read_maps_file(pid, size);
        
    // back up memory and registers
    unsigned char backup_buf[size];
    readmem(pid, entry.start, backup_buf, size);
    
    get_registers(pid, &backup_regs);
    get_registers(pid, &regs);
    
    regs.rax = 9;                // mmap syscall
    regs.rdi = 0;               // map offset
    regs.rsi = map_size;       // size
    regs.rdx = 7;             // permissions (full)
    regs.r10 = 0x22;         // anonymous
    regs.r8 = 0;            // fd
    regs.r9 = 0;           // fd

    regs.rip = entry.start; // direct the instruction pointer to the start of our injected code
    
    set_registers(pid, &regs);// set registers to the newly initialized registers struct
    pokemem(pid, entry.start, stub_buffer, sizeof(stub_buffer)); // write our syscall/sigtrap buffer to memory where rip points
    continue_process(pid); // continue execution at the start of our buffer
    
    int status;

    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        get_registers(pid, &regs);
        if (regs.rax != -1) { // check remote mmap's return value
            *address = regs.rax; // mmap ran successfully, retrieve the address to the start of our memory block from the rax register
            status = 0;     
        } else {
            status = -1;
        }
    }
    
    // restore program state
    set_registers(pid, &backup_regs);
    pokemem(pid, entry.start, backup_buf, sizeof(backup_buf));
        
    return status;
}

int inject_so() {
    
} // process_vm__writev
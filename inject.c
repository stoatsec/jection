#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

#include "process/parser.h"
#include "process/trace.h"

// techniques inspired by http://phrack.org/issues/59/8.html

static unsigned char syscall_stub[] = {
    0x0f, 0x05, 0xcc // syscall and int3
};

static unsigned char rax_call_stub[] = {
    0xff, 0xd0, 0xcc // call rax and int3
};

/* allocates space to store our code in on the target process, and writes the block's starting address to the address parameter */
int addrspc_alloc(pid_t pid, size_t map_size, unsigned long long* address) {
    
    struct user_regs_struct regs, backup_regs;
    unsigned long size = sizeof(syscall_stub);
    MapEntry entry = parse_rwx(pid, size);
        
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
    pokemem(pid, entry.start, syscall_stub, sizeof(syscall_stub)); // write our syscall/sigtrap buffer to memory where rip points
    continue_process(pid); // continue execution at the start of our buffer
    
    int status;

    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        get_registers(pid, &regs);
        if (regs.rax != -1) {     // check remote mmap's return value
            *address = regs.rax; // mmap ran successfully, retrieve the address to the start of our memory block from the rax register
            status = 0;         // int3 is hit after execution, and the program halts so we can restore the memory and registers
        } else {
            status = -1;
        }
    }
    
    // restore program state
    set_registers(pid, &backup_regs);
    pokemem(pid, entry.start, backup_buf, sizeof(backup_buf));
        
    return status;
}

int inject_so(pid_t pid, char* path) {
    
    unsigned long long path_address;
    size_t pathsize = strlen(path);
    unsigned long stub_size = sizeof(rax_call_stub);
    MapEntry stub_entry = parse_rwx(pid, stub_size); // locate a memory block suitable for injecting the stub
    
    // get the location of dlopen from where libc is loaded into memory
    MapEntry libc_entry = parse_libc_loc(pid);
    unsigned long long offset = 589664; // need to change this dynamically fr fr
    
    // allocate a block of memory for the shared object path
    addrspc_alloc(pid, pathsize, &path_address);
    
    // back up memory
    unsigned char backup_buf[stub_size];
    readmem(pid, stub_entry.start, backup_buf, stub_size);
    
    // back up registers
    struct user_regs_struct regs, backup_regs;
    get_registers(pid, &backup_regs);
    get_registers(pid, &regs);

    // inject path into newly allocated chunk of memory in target process
    pokemem(pid, path_address, path, pathsize);
    pokemem(pid, stub_entry.start, rax_call_stub, sizeof(rax_call_stub)); // inject our stub into memory as well
        
    // prepare target process registers for dlopen() execution
    regs.rax = libc_entry.start + offset; // location of dlopen() in our target process' memory
    regs.rdi = path_address+1;           // pointer to shared object path (+1 because we land on a null byte otherwise)
    regs.rsi = RTLD_LAZY;               // lazy :P
    
    regs.rip = stub_entry.start;
    
    set_registers(pid, &regs);
    continue_process(pid); // continue execution at the start of our buffer
    
    int status;

    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        get_registers(pid, &regs);
        if (regs.rax != 0) {    
            status = 0;
        } else {
            //perror("dlopen failed");
            status = -1;
        }
    }
    
    // restore program state
    set_registers(pid, &backup_regs);
    pokemem(pid, stub_entry.start, backup_buf, sizeof(backup_buf));
    
    return status;
    
    // todo!
    // - get dlopen from .dynsym section in libc binary
    
}
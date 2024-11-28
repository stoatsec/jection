#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "inject.h"
#include "colors.h"
#include "parsing/parser.h"
#include "process/trace.h"
#include "utils.h"

// techniques inspired by http://phrack.org/issues/59/8.html

/* executes a syscall specified by the registers struct passed in */
int inject_syscall(pid_t pid, struct user_regs_struct* regs, int ret) {
    struct user_regs_struct backup_regs;
    size_t size = sizeof(syscall_stub)
        / sizeof(syscall_stub[0]); // get the true length of the
    // array from the byte count

    MapEntry entry = parse_rwx(pid, size);

    // back up memory and registers
    uint64_t backup_buf[size];
    readmem_ul(pid, entry.start, backup_buf, size);
    get_registers(pid, &backup_regs);

    regs->rip = entry.start;

    set_registers(
        pid,
        regs
    ); // set registers to the newly initialized registers struct
    pokemem_ul(
        pid,
        entry.start,
        syscall_stub,
        size
    ); // write our syscall/sigtrap buffer to
        // memory where rip points
    continue_process(pid); // continue execution at the start of our buffer

    int status;

    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        get_registers(pid, regs);
        if (regs->rax != ret) { // check remote mmap's return value
            status = 0; // int3 is hit after execution, and the program halts so
                // we can restore the memory and registers
        } else {
            printf(
                "[%s] Failed to execute syscall with id: %llu\n",
                RED "-" RESET,
                regs->orig_rax
            );
            status = -1; // returns -1 if an unexpected return value is found
        }
    }

    // restore program state
    set_registers(pid, &backup_regs);
    pokemem_ul(pid, entry.start, backup_buf, size);

    return status;
}

/* allocates space to store our code in on the target process, and writes the
 * block's starting address to the address parameter */
int addrspc_alloc(pid_t pid, size_t map_size, uint64_t* address) {
    struct user_regs_struct regs;
    get_registers(pid, &regs);

    regs.rax = 9; // mmap syscall
    regs.rdi = 0; // map offset
    regs.rsi = map_size; // size
    regs.rdx = 7; // permissions (full)
    regs.r10 = 0x22; // anonymous
    regs.r8 = 0; // fd
    regs.r9 = 0; // fd

    int status = inject_syscall(pid, &regs, -1);
    *address = regs.rax;

    printf(
        "[%s] Attempted to allocate memory block at %lx\n",
        GREEN "+" RESET,
        *address
    );

    return status;
}

/* calls munmap on a specified block of memory */
int addrspc_dealloc(pid_t pid, size_t map_size, uint64_t address) {
    struct user_regs_struct regs;
    get_registers(pid, &regs);

    regs.rax = 11; // munmap syscall
    regs.rdi = address; // address start of the block
    regs.rsi = map_size; // size

    int status = inject_syscall(pid, &regs, -1);

    if (status != -1) {
        printf(
            "[%s] Deallocated memory block at %lx\n",
            GREEN "+" RESET,
            address
        );
    }

    return status;
}

/* injects a shared object specified by the char* path in the target process
 * (will require an asbolute path for now) */
int inject_so(pid_t pid, char* path) {
    uint64_t path_address;
    size_t pathsize = strlen(path);
    size_t stub_size = sizeof(rax_call_stub)
        / sizeof(rax_call_stub[0]); // get the length of the array
    MapEntry stub_entry =
        parse_rwx(pid, sizeof(rax_call_stub)); // locate a memory block suitable
    // for injecting the stub

    // get the location of dlopen from where libc is loaded into memory
    MapEntry libc_entry = parse_libc_loc(pid);
    uint64_t offset = parse_libc_sym("dlopen"
    ); // locate the offset of the symbol "dlopen" in libc
    // objdump -T /lib/libc.so.6 | grep dlopen

    // allocate a block of memory for the shared object path
    int path_alloc = addrspc_alloc(pid, pathsize, &path_address);
    if (path_alloc != 0) {
        printf(
            "[%s] Failed to allocate memory for shared object path\n",
            RED "-" RESET
        );
    }

    // back up memory
    uint64_t backup_buf[stub_size];
    readmem_ul(pid, stub_entry.start, backup_buf, stub_size);

    // back up registers
    struct user_regs_struct regs, backup_regs;
    get_registers(pid, &backup_regs);
    get_registers(pid, &regs);

    // inject path into newly allocated chunk of memory in target process
    pokemem_char(pid, path_address, path, pathsize);
    pokemem_ul(
        pid,
        stub_entry.start,
        rax_call_stub,
        stub_size
    ); // inject our stub into memory as well

    // prepare target process registers for dlopen() execution
    regs.rax = libc_entry.start
        + offset; // location of dlopen() in our target process' memory
    regs.rdi = path_address; // pointer to shared object path
    regs.rsi = RTLD_LAZY; // lazy :P

    regs.rip = stub_entry.start;

    set_registers(pid, &regs);
    continue_process(pid); // continue execution at the start of our buffer

    int status;

    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        get_registers(pid, &regs);
        if (regs.rax != 0) {
            printf(
                "[%s] Successfully injected shared object \"%s\"\n",
                GREEN "+" RESET,
                path
            );
            status = 0;
        } else {
            printf(
                "[%s] Failed to inject shared object \"%s\"\n",
                RED "-" RESET,
                path
            );
            status = -1;
        }
    } else {
        printf(
            "[%s] Failed to inject shared object \"%s\". Process did not stop\n",
            RED "-" RESET,
            path
        );
        status = -1;
    }

    // free memory block holding shared object path
    int path_dealloc = addrspc_dealloc(pid, pathsize, path_address);
    if (path_dealloc != 0) {
        printf(
            "[%s] Failed to deallocate memory for shared object path",
            RED "-" RESET
        );
    }

    // restore program state
    set_registers(pid, &backup_regs);
    pokemem_ul(pid, stub_entry.start, backup_buf, stub_size);

    return status;
}
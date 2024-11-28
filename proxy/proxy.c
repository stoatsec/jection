#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../colors.h"
#include "../process/trace.h"
#include "../utils.h"

typedef struct {
    char* content;
    int size;
} compbuf;

/* check if the next syscall is send_to or send_msg, and return one if true */
static int wait_send_syscall(pid_t pid) {
    wait_syscall(pid);

    struct user_regs_struct regs;
    get_registers(pid, &regs);

    if ((regs.orig_rax != 44)
        && (regs.orig_rax != 46
        )) { // if syscall is not send_to or send_msg, we return 0
        return 0;
    }

    return 1;
}

/* main syscall intercept proxy loop */
void proxy_loop(pid_t pid, int compare) {
    int is_send_syscall = 0;
    struct user_regs_struct regs;

    compbuf old_buffer;
    old_buffer.content = NULL;
    old_buffer.size = 0;

    while (1) {
        is_send_syscall = wait_send_syscall(pid);

        if (is_send_syscall != 1) {
            continue;
        }

        get_registers(pid, &regs);

        // rdx: content buffer length
        // rsi: pointer to content buffer

        char contentbuf[regs.rdx];
        readmem_char(pid, regs.rsi, contentbuf, regs.rdx);

        unsigned int indicies_size = 0;
        int* matches = NULL;

        if (compare && old_buffer.content != NULL && old_buffer.content > 0) {
            size_t min_size =
                (regs.rdx < old_buffer.size) ? regs.rdx : old_buffer.size;
            matches = compare_bufs(
                contentbuf,
                old_buffer.content,
                min_size,
                &indicies_size
            );
        } // compare the new and old buffers, and store the indicies that match in matches

        printf("[%s] ", GREEN "+" RESET);

        if (matches != NULL) {
            for (int i = 0; i < regs.rdx; i++) {
                int is_match = 0;

                for (int ii = 0; ii < indicies_size; ii++) {
                    if (matches[ii] == i) {
                        is_match = 1;
                        break;
                    }
                }

                if (is_match) {
                    printf(GREEN "%hhx " RESET, contentbuf[i]);
                } else {
                    printf("%hhx ", contentbuf[i]);
                }
            }
        } else {
            for (int i = 0; i < regs.rdx; i++)
                printf("%hhx ", contentbuf[i]);
        }

        printf(RESET "\n");

        if (old_buffer.content != NULL) {
            free(old_buffer.content);
        }

        old_buffer.content = malloc(regs.rdx);
        if (old_buffer.content == NULL) {
            perror("Failed to allocate memory for old_buffer.content");
            exit(1);
        }

        memcpy(old_buffer.content, contentbuf, regs.rdx);
        old_buffer.size = regs.rdx;

        wait_send_syscall(pid); // skip syscall exit
    }
}

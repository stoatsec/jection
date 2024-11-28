#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <unistd.h>

#include "colors.h"
#include "inject.h"
#include "process/trace.h"
#include "proxy/proxy.h"

static void print_help() {
    printf("USAGE: jection <PID> [FLAGS]\n\n");
    printf("FLAGS:\n");
    printf(
        "-l <libpath> ─  injects a library from an absolute path into the target PID\n"
    );
    printf("-r <address> ─  reads memory from the specified address\n");
    printf("-p <address> <data> ─  writes data to specified address\n");
    printf("-h ─  displays this dialogue\n");
    printf(
        "-i ─  intercept send and send_to syscalls and print the transmitted data\n"
    );
    printf(
        " └─  -c ─  compare each data buffer with the previous one to highlight matching bytes\n"
    );
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <PID> [FLAGS]", argv[0]);
        return 1;
    }

    char* endptr;
    pid_t pid = (pid_t)strtol(argv[1], &endptr, 10);

    if (endptr == argv[1]) {
        fprintf(stderr, "Error: Invalid PID\n");
        return 1;
    }

    // check if pid is currently running

    if (kill(pid, 0) != 0) {
        printf("Process with PID %ld is not running\n", (long)pid);
        exit(1);
    }

    attach(pid);

    static struct option long_options[] = {
        {"library", required_argument, NULL, 'l'},
        {"poke", required_argument, NULL, 'p'},
        {"read", required_argument, NULL, 'r'},
        {"intercept", no_argument, NULL, 'i'},
        {"compare", no_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int compare = 0;
    int intercept = 0;
    int status = 0;
    char* libpath;
    uint64_t addr;
    uint64_t data;

    int c;
    while ((c = getopt_long(argc, argv, "hcir:p:l:", long_options, NULL)) != -1
    ) {
        switch (c) {
            case 'i':
                intercept = 1;
                break;
            case 'c':
                compare = 1;
                break;
            case 'l':

                status = inject_so(pid, optarg);

                if (status != 0) {
                    return -1;
                }

                return 0;
            case 'p':

                if (optind + 1 != argc) {
                    fprintf(
                        stderr,
                        RED "Option 'poke' requires two arguments\n\n" RESET
                    );
                    print_help();
                    return -1;
                }

                addr = strtoull(optarg, NULL, 16);
                optarg = argv[optind++];
                data = strtoull(optarg, NULL, 16);

                pokemem_ul(pid, addr, &data, 1);
                printf(
                    "[%s] Writing data 0x%lx to address %lx\n",
                    GREEN "+" RESET,
                    data,
                    addr
                );

                return 0;
            case 'r':
                addr = strtoull(optarg, NULL, 16);

                readmem_ul(pid, addr, &data, 1);
                printf(
                    "[%s] Data at address %lx: 0x%lx\n",
                    GREEN "+" RESET,
                    addr,
                    data
                );

                return 0;
            case 'h':
                print_help();
                return 0;

            default:
                return 1;
        }
    }

    if (intercept == 1) {
        proxy_loop(pid, compare);
    } else {
        fprintf(stderr, RED "No valid arguments provided\n\n" RESET);
        print_help();
    }

    detach(pid);

    return 0;
}
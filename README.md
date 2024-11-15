# Jection

An external process memory injector for x86_64 Linux written in C. Uses the ptrace syscall to handle running processes. Features include shared object injection as well as reading/writing memory to/from set locations in memory. 	

## Usage

Jection attaches to a running process, so the first argument supplied must be the target PID. Jection must be run with root.

```jection <PID> [FLAGS]```

**Flags**:

 - -l <libpath> -- injects a shared object into the running process where libpath is the absolute path to the shared object file
 - -p <address> <data> -- poke data to a specified memory address
 - -r <address> -- read memory from a specified memory address
 - -h -- displays the help dialogue


## Features

 - attach to and edit running process memory
 - shared object injection

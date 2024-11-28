# Jection

(*heavily* beta)

An external process memory modification toolkit for x86_64 Linux written in C. Features include shared object injection, syscall interception,  and basic memory read/write capabilities.

## Installation

As of right now, the only way to install Jection is to compile it with make.

```
git clone https://github.com/stoatsec/jection.git
cd jection

make
mv build/jection /usr/local/bin/
```

## Usage

Jection attaches to a running process, so the first argument supplied must be the target PID. Jection also has to be run with root.

```jection <PID> [FLAGS]```

**Flags**:

```
 --library / -l <libpath> ─ injects a shared object into the running process where libpath is the absolute path to the shared object file
 --poke / -p <address> <data> ─ poke data to a specified memory address
 --read / -r <address> ─ read memory from a specified memory address
 --help / -h ─ displays the help dialogue
 -- intercept / -i ─ intercepts send and send_to syscalls
    └─ --compare / -c ─  compare each data buffer with the previous one to highlight matching bytes
```

## Features

 - attach to and edit running process memory at specified addresses
 - proxy syscalls and intercept data before it reaches the operating system network stack
 - inject shared objects into running processes
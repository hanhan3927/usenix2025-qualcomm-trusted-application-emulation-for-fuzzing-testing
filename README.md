# Qualcomm Trusted Application Emulation for Fuzzing Testing
## USENIX Security 2025 Poster Submission

**Status:** Accepted

*This work will be presented at USENIX Security 2025 poster session.*

## Full Technical Paper

Preprint: [arXiv](https://arxiv.org/abs/2507.08331)

---

## Overview

This tool is based on the Unicorn Engine for emulating ARM64 Pixel 4-XL trusted applications. The emulator includes debugging features for code tracing and can partially emulate code of interest.

## Features

### Emulator
The emulator provides comprehensive debugging capabilities:
- **Memory hexdump** - Inspect memory contents
- **Register dump** - View processor register states  
- **Instruction dump** - Trace executed instructions
- **Hook functionality** - Hook library code for convenient debugging environment setup

### Example Usage
```bash
./make
./emulator pixel4_widevine
```

## Loader Design

The loader parses ELF binary files and places library addresses in the GOT (Global Offset Table). When the program references these addresses, the emulator can jump to and execute the corresponding library code.

## Fuzzing Testing

### Prerequisites
1. Install AFL++ with Unicorn mode support
2. Configure the Makefile with your environment paths

### Configuration

Update the following paths in your Makefile according to your environment:

```makefile
# AFL-Unicorn installation directory
-I/PATH_TO_AFL_UNICORN_INSTALL_DIR

# Configure unicorn library paths
UNICORNAFL_LIB: /PATH_TO_YOUR_INSTALL_DIR
UNICORN_LIB: /PATH_TO_YOUR_INSTALL_DIR
```

### Compilation
Add the static library path to compile the harness:
```makefile
$(CC) $^ /PATH_TO_LIBUNICORNAFL.a $(LDFLAGS) -o $(EXE)
```

### Fuzzing Execution
Configure library paths and AFL-fuzz path:
```makefile
fuzz: $(EXE)
    DYLD_FALLBACK_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/build" \
    LD_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/build" \
    /PATH/AFLplusplus/afl-fuzz -m none -i sample_inputs -o out -t+1000 -- ./harness @@
```

### Pre-fuzzing Setup
Before starting fuzzing, run as root:
```bash
echo core >/proc/sys/kernel/core_pattern
```
This prevents core dump errors during fuzzing.

### Example Usage
```bash
make fuzz  # Compiles and starts fuzzing
```

## Troubleshooting

The loader loads dependency libraries inside the emulator but may encounter crashes when reaching uninitialized variables. These issues can be resolved using the debug utilities and tracing functionality.

## Quick Start
1. Clone the repository
2. Configure paths in Makefile
3. Run `make` to build
4. Execute `./emulator pixel4_widevine` for basic emulation
5. Run `make fuzz` to start fuzzing testing

---

*This work is currently under review for the USENIX Security 2025 poster session. The full technical paper is available as a preprint on arXiv for detailed methodology and experimental results.*

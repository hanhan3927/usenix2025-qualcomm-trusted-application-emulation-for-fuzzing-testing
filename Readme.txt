# [USENIX Security 2025] Qualcomm Trusted Application Emulation for Fuzzing Testing
## Unicorn base trusted appliction fuzzing 

This tool is based on unicorn engine for emualting arm64 Pixel4-XL trusted application.


## Emulator

The emualtor we design some debugging features for code tracing, it can partial emualte the code we're interesting.
The debug feature including memory hexdump, register dump, and instruction dump !

Also the hook can be used to hook the library code, its very convenience for debugging the enviroment.

Example usage : 
    ./make
    ./emualtor pixel4_widevine

## Loader Design

The loader parse the ELF binary file, and basically simply place whole the library address in the GOT table, 
when the program use it, the emulator can also jump on the address and execute the code in the library.



## Fuzzing testing

Install afl-plusplus with unicorn mode first, and change the Makefile file.
For example change the unicorn library path and the fuzzer path to compile and fuzz the binary.

Below `PATH` need to change to your environmnet    
    -I/PATH afl-unicorn install directory 
    UNICORNAFL_LIB : Configure it as your install directory
    UNICORN_LIB : Configure it as your install directory

Add the static library path to compile the harness.
    $(CC) $^ PATH/libunicornafl.a $(LDFLAGS) -o $(EXE)

Add the path LD_LIBRARY_PATH and DYLD_FALLBACK_LIBRARY_PATH, and afl-fuzz path.
fuzz: $(EXE)
    DYLD_FALLBACK_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/build" LD_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_modeunicornafl/unicorn/build" /PATH/AFLplusplus/afl-fuzz -m none -i sample_inputs -o out -t+1000 -- ./harness @@


Loader will load the dependency library inside the emulator, but it may encounter some crash when reaching the uninitialize variables,
it can be fixed by using the debug utils and trace it !

Before fuzzing, enter root and set `echo core >/proc/sys/kernel/core_pattern` to avoid the error.

Example usage:
    make fuzz (It will compile it and start fuzzing)

CC:=gcc
EXE:=harness
SRCS:=harness.c util.c
OBJS:=$(SRCS:.c=.o)
CFLAGS +=-Wall -I/PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/include -I/PATH/AFLplusplus/unicorn_mode/unicornafl/include

UNICORNAFL_LIB = /PATH/AFLplusplus/unicorn_mode/unicornafl/build
UNICORN_LIB = /PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/build


LDFLAGS += -L$(UNICORNAFL_LIB) -L$(UNICORN_LIB) -lunicornafl -lunicorn -lpthread -lcapstone -lm -lstdc++ -lrt

.PHONY: all clean

harness: harness.o util.o
	$(CC) $^ /PATH/AFLplusplus/unicorn_mode/unicornafl/build/libunicornafl.a $(LDFLAGS) -o $(EXE)

harness.o: harness.c
	$(CC) $(CFLAGS) -O3 -c $<

util.o: util.c
	$(CC) $(CFLAGS) -O3 -c $<

fuzz: $(EXE)
	DYLD_FALLBACK_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_mode/unicornafl/unicorn/build" LD_LIBRARY_PATH="/PATH/AFLplusplus/unicorn_modeunicornafl/unicorn/build" /PATH/AFLplusplus/afl-fuzz -m none -i sample_inputs -o out -t+1000 -- ./harness @@

clean:
	rm -f *.o $(EXE)

 

CC:=gcc
EXE:=emulator
SRCS:=emu.c hook_cmnlib.c util.c
OBJS:=$(SRCS:.c=.o)

CFLAGS = -g



all:$(EXE)

$(EXE):$(OBJS)
	@$(CC) $(OBJS) -lcapstone -lunicorn -lpthread -o $(EXE) 

%.o:%.c
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(EXE)


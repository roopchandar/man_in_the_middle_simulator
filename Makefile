CC      = gcc
CFLAGS  = -Wall -Wextra -g
LDFLAGS = -lws2_32
TARGETS = sender.exe attacker.exe receiver.exe

.PHONY: all clean

all: $(TARGETS)

sender.exe: sender.c
	$(CC) $(CFLAGS) -o sender.exe sender.c $(LDFLAGS)

attacker.exe: attacker.c
	$(CC) $(CFLAGS) -o attacker.exe attacker.c $(LDFLAGS)

receiver.exe: receiver.c
	$(CC) $(CFLAGS) -o receiver.exe receiver.c $(LDFLAGS)

clean:
	del /Q sender.exe attacker.exe receiver.exe 2>nul || true

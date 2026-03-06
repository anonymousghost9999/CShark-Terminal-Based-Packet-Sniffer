CC=gcc
CFLAGS=-Wall -Wextra -I..
LDFLAGS=-lpcap -pthread

all: cshark

cshark: device.c
	$(CC) $(CFLAGS) -o cshark device.c $(LDFLAGS)

clean:
	-rm -f cshark
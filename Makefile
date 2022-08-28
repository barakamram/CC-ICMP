CC=gcc
FLAGS=-Wall -g
.PHONY: all clean
all: myping sniffer

myping: myping.c
	$(CC) myping.c -lpcap -o myping

sniffer: sniffer.c
	$(CC) sniffer.c -lpcap -o sniffer

clean:
	rm myping sniffer

CC=gcc
CFLAGS=-O2

aapr: main.o aes.o crc.o sha1.o aapr.o
	$(CC) $(CFLAGS) -o build/aapr aes.c  crc.c sha1.c aapr.c main.c

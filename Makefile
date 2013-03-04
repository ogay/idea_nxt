CC = gcc
CFLAGS = -O2 -fomit-frame-pointer

all: test_vectors

test_vectors: nxt_common.o nxt64.o nxt128.o test_vectors.c
	$(CC) -Wall -W -ansi -pedantic $(CFLAGS) $^ -o $@

nxt64.o: nxt64.c nxt_common.h nxt64_tables.h nxt64.h
	$(CC) -Wall -W -ansi -pedantic $(CFLAGS) -c $< -o $@

nxt128.o: nxt128.c nxt_common.h nxt128_tables.h nxt128.h
	$(CC) -Wall -W -ansi -pedantic $(CFLAGS) -c $< -o $@

nxt_common.o: nxt_common.c nxt_common.h
	$(CC) -Wall -W -ansi -pedantic $(CFLAGS) -c $< -o $@

clean:
	- rm -rf *.o test_vectors


# Makefile for PT_LOAD injector

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

all: pt_load_injector test_hello

pt_load_injector: pt_load_injector.c
	$(CC) $(CFLAGS) -o pt_load_injector pt_load_injector.c

test_hello: test_hello.c
	$(CC) -no-pie -static -o test_hello test_hello.c

clean:
	rm -f pt_load_injector test_hello infected_hello *.o

test: all
	./test_hello
	./pt_load_injector test_hello infected_hello
	./infected_hello

.PHONY: all clean test

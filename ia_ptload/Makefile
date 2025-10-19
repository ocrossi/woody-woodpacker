# Makefile for PT_LOAD injector

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

all: pt_load_injector test_hello test_hello_pie

pt_load_injector: pt_load_injector.c
	$(CC) $(CFLAGS) -o pt_load_injector pt_load_injector.c

test_hello: test_hello.c
	$(CC) -no-pie -o test_hello test_hello.c

test_hello_pie: test_hello.c
	$(CC) -o test_hello_pie test_hello.c

clean:
	rm -f pt_load_injector test_hello test_hello_pie infected_hello infected_hello_pie *.o

test: all
	@echo "=== Testing non-PIE executable ==="
	./test_hello
	./pt_load_injector test_hello infected_hello
	./infected_hello
	@echo ""
	@echo "=== Testing PIE executable ==="
	./test_hello_pie
	./pt_load_injector test_hello_pie infected_hello_pie
	./infected_hello_pie

.PHONY: all clean test

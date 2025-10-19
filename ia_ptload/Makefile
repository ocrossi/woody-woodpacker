# Makefile for PT_LOAD injector

CC = gcc
CFLAGS = -Wall -Wextra -Werror -O2

all: pt_load_injector test_hello test_hello_pie encrypt_decrypt

pt_load_injector: pt_load_injector.c
	$(CC) $(CFLAGS) -o pt_load_injector pt_load_injector.c

encrypt_decrypt: encrypt_decrypt.c
	$(CC) $(CFLAGS) -o encrypt_decrypt encrypt_decrypt.c

test_hello: test_hello.c
	$(CC) -no-pie -o test_hello test_hello.c

test_hello_pie: test_hello.c
	$(CC) -o test_hello_pie test_hello.c

clean:
	rm -f pt_load_injector test_hello test_hello_pie infected_hello infected_hello_pie encrypt_decrypt *.o encrypted_* decrypted_*

test: all
	@echo "=== Testing non-PIE executable ==="
	./test_hello
	./pt_load_injector test_hello infected_hello
	./infected_hello
	@echo ""
	@echo "=== Testing encryption/decryption ==="
	./encrypt_decrypt infected_hello encrypted_infected_hello
	./encrypt_decrypt encrypted_infected_hello decrypted_infected_hello
	@echo "Verifying decrypted file matches original..."
	cmp infected_hello decrypted_infected_hello && echo "SUCCESS: Files match!" || echo "FAILED: Files don't match"
	@echo ""
	@echo "=== Testing PIE executable ==="
	./test_hello_pie
	./pt_load_injector test_hello_pie infected_hello_pie
	./infected_hello_pie
	./encrypt_decrypt infected_hello_pie encrypted_infected_hello_pie
	./encrypt_decrypt encrypted_infected_hello_pie decrypted_infected_hello_pie
	cmp infected_hello_pie decrypted_infected_hello_pie && echo "SUCCESS: PIE files match!" || echo "FAILED: PIE files don't match"

.PHONY: all clean test

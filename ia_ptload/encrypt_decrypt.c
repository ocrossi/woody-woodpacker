#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// Encryption seed for the PRNG
#define ENCRYPTION_SEED 0xDEADBEEF

// Tiny Xorshift32 PRNG
static inline uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

void encrypt_decrypt_file(const char *input_file, const char *output_file) {
    // Read input file
    int fd = open(input_file, O_RDONLY);
    if (fd == -1) {
        perror("Error opening input file");
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("Error getting file size");
        close(fd);
        exit(1);
    }

    size_t file_size = st.st_size;
    unsigned char *data = malloc(file_size);
    if (!data) {
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    if (read(fd, data, file_size) != (ssize_t)file_size) {
        perror("Error reading file");
        free(data);
        close(fd);
        exit(1);
    }
    close(fd);

    // XOR encrypt/decrypt using Xorshift32 PRNG
    uint32_t prng_state = ENCRYPTION_SEED;
    for (size_t i = 0; i < file_size; i++) {
        uint32_t keystream_byte = xorshift32(&prng_state) & 0xFF;
        data[i] ^= keystream_byte;
    }

    // Write output file
    fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("Error creating output file");
        free(data);
        exit(1);
    }

    if (write(fd, data, file_size) != (ssize_t)file_size) {
        perror("Error writing output file");
        close(fd);
        free(data);
        exit(1);
    }

    close(fd);
    free(data);

    printf("Successfully processed file: %s -> %s\n", input_file, output_file);
    printf("File size: %zu bytes\n", file_size);
    printf("XOR-stream encryption/decryption applied with PRNG seed: 0x%08X\n", ENCRYPTION_SEED);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        fprintf(stderr, "\nThis tool encrypts/decrypts files using XOR-stream with Xorshift32 PRNG.\n");
        fprintf(stderr, "The same operation encrypts and decrypts (XOR is symmetric).\n");
        return 1;
    }

    encrypt_decrypt_file(argv[1], argv[2]);
    return 0;
}

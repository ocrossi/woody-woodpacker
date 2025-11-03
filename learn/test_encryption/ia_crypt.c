#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* In-place encryption: exactly the behavior in ASM/encrypt.s */
void woody_encrypt(uint8_t *data, int dataSize, const uint8_t *key, int keySize) {
    if (dataSize <= 0 || keySize <= 0) return;
    /* first byte */
    data[0] = (uint8_t)(data[0] + key[0]);

    /* remaining bytes: data[i] += key[i % keySize] + data[i-1] (data[i-1] is already encrypted) */
    for (int i = 1; i < dataSize; ++i) {
        int k = i % keySize;
        uint8_t bl = (uint8_t)(key[k] + data[i - 1]);
        data[i] = (uint8_t)(data[i] + bl);
    }
}

/* In-place decryption: exactly the behavior in ASM/decrypt.s */
void woody_decrypt(uint8_t *data, int dataSize, const uint8_t *key, int keySize) {
    if (dataSize <= 0 || keySize <= 0) return;

    /* Start key index for the last byte: r = dataSize % keySize */
    int k = dataSize % keySize;

    /* process from end to 1 */
    for (int i = dataSize - 1; i >= 1; --i) {
        if (k == 0) k = keySize;
        --k; /* now k == (i % keySize) */
        uint8_t bl = (uint8_t)(data[i - 1] + key[k]);
        data[i] = (uint8_t)(data[i] - bl);
    }
    /* first byte */
    data[0] = (uint8_t)(data[0] - key[0]);
}

/* helper to print bytes in hex */
void print_hex(const uint8_t *buf, int n) {
    for (int i = 0; i < n; ++i) printf("%02X ", buf[i]);
    printf("\n");
}

int main(void) {
    uint8_t key[] = { 'A', 'B', 'C' }; /* ASCII 65,66,67 */
    uint8_t plaintext[] = { 'H', 'E', 'L', 'L', 'O' }; /* 72,69,76,76,79 */
    int n = sizeof(plaintext);

    printf("Plaintext bytes: ");
    print_hex(plaintext, n);

    /* encrypt */
    woody_encrypt(plaintext, n, key, sizeof(key));
    printf("Encrypted bytes: ");
    print_hex(plaintext, n); /* expected (mod 256): 89 10 9F 2C BD */

    /* decrypt back */
    woody_decrypt(plaintext, n, key, sizeof(key));
    printf("After decrypt:   ");
    print_hex(plaintext, n);

    /* Print as string */
    printf("Recovered text: '%.*s'\n", n, (char*)plaintext);
    return 0;
}

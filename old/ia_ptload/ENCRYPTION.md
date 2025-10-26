# XOR-Stream Encryption with PRNG

## Overview

This directory now includes an `encrypt_decrypt` tool that uses XOR-stream encryption with a tiny Xorshift32 PRNG to encrypt and decrypt output files.

## Implementation

### PRNG: Xorshift32

We use a tiny, fast Xorshift32 pseudo-random number generator:

```c
uint32_t xorshift32(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}
```

**Properties:**
- **Tiny**: Only 5 lines of C code, minimal assembly footprint
- **Fast**: Only bitwise operations (shifts and XORs)
- **Good period**: 2^32 - 1 (all non-zero states)
- **Deterministic**: Same seed always produces same keystream

### Encryption Seed

The encryption uses a fixed seed: `0xDEADBEEF`

This seed initializes the PRNG, which then generates a keystream that's XORed with the file data.

### Symmetric XOR Encryption

XOR encryption is symmetric, meaning the same operation both encrypts and decrypts:
- `encrypted = plaintext XOR keystream`
- `plaintext = encrypted XOR keystream`

## Usage

### Building

```bash
make clean
make
```

This builds:
- `pt_load_injector`: Creates infected ELF files
- `encrypt_decrypt`: Encrypts/decrypts files using XOR-stream
- `test_hello`: Test executable (non-PIE)
- `test_hello_pie`: Test executable (PIE)

### Encrypting an Output File

```bash
# Create infected file
./pt_load_injector test_hello infected_hello

# Encrypt the infected file
./encrypt_decrypt infected_hello encrypted_infected_hello
```

### Decrypting an Output File

```bash
# Decrypt the file
./encrypt_decrypt encrypted_infected_hello decrypted_infected_hello

# Verify it matches the original
cmp infected_hello decrypted_infected_hello
```

### Running Tests

```bash
make test
```

This will:
1. Create infected versions of test executables
2. Run them to verify they work
3. Encrypt the infected files
4. Decrypt them back
5. Verify the decrypted files match the originals
6. Test both PIE and non-PIE executables

## Example Output

```
=== Testing encryption/decryption ===
./encrypt_decrypt infected_hello encrypted_infected_hello
Successfully processed file: infected_hello -> encrypted_infected_hello
File size: 15964 bytes
XOR-stream encryption/decryption applied with PRNG seed: 0xDEADBEEF

./encrypt_decrypt encrypted_infected_hello decrypted_infected_hello
Successfully processed file: encrypted_infected_hello -> decrypted_infected_hello
File size: 15964 bytes
XOR-stream encryption/decryption applied with PRNG seed: 0xDEADBEEF

Verifying decrypted file matches original...
SUCCESS: Files match!
```

## Security Notes

**This is for educational purposes only!**

- XOR with a PRNG is NOT cryptographically secure
- The fixed seed means the keystream is always the same
- This provides obfuscation, not real security
- An attacker who knows the algorithm and seed can easily decrypt

For real security, use:
- Cryptographically secure PRNGs
- Proper key derivation functions
- Random initialization vectors
- Authenticated encryption (e.g., AES-GCM, ChaCha20-Poly1305)

## Technical Details

### File Structure

After encryption, the file is completely transformed:
- ELF magic bytes are encrypted (file becomes unrecognizable)
- All headers and code are XORed with the keystream
- File size remains the same
- The encrypted file cannot be executed

### Why Not Self-Decrypting?

While it would be possible to create a self-decrypting stub that decrypts the payload at runtime, this approach was chosen for simplicity and clarity:

1. **Simpler implementation**: No complex position-independent code needed
2. **Clearer demonstration**: The encryption/decryption process is explicit
3. **Flexible**: Can encrypt/decrypt any file, not just ELF executables
4. **Educational**: Shows the PRNG and XOR-stream concepts clearly

## Files

- `encrypt_decrypt.c`: XOR-stream encryption/decryption tool with Xorshift32 PRNG
- `pt_load_injector.c`: Original PT_LOAD injection tool (unchanged)
- `Makefile`: Updated to build the encryption tool and run tests
- `ENCRYPTION.md`: This documentation file

## References

- [Xorshift PRNGs](https://en.wikipedia.org/wiki/Xorshift): Simple, fast pseudo-random number generators
- [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher): Symmetric encryption using XOR operation
- [Stream cipher](https://en.wikipedia.org/wiki/Stream_cipher): Encryption using keystream generation

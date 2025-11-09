#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#define KEY_SIZE 8

typedef struct s_woodyData {
    int fd;
    size_t file_size;
    int fd_out;
    size_t output_size;
    char* output_bytes; 
    // size_t offset_ptnote; // how many bytes starting at the beginning of the file
    

    uint64_t new_entrypoint;
    char key[KEY_SIZE];

    // int payload_size;
    // uint64_t injection_addr;


    Elf64_Phdr pt_note; // lu tel quel dans le fichier
    Elf64_Phdr pt_load; // transforme pour infection
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

extern char* syscall_random(void *buf, int size);

extern void encrypt(const char *key, const char *text, size_t len);
extern void decrypt(const char *key, const char *text, size_t len);

void print_hex(const char* buffer, size_t n);

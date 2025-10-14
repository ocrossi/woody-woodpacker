#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

typedef struct s_woodyData {
    // char *file_bytes;
    // char *output_bytes;

    // size_t length_ptload;
    // size_t length_shellcode;
    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file

    int fd;

    Elf64_Phdr pt_note;
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

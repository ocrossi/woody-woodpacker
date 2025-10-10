#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>


typedef struct s_woodyData {
    char *file_bytes;
    char *output_bytes;
    void *e_entry;

    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file
 
    Elf64_Phdr pt_note;
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

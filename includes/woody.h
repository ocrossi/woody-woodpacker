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

    size_t length_ptload;
    size_t length_shellcode;
    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file
 
    Elf64_Phdr pt_note;
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;


// libc functions 
void	  *ft_memset(void *b, int c, size_t len);
void	  *ft_memcpy(void *dst, const void *src, size_t n);
size_t	ft_strlen(const char *str);
int		  ft_memcmp(const void *s1, const void *s2, size_t n);

// print functions
void print_hex(const char* buffer, size_t n);
void compare_elf_header_with_sytem(t_woodyData *data);
void compare_prgm_headers_with_system();
void print_program_header(Elf64_Phdr phdr);

// ASM functions
extern void asm_write(const char *str, size_t len);

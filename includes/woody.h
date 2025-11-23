#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#define KEY_SIZE 8

typedef struct s_woodyData {
    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file

    void *new_entrypoint;
    char key[KEY_SIZE + 1];

    char* output_bytes; 
    int payload_size;
    int size_out;
    uint64_t injection_addr;

    size_t start_encryption;
    size_t len_encryption;

    int fd;
    int fd_out;

    Elf64_Phdr pt_note; // lu tel quel dans le fichier
    Elf64_Phdr pt_load; // transforme pour infection
    Elf64_Shdr text_sec; // transforme pour infection
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

extern char* syscall_random(void *buf, int size);

extern void encrypt(const char *key, const char *text, size_t len);
extern void decrypt(const char *key, const char *text, size_t len);

int is_valid_elf64_executable(const Elf64_Ehdr *header);
int is_valid_elf64_program_header(const Elf64_Phdr *phdr, int index);
int is_valid_elf64_section_header(const Elf64_Shdr *shdr);

void print_hex(const char* buffer, size_t n);
void	*ft_memset(void *b, int c, size_t len);
void	*ft_memcpy(void *dst, const void *src, size_t n);
size_t	ft_strlen(const char *str);
int		ft_strcmp(const char *s1, const char *s2);

void read_parse_sheaders(t_woodyData *data);
void read_store_elf_header(t_woodyData *data);
Elf64_Phdr read_parse_phdrs_store_ptnote(t_woodyData *data);
t_woodyData read_store_headers(const char *filename);
char* read_shstrtab(t_woodyData *data);

#include "../includes/woody.h"

void read_parse_sheaders(t_woodyData *data) {
    char* sh_names = read_shstrtab(data);
    char control = 0;

    ssize_t bytes_read = 0;
    for (int i = 0; i < data->elf_hdr.e_shnum; i++) {
        Elf64_Shdr current;
        int offset = data->elf_hdr.e_shoff + i * data->elf_hdr.e_shentsize;
        lseek(data->fd, offset, SEEK_SET);
        memset(&current, 0, sizeof(Elf64_Shdr));
        bytes_read = read(data->fd, &current, data->elf_hdr.e_shentsize);
        if (bytes_read != data->elf_hdr.e_shentsize) {
            printf("Couldnt read section headers correctly\n");
            free(sh_names);
            exit(1);
        }
        if (!is_valid_elf64_section_header(&current)) {
            printf("Couldnt parse program header correctly at index %d\n", i);
            free(sh_names);
            exit(1);
        }
        if (ft_strcmp(".text", &sh_names[current.sh_name]) == 0) {
            ft_memcpy(&data->text_sec, &current, sizeof(Elf64_Shdr));
            control = 1;
        }  
    }
    if (control == 0) {
        printf("No text section found in input binary, either the binary was stripped or it is not an executable, exiting ...\n");
        free(sh_names);
        exit(1);
    }
    free(sh_names);
}

void read_store_elf_header(t_woodyData *data) {
    ssize_t bytes_read = read(data->fd, &data->elf_hdr, sizeof(Elf64_Ehdr));
    if (bytes_read == -1 || bytes_read != sizeof(Elf64_Ehdr)) {
        perror("couldnt read elf header correctly\n");
        exit(1);
    }
    if (!is_valid_elf64_executable(&data->elf_hdr)) {
        printf("parsing error for elf header");
        exit(1);
    }
}

Elf64_Phdr read_parse_phdrs_store_ptnote(t_woodyData *data) {
    ssize_t bytes_read = 0;
    for (int i = 0; i < data->elf_hdr.e_phnum; i++) {
        Elf64_Phdr current;
        int offset = data->elf_hdr.e_phoff + i * data->elf_hdr.e_phentsize;
        lseek(data->fd, offset, SEEK_SET);
        ft_memset(&current, 0, sizeof(Elf64_Phdr));
        bytes_read = read(data->fd, &current, data->elf_hdr.e_phentsize);
        if (bytes_read != data->elf_hdr.e_phentsize) {
            printf("Couldnt read program headers correctly\n");
            exit(1);
        }
        if (current.p_type == PT_NOTE) {
            data->offset_ptnote = offset; 
            return current;
        }
    }
    printf("Fatal, didnt find any PT_Note program header,  exiting ...\n");
    exit(1);
}

t_woodyData read_store_headers(const char *filename) {
    t_woodyData data;

    ft_memset(&data, 0, sizeof(t_woodyData));
    data.fd = open(filename, O_RDONLY);
    if (data.fd < 3) {
        printf("Couldnt open filename %s\n", filename);
        exit(1);
    }
    read_store_elf_header(&data);
    read_parse_phdrs_store_ptnote(&data);
    read_parse_sheaders(&data);
    return data;
}

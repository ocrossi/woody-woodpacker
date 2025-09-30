#include "../includes/woody.h"

int is_valid_elf64(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 0;
    }

    Elf64_Ehdr elf_header;
    ssize_t bytes_read = read(fd, &elf_header, sizeof(Elf64_Ehdr));
    close(fd);

    if (bytes_read != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Not a valid ELF file (too small).\n");
        return 0;
    }

    // Check ELF magic
    if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file (bad magic).\n");
        return 0;
    }

    // Check class (64-bit)
    if (elf_header.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a 64-bit ELF file.\n");
        return 0;
    }

    // Check data encoding (little/big endian)
    if (elf_header.e_ident[EI_DATA] != ELFDATA2LSB &&
        elf_header.e_ident[EI_DATA] != ELFDATA2MSB) {
        fprintf(stderr, "Unknown data encoding.\n");
        return 0;
    }

    // Check ELF version
    if (elf_header.e_ident[EI_VERSION] != EV_CURRENT) {
        fprintf(stderr, "Unknown ELF version.\n");
        return 0;
    }

    // Check OS/ABI
    if (elf_header.e_ident[EI_OSABI] != ELFOSABI_SYSV &&
        elf_header.e_ident[EI_OSABI] != ELFOSABI_LINUX) {
        fprintf(stderr, "Unknown OS/ABI.\n");
        return 0;
    }

    // Check ELF type (ET_EXEC or ET_DYN)
    if (elf_header.e_type != ET_EXEC && elf_header.e_type != ET_DYN) {
        fprintf(stderr, "Not an executable or shared object.\n");
        return 0;
    }

    return 1;
}

int main(int ac, char **av)
{
    if (ac != 2) {
        printf("Usage: ./woody_woodpacker FILE");
        return 1;
    }
    // parse elf file: only header ?
    if (!is_valid_elf64(av[1])) {
        printf("Please input a valid ELF file\n");
        return -1;
    }
    printf("%s is a valid ELF file", av[1]);

    // change sections data 
    // add a woody display
    return 0;
}

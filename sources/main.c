#include "../includes/woody.h"

int is_valid_elf64_executable(const Elf64_Ehdr *header) {
    if (header == NULL) {
        fprintf(stderr, "Error: NULL header pointer\n");
        return 0;
    }

    // Check ELF magic number (0x7f, 'E', 'L', 'F')
    if (header->e_ident[EI_MAG0] != ELFMAG0 ||
        header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 ||
        header->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Error: Invalid ELF magic number\n");
        return 0;
    }

    // Check if it's 64-bit
    if (header->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Error: Not a 64-bit ELF file (class: %d)\n", 
                header->e_ident[EI_CLASS]);
        return 0;
    }

    // Check data encoding (little endian only, most common)
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "Error: Invalid data encoding: %d\n", 
                header->e_ident[EI_DATA]);
        return 0;
    }

    // Check ELF version
    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        fprintf(stderr, "Error: Invalid ELF version in e_ident: %d\n", 
                header->e_ident[EI_VERSION]);
        return 0;
    }

    // Check if it's an executable file (ET_EXEC or ET_DYN for PIE executables)
    if (header->e_type != ET_EXEC && header->e_type != ET_DYN) {
        fprintf(stderr, "Error: Not an executable file (type: %d)\n", 
                header->e_type);
        return 0;
    }

    // Validate version field
    if (header->e_version != EV_CURRENT) {
        fprintf(stderr, "Error: Invalid e_version: %d\n", header->e_version);
        return 0;
    }

    // Validate ELF header size
    if (header->e_ehsize != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error: Invalid ELF header size: %d (expected: %lu)\n", 
                header->e_ehsize, sizeof(Elf64_Ehdr));
        return 0;
    }

    printf("Valid 64-bit ELF executable:\n");
    printf("  Class: 64-bit\n");
    printf("  Data: %s\n", 
           header->e_ident[EI_DATA] == ELFDATA2LSB ? "Little Endian" : "Big Endian");
    printf("  Type: %s\n", 
           header->e_type == ET_EXEC ? "Executable" : "Shared Object (PIE)");
    printf("  Entry point: 0x%lx\n", header->e_entry);

    return 1;
}

void read_parse_elf_header(const char *filename, t_woodyData *data) {
    data->fd = open(filename, O_RDONLY);
    if (data->fd < 3) {
        printf("Couldnt open filename %s\n", filename);
        exit(1);
    }
    ssize_t bytes_read = read(data->fd, &data->elf_hdr, sizeof(Elf64_Ehdr));
    if (bytes_read == -1 || bytes_read != sizeof(Elf64_Ehdr)) {
        printf("couldnt read %s correctly\n", filename);
        exit(1);
    }
    if (!is_valid_elf64_executable(&data->elf_hdr)) {
        dprintf(1, "could not parse the elf header correctly, make sure its valid\n");
        exit(1);
    }
}

int is_valid_elf64_program_header(const Elf64_Phdr *phdr, int index) {

    // Validate alignment
    // If p_align is not 0 or 1, it must be a power of 2
    if (phdr->p_align != 0 && phdr->p_align != 1) {
        // Check if power of 2
        if ((phdr->p_align & (phdr->p_align - 1)) != 0) {
            fprintf(stderr, "Error: Program header %d has invalid alignment: 0x%lx\n",
                    index, phdr->p_align);
            return 0;
        }

        // For loadable segments, p_vaddr and p_offset must be congruent modulo alignment
        if (phdr->p_type == PT_LOAD && phdr->p_align > 1) {
            if ((phdr->p_vaddr % phdr->p_align) != (phdr->p_offset % phdr->p_align)) {
                fprintf(stderr, "Error: Program header %d has misaligned vaddr/offset\n", index);
                fprintf(stderr, "  vaddr: 0x%lx, offset: 0x%lx, align: 0x%lx\n",
                        phdr->p_vaddr, phdr->p_offset, phdr->p_align);
                return 0;
            }
        }
    }

    // Memory size must be >= file size
    if (phdr->p_memsz < phdr->p_filesz) {
        fprintf(stderr, "Error: Program header %d has memsz (0x%lx) < filesz (0x%lx)\n",
                index, phdr->p_memsz, phdr->p_filesz);
        return 0;
    }

    // Validate flags (must not have reserved bits set)
    if (phdr->p_flags & ~(PF_R | PF_W | PF_X | 0x0ff00000)) {
        fprintf(stderr, "Warning: Program header %d has unknown flags: 0x%x\n",
                index, phdr->p_flags);
    }

    // Type-specific validations
    switch (phdr->p_type) {
        case PT_NULL:
            // NULL entries should be ignored, always valid
            break;

        case PT_LOAD:
            // LOAD segments should have at least one permission
            if ((phdr->p_flags & (PF_R | PF_W | PF_X)) == 0) {
                fprintf(stderr, "Warning: LOAD segment %d has no permissions\n", index);
            }
            break;

        case PT_INTERP:
            // INTERP segment should have a non-zero file size
            if (phdr->p_filesz == 0) {
                fprintf(stderr, "Error: INTERP segment %d has zero file size\n", index);
                return 0;
            }
            break;

        case PT_PHDR:
            // PHDR segment should be readable
            if (!(phdr->p_flags & PF_R)) {
                fprintf(stderr, "Warning: PHDR segment %d is not readable\n", index);
            }
            break;
    }

    return 1;
}

Elf64_Phdr read_parse_program_headers(t_woodyData *data) {
    ssize_t bytes_read = 0;
    for (int i = 0; i < data->elf_hdr.e_phnum; i++) {
        Elf64_Phdr current;
        int offset = data->elf_hdr.e_phoff + i * data->elf_hdr.e_phentsize;
        lseek(data->fd, offset, SEEK_SET);
        memset(&current, 0, sizeof(Elf64_Phdr));
        bytes_read = read(data->fd, &current, data->elf_hdr.e_phentsize);
        if (bytes_read != data->elf_hdr.e_phentsize) {
            printf("Couldnt read program headers correctly\n");
            exit(1);
        }
        if (!is_valid_elf64_program_header(&current, i)) {
            printf("Couldnt parse program header correctly at index %d\n", i);
            exit(1);
        }
        
    }
    printf("Fatal, didnt find any PT_Note program header");
    exit(1);
}

int is_valid_elf64_section_header(const Elf64_Shdr *shdr) {
    if (shdr == NULL) {
        return 0;
    }

    // Validate alignment - must be 0, 1, or power of 2
    if (shdr->sh_addralign != 0 && shdr->sh_addralign != 1) {
        if ((shdr->sh_addralign & (shdr->sh_addralign - 1)) != 0) {
            return 0;  // Not a power of 2
        }
    }

    // If allocated and aligned, address must be aligned
    if ((shdr->sh_flags & SHF_ALLOC) && shdr->sh_addralign > 1) {
        if ((shdr->sh_addr % shdr->sh_addralign) != 0) {
            return 0;  // Address not aligned
        }
    }

    // Type-specific validations
    switch (shdr->sh_type) {
        case SHT_SYMTAB:
        case SHT_DYNSYM:
        case SHT_DYNAMIC:
        case SHT_REL:
        case SHT_RELA:
            // These types must have non-zero entry size
            if (shdr->sh_entsize == 0) {
                return 0;
            }
            break;
    }

    // If section has entries, size should be multiple of entry size
    if (shdr->sh_entsize > 0 && shdr->sh_size > 0) {
        if (shdr->sh_size % shdr->sh_entsize != 0) {
            return 0;
        }
    }

    return 1;
}

void read_parse_section_headers(t_woodyData *data) {
    ssize_t bytes_read = 0;
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    for (int i = 0; i < data->elf_hdr.e_shnum; i++) {
        Elf64_Shdr current;
        int offset = data->elf_hdr.e_shoff + i * data->elf_hdr.e_shentsize;
        lseek(data->fd, offset, SEEK_SET);
        memset(&current, 0, sizeof(Elf64_Shdr));
        bytes_read = read(data->fd, &current, data->elf_hdr.e_shentsize);
        if (bytes_read != data->elf_hdr.e_shentsize) {
            printf("Couldnt read section headers correctly\n");
            exit(1);
        }
        if (!is_valid_elf64_section_header(&current)) {
            printf("Couldnt parse program header correctly at index %d\n", i);
            exit(1);
        }
    }
    printf("Fatal, didnt find any PT_Note program header");
    exit(1);
}

t_woodyData read_parse_headers(const char *filename) {
    t_woodyData data;

    memset(&data, 0, sizeof(t_woodyData));
    read_parse_elf_header(filename, &data);
    read_parse_program_headers(&data);
    read_parse_section_headers(&data);

    return data;
}

void infect_output_data(const char *filename, t_woodyData *data) {
    // create pt_load 
}

int main(int argc, char *argv[])
{
    t_woodyData data;
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    data = read_parse_headers(argv[1]); 
    infect_output_data(argv[1], &data);

    //  objdump -d decrypt.o -M intel -> gets instructions with bytes
    // write_output_file(&data);

    return EXIT_SUCCESS;
}

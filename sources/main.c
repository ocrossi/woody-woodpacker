#include "../includes/woody.h"

char shellcode_exit[] = {
    0x31, 0xc0, 0x99, 0xb2, 0x0a, 0xff, 0xc0, 0x89,
    0xc7, 0x48, 0x8d, 0x35, 0x12, 0x00, 0x00, 0x00,
    0x0f, 0x05, 0xb2, 0x2a, 0x31, 0xc0, 0xff, 0xc0,
    0xf6, 0xe2, 0x89, 0xc7, 0x31, 0xc0, 0xb0, 0x3c,
    0x0f, 0x05, 0x2e, 0x2e, 0x57, 0x4f, 0x4f, 0x44,
    0x59, 0x2e, 0x2e, 0x0a
};

/* 
 * lit le fichier d inputs  
 * stocke la taille du fichier dans data->file_size
 * stocke le fichier en bytes dans data->file_bytes 
 * */
void read_file(const char *filename, t_woodyData *data) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(1);
    }
    off_t size = lseek(fd, 0, SEEK_END);
    data->file_size = size;
    if (size == -1) {
        perror("Failed to seek file");
        close(fd);
        exit(1);
    }
    lseek(fd, 0, SEEK_SET); // Rewind to start

    data->file_bytes = malloc(size + 1);

    ssize_t bytes_read = read(fd, data->file_bytes, size);
    if (bytes_read != size) {
        fprintf(stderr, "Didnt read enough bytes");
        exit(1);
    }
    printf("data->filesize = %ld\n", data->file_size);
}

/* 
 * copie le header elf de file_bytes vers une struct Elf_header
 * alloue un tableau de program headers 
 * copie les program headers de file_bytes vers la zone allouee
 * */
void store_headers(t_woodyData *data) {
    ft_memcpy(&data->elf_hdr, data->file_bytes, sizeof(Elf64_Ehdr));
    data->prgm_hdrs = malloc(data->elf_hdr.e_phentsize * data->elf_hdr.e_phnum); 
    ft_memcpy(data->prgm_hdrs, data->file_bytes + data->elf_hdr.e_phoff, data->elf_hdr.e_phentsize * data->elf_hdr.e_phnum);
}

void parse_elf64(t_woodyData *data) {
    // Check ELF magic
    if (ft_memcmp(data->elf_hdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file (bad magic).\n");
        exit(1);
    }

    // Check class (64|32-bit)
    if (data->elf_hdr.e_ident[EI_CLASS] != ELFCLASS64 
            && data->elf_hdr.e_ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "Not a 64-bit or 32-bit ELF file.\n");
        exit(1);
    }

    // Check data encoding (little/big endian)
    if (data->elf_hdr.e_ident[EI_DATA] != ELFDATA2LSB &&
            data->elf_hdr.e_ident[EI_DATA] != ELFDATA2MSB) {
        fprintf(stderr, "Unknown data encoding.\n");
        exit(1);
    }

    // Check ELF version
    if (data->elf_hdr.e_ident[EI_VERSION] != EV_CURRENT) {
        fprintf(stderr, "Unknown ELF version.\n");
        exit(1);
    }

    // Check OS/ABI
    if (data->elf_hdr.e_ident[EI_OSABI] != ELFOSABI_SYSV &&
            data->elf_hdr.e_ident[EI_OSABI] != ELFOSABI_LINUX) {
        fprintf(stderr, "Unknown OS/ABI.\n");
        exit(1);
    }

    // Check ELF type (ET_EXEC or ET_DYN)
    if (data->elf_hdr.e_type != ET_EXEC && data->elf_hdr.e_type != ET_DYN
            /* ptet a enlever, c est pour les .o */ && data->elf_hdr.e_type != ET_REL) {
        fprintf(stderr, "Not an executable or shared object.\n");
        exit(1);
    }

    printf("arg given is a valid ELF file\n");
}

void find_ptnote_section(t_woodyData *data) {
    printf("Program Header related vars in elf header :\n");
    printf("e_phoff :  %#016lx\n", data->elf_hdr.e_phoff);
    printf("e_phentsize: %d\n", data->elf_hdr.e_phentsize);
    printf("e_phnum: %d\n", data->elf_hdr.e_phnum);

    Elf64_Phdr phdr;
    
    for (int i = 0; i < data->elf_hdr.e_phnum; i++) {
        ft_memset(&phdr, 0, data->elf_hdr.e_phentsize);
        size_t offset = data->elf_hdr.e_phoff + (i * data->elf_hdr.e_phentsize);
        ft_memcpy(&phdr, &(data->file_bytes[offset]), data->elf_hdr.e_phentsize); 
        if (phdr.p_type == 4) {
            if (data->offset_ptnote == 0) {
                print_program_header(phdr);
                data->offset_ptnote = offset;
                ft_memcpy(&data->pt_note ,&phdr, data->elf_hdr.e_phentsize);
                printf("store ptnote offset data %ld\n", data->offset_ptnote);
                printf("Ya du pnote  a l index %d:\n", i);
                return;
            }
        }
    }
    printf("No pt_note program header found, exiting...\n");
    exit(1);
}

void modify_pt_note_section(t_woodyData *data) {
    data->pt_note.p_type = 1; // pt_note to pt_load
    data->pt_note.p_flags = PF_R | PF_X; // add read exec on segment 
    // data->pt_note.p_vaddr = 0xc000000 + data->file_size; est ce qu on peut juste mettre a une valeur fixe?
    data->pt_note.p_vaddr = 0xc000000 + data->file_size;
    
    // accomodate some room for payload code
    // printf("before changing segment size pt_note filesz %ld\n", data->pt_note.p_filesz);
    // printf("before changing segment size pt_note memsz %ld\n", data->pt_note.p_memsz);
    // data->pt_note.p_filesz += data->length_ptload; 
    // data->pt_note.p_memsz += data->length_ptload;
    data->pt_note.p_filesz += data->length_shellcode; 
    data->pt_note.p_memsz += data->length_shellcode;
    // point to EOF where we ll put the code
    // c est ici? on est pas cense le copier au meme endroit?
    data->pt_note.p_offset = data->file_size;
}

void prepare_output_file(t_woodyData *data) {
    data->output_bytes = malloc(data->file_size + data->length_ptload + 1);
    ft_memcpy(data->output_bytes, data->file_bytes, data->file_size);
    ft_memcpy(&data->output_bytes[data->offset_ptnote], &data->pt_note, data->elf_hdr.e_phentsize);
}

void change_entrypoint(t_woodyData *data) {
    char new_entrypoint[4] = {0x00, 0x00, 0x00, 0x0c}; // care endianness
    ft_memcpy(&data->output_bytes[0x18], new_entrypoint, 4);
}

void write_file(t_woodyData *data) {
    int fd = open("output_woody", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0777);
    if (fd == -1) {
        perror("Failed to open file");
        exit(1);
    }
    
    // write file
    ssize_t bytes_written = write(fd, data->output_bytes, data->file_size);
    if (bytes_written == -1 || (size_t)bytes_written != data->file_size) {
        printf("1st write for file data");
        printf("bytes written %ld", bytes_written);
        printf("size needed %ld", data->file_size);
        perror("Failed to write all bytes");
        close(fd);
        exit(1);
    }
    // write payload
    bytes_written = write(fd, &shellcode_exit, data->length_shellcode);
    if (bytes_written == -1 || (size_t)bytes_written != data->length_shellcode) {
        printf("2nd write for shellcode");
        printf("bytes written %ld", bytes_written);
        printf("size needed %ld", data->file_size);
        perror("Failed to write all bytes");
        close(fd);
        exit(1);
    }
    close(fd);
}

int main(int ac, char **av)
{
    t_woodyData data;
    ft_memset(&data, 0, sizeof(t_woodyData)); 

    // defines?
    data.length_ptload = 256;
    data.length_shellcode = 48;
    printf("data.length_shellcode = %ld\n", data.length_shellcode);
    if (ac != 2) {
        printf("Usage: ./woody_woodpacker FILE");
        return 1;
    }
    read_file(av[1], &data);
    store_headers(&data);
    parse_elf64(&data);
    // check validity section & segment headers 
    find_ptnote_section(&data);
    modify_pt_note_section(&data);
    prepare_output_file(&data);
    change_entrypoint(&data);
    write_file(&data);
    // test output
    // compare_elf_header_with_sytem(&data);
    // compare_prgm_headers_with_system();
    return 0;
}

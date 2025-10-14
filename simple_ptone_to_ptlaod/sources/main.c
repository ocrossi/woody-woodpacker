#include "../includes/includes.h"
#include <elf.h>

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
    // const char *command_start = "readelf -h ";
    // size_t len = strlen(command_start) + strlen(filename) + 1;
    // printf("len to allocate %ld\n", len);
    // printf("filename %s\n", filename);
    // char *command = malloc(len);
    // memset(command, 0, len);
    // strncat(command, command_start, strlen(command_start));
    // strncat(command, filename, strlen(filename));
    //
    // dprintf(1, "command to run %s\n", command);
    // system(command);
}

t_woodyData read_store_headers(const char *filename) {
    t_woodyData data;

    memset(&data, 0, sizeof(t_woodyData));
    read_store_elf_header(filename, &data);
    // read_program_header 
    // read_section_header
    return data;
}

void infect_file(const char *filename) {
    t_woodyData data = read_store_headers(filename);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    // no parsing its just for tests, we assume its a valid elf bin
    infect_file(argv[1]);

    return EXIT_SUCCESS;
}

#include "../includes/woody.h"

void print_hex(const char* buffer, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", (unsigned char)buffer[i]);
        if ((i + 1) % 8 == 0) {
            printf(" || ");
            if ((i + 1) % 16) {
                printf("\n");
            }
        }
    }
    printf("\n");
}

void print_program_header(Elf64_Phdr phdr) {
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

void compare_elf_header_with_sytem(t_woodyData *data) {
     printf("Prgm entry address in hex: %p\n", (void *)data->elf_hdr.e_entry);
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("before \n");
    system("readelf -h ./woody_woodpacker ");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("after \n");
    system("readelf -h ./output_woody ");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("Stored e_entry = %p\n", (void *)data->elf_hdr.e_entry);
}

void compare_prgm_headers_with_system() {
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("before \n");
    system("readelf -l ./woody_woodpacker ");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
    printf("after \n");
    system("readelf -l ./output_woody ");
    printf("\n++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

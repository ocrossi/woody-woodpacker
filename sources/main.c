#include "../includes/woody.h"

unsigned char code[] = {
    // Save all callee-saved registers
    0x50,                               // push rax
    0x51,                               // push rcx
    0x52,                               // push rdx
    0x53,                               // push rbx
    0x56,                               // push rsi
    0x57,                               // push rdi
    0x55,                               // push rbp
    0x41, 0x50,                         // push r8
    0x41, 0x51,                         // push r9
    0x41, 0x52,                         // push r10
    0x41, 0x53,                         // push r11
    // write(1, message, message_len)
    0xb8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1 (sys_write)
    0xbf, 0x01, 0x00, 0x00, 0x00,       // mov edi, 1 (stdout)
    0x48, 0x8d, 0x35, 0x39, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x39]  (message)
    0xba, 0x1a, 0x00, 0x00, 0x00,       // mov edx, 26 (message length)
    0x0f, 0x05,                         // syscall
    // Restore all registers
    0x41, 0x5b,                         // pop r11
    0x41, 0x5a,                         // pop r10
    0x41, 0x59,                         // pop r9
    0x41, 0x58,                         // pop r8
    0x5d,                               // pop rbp
    0x5f,                               // pop rdi
    0x5e,                               // pop rsi
    0x5b,                               // pop rbx
    0x5a,                               // pop rdx
    0x59,                               // pop rcx
    0x58,                               // pop rax
    // For PIE: Calculate base address and add original entry offset
    // Get current RIP into rax
    0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00,  // lea rax, [rip]  (current address)
    // Load injection_vaddr into rbx (will be patched)
    0x48, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rbx, injection_vaddr (10 bytes)
    // Calculate base: base = current_rip - injection_vaddr
    0x48, 0x29, 0xd8,                   // sub rax, rbx
    // Load original entry offset into rbx (will be patched)
    0x48, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rbx, original_entry (10 bytes)
    // Calculate actual entry: actual_entry = base + original_entry
    0x48, 0x01, 0xd8,                   // add rax, rbx
    // Jump to the calculated address
    0xff, 0xe0,                         // jmp rax
    // Message: "hello world from pt_load\n"
    'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', ' ',
    'f', 'r', 'o', 'm', ' ', 'p', 't', '_', 'l', 'o', 'a', 'd', '\n', 0x00
};



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

    // Patch shellcode with injection address and original entry point
    unsigned char patched_code[sizeof(code)];
    memcpy(patched_code, code, sizeof(code));
    
    // Patch injection_vaddr at offset 63 (after the movabs rbx instruction opcode)
    // We add 61 because that's where RIP will be when lea rax,[rip] executes
    uint64_t injection_vaddr = data->pt_load.p_vaddr + 61;
    memcpy(&patched_code[63], &injection_vaddr, sizeof(uint64_t));
    
    // Patch original_entry at offset 76 (after the second movabs rbx instruction opcode)
    uint64_t original_entry = data->elf_hdr.e_entry;
    memcpy(&patched_code[76], &original_entry, sizeof(uint64_t));

    memcpy(&output[0x18], &data->new_entrypoint, sizeof(void *));
    memcpy(&output[data->offset_ptnote], &data->pt_load, sizeof(Elf64_Phdr));
    memcpy(&output[data->file_size], patched_code, data->payload_size);

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

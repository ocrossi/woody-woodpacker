#include "../includes/woody.h"
#include <elf.h>

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
    0xba, 0xf, 0x00, 0x00, 0x00,       // mov edx, 15 (message length)
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
    '.','.','.','.','W', 'O', 'O', 'D', 'Y','.','.','.','.', '\n', 0x00
};

void read_parse_sheaders(t_woodyData *data) {
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
            printf("pt_note found\n");
            return current;
        }
    }
    printf("Fatal, didnt find any PT_Note program header");
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

void change_pt_note(t_woodyData *data) {
    ft_memcpy(&data->pt_load, &data->pt_note, sizeof(Elf64_Phdr));

    data->injection_addr = 0xc000000 +  data->file_size;
    data->pt_load.p_type = PT_LOAD; // pt_note to pt_load en changeant type
    data->pt_load.p_flags = PF_X | PF_W | PF_R; // pt_note to pt_load en changeant type
    data->pt_load.p_offset = data->file_size;
    data->pt_load.p_vaddr = data->injection_addr;
    data->pt_load.p_filesz = data->payload_size; 
    data->pt_load.p_memsz = data->payload_size;
    data->new_entrypoint = (void*)data->injection_addr;
}

void write_shellcode(t_woodyData *data, char *output) {
    unsigned char *shellcode_with_ret = malloc(sizeof(data->payload_size));

    if (shellcode_with_ret == NULL) {
        perror("Malloc failed for shellcode allocation");
        free(shellcode_with_ret);
        exit(1);
    }
    
    uint64_t offset_placeholder = data->injection_addr + 61; //pos 1er placeholder
    
    ft_memcpy(shellcode_with_ret, code, data->payload_size);
    ft_memcpy(shellcode_with_ret + 63, &offset_placeholder, sizeof(uint64_t));
    ft_memcpy(shellcode_with_ret + 76, &data->elf_hdr.e_entry, sizeof(uint64_t));
    ft_memcpy(&output[data->file_size], shellcode_with_ret, data->payload_size);
}

void write_output_data(t_woodyData *data) {
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    data->fd_out = open("woody", O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (data->fd_out < 3) {
        perror("could not open file\n");
        exit(1);
    }
    data->size_out = data->file_size + data->payload_size + KEY_SIZE + 1;
    char *output = malloc(data->size_out);
    if (output == NULL) {
        perror("output malloc failed\n");
        exit(1);
    }
    ft_memset(output, 0, data->size_out);
    dprintf(1, "malloced\n");
    ssize_t bytes_read = read(data->fd, output, data->file_size);
    if (bytes_read != (ssize_t)data->file_size) {
        perror("read issue\n");
        exit(1);
    }
    dprintf(1, "red %ld \n", bytes_read);

    ft_memcpy(&output[0x18], &data->new_entrypoint, sizeof(void *));
    ft_memcpy(&output[data->offset_ptnote], &data->pt_load, sizeof(Elf64_Phdr));

    write_shellcode(data, output);
    data->output_bytes = output;
}

void infect_output_data(const char *filename, t_woodyData *data) {
    *data = read_store_headers(filename); 
    data->file_size = lseek(data->fd, 0, SEEK_END); // on recup la taille du fichier
    data->payload_size = sizeof(code);
    printf("data->payload size = %d\n", data->payload_size);
    change_pt_note(data);
    write_output_data(data);
}

void store_ascii_key(t_woodyData *data) {
    for (int i = 0; i < KEY_SIZE; i++) {
        char c = data->key[i] % 60;
        c = c < 0 ? c * -1 : c;
        if (c < 10)
            c += 48;
        else if (c < 36)
            c = c - 10 + 65;
        else 
            c = c - 35 + 97;
        data->key[i] = c;
    }
}

void generate_store_key(t_woodyData *data) {
    syscall_random(data->key, KEY_SIZE);
    store_ascii_key(data);
    printf("readable key is %s\n", data->key);
    ft_memcpy(&data->output_bytes[data->file_size + data->payload_size], data->key, KEY_SIZE + 1);
    printf("pos where key is written %lx\n", (data->file_size + data->payload_size));
    // encrpyt section text 
}

void write_output_file(t_woodyData *data) {
    write(data->fd_out, data->output_bytes, data->size_out);
    dprintf(1, "written\n");
}

int main(int argc, char *argv[])
{
    t_woodyData data;
    ft_memset(&data, 0, sizeof(data));
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    infect_output_data(argv[1], &data);
    generate_store_key(&data);
    // encrypt(&data.output_bytes[data.start_encryption], data.key, data.len_encryption);
    write_output_file(&data);

    return EXIT_SUCCESS;
}

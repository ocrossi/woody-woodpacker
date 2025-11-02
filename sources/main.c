#include "../includes/woody.h"
#include <elf.h>
#include <unistd.h>

unsigned char code[] = {
    // Save all callee-saved registers
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x41, 0x50, 0x41, 0x51, 0x41,
    0x52, 0x41, 0x53,
    // Setup decrypt arguments (will be patched)
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rdi, key_addr (bytes 17-24)
    0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rsi, text_addr (bytes 27-34)
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rdx, text_len (bytes 37-44)
    // Call decrypt inline
    0xe8, 0x4a, 0x00, 0x00, 0x00,       // call decrypt_func
    // write(1, message, message_len)
    0xb8, 0x01, 0x00, 0x00, 0x00,       // mov eax, 1 (sys_write)
    0xbf, 0x01, 0x00, 0x00, 0x00,       // mov edi, 1 (stdout)
    0x48, 0x8d, 0x35, 0x62, 0x00, 0x00, 0x00,  // lea rsi, [rel message]
    0xba, 0x0d, 0x00, 0x00, 0x00,       // mov edx, 13 (message length)
    0x0f, 0x05,                         // syscall
    // Restore all registers
    0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5d, 0x5f,
    0x5e, 0x5b, 0x5a, 0x59, 0x58,
    // Calculate base address and jump to original entry
    0x48, 0x8d, 0x05, 0xa0, 0xff, 0xff, 0xff,  // lea rax, [rel shellcode_start]
    0x48, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rbx, injection_vaddr (bytes 99-106)
    0x48, 0x29, 0xd8,                   // sub rax, rbx
    0x48, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rbx, original_entry (bytes 112-119)
    0x48, 0x01, 0xd8,                   // add rax, rbx
    0xff, 0xe0,                         // jmp rax
    // Inline decrypt function
    0x49, 0x89, 0xfb, 0x8a, 0x0f, 0x8a, 0x06, 0x8a,
    0x1f, 0x48, 0xff, 0xca, 0x48, 0x83, 0xfa, 0x00, 0x74, 0x16, 0x80, 0xfb,
    0x00, 0x74, 0x0c, 0x30, 0xd8, 0x88, 0x06, 0x48, 0xff, 0xc6, 0x48, 0xff,
    0xc7, 0xeb, 0xe2, 0x4c, 0x89, 0xdf, 0xeb, 0xdd, 0xc3,
    // Message
    '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', 0x0a, 0x00
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
    Elf64_Phdr pt_note_found;
    int found_note = 0;
    int found_exec = 0;
    
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
            memcpy(&pt_note_found, &current, sizeof(Elf64_Phdr));
            found_note = 1;
        }
        // Find executable PT_LOAD segment for encryption
        if (current.p_type == PT_LOAD && (current.p_flags & PF_X)) {
            data->text_segment_offset = current.p_offset;
            data->text_segment_size = current.p_filesz;
            data->text_segment_vaddr = current.p_vaddr;
            data->text_segment_phdr_offset = offset;  // Save offset to patch flags later
            printf("Executable PT_LOAD found at offset 0x%lx, size 0x%lx, vaddr 0x%lx\n", 
                   data->text_segment_offset, data->text_segment_size, data->text_segment_vaddr);
            found_exec = 1;
        }
    }
    if (!found_note) {
        printf("Fatal, didnt find any PT_Note program header\n");
        exit(1);
    }
    if (!found_exec) {
        printf("Fatal, didnt find executable PT_LOAD segment\n");
        exit(1);
    }
    return pt_note_found;
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


    data->injection_addr = 0xc000000 +  data->file_size;

    data->pt_load.p_type = PT_LOAD; // pt_note to pt_load en changeant type
    data->pt_load.p_flags = PF_X | PF_W | PF_R; // pt_note to pt_load en changeant type
    data->pt_load.p_offset = data->file_size;
    data->pt_load.p_vaddr = data->injection_addr;
    // data->pt_load.p_paddr = injection_addr;
    data->pt_load.p_filesz = data->payload_size; 
    data->pt_load.p_memsz = data->payload_size;
    // data->pt_load.p_align = 0x1000;
    data->new_entrypoint = (void *)data->pt_load.p_vaddr;
}

void write_shellcode(t_woodyData *data, char *output) {
    unsigned char *shellcode_with_ret = malloc(data->payload_size);

    if (shellcode_with_ret == NULL) {
        perror("Malloc failed for shellcode allocation");
        exit(1);
    }
    
    // Copy the shellcode template
    memcpy(shellcode_with_ret, code, data->payload_size);
    
    // Calculate addresses for decrypt call (use virtual addresses)
    uint64_t key_addr = data->injection_addr + data->payload_size;  // Key is after shellcode (vaddr)
    uint64_t text_vaddr = data->text_segment_vaddr;  // Virtual address of text segment
    uint64_t text_len = data->text_segment_size;
    
    printf("Patching shellcode: key_addr=0x%lx, text_vaddr=0x%lx, text_len=0x%lx\n",
           key_addr, text_vaddr, text_len);
    
    // Patch decrypt arguments at bytes 17, 27, 37
    memcpy(shellcode_with_ret + 17, &key_addr, sizeof(uint64_t));
    memcpy(shellcode_with_ret + 27, &text_vaddr, sizeof(uint64_t));
    memcpy(shellcode_with_ret + 37, &text_len, sizeof(uint64_t));
    
    // Patch injection_vaddr and original_entry at bytes 99 and 112
    memcpy(shellcode_with_ret + 99, &data->injection_addr, sizeof(uint64_t));
    memcpy(shellcode_with_ret + 112, &data->elf_hdr.e_entry, sizeof(uint64_t));
    
    // Write shellcode to output
    memcpy(&output[data->file_size], shellcode_with_ret, data->payload_size);
    
    free(shellcode_with_ret);
}

void write_output_data(t_woodyData *data) {
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    data->fd_out = open("output", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (data->fd_out < 3) {
        perror("could not open file\n");
        exit(1);
    }
    char *output = malloc(data->file_size + data->payload_size + KEY_SIZE + 1);  // +1 for null terminator
    if (output == NULL) {
        perror("output malloc failed\n");
        exit(1);
    }
    memset(output, 0, data->file_size + data->payload_size + KEY_SIZE + 1);
    dprintf(1, "malloced\n");
    ssize_t bytes_read = read(data->fd, output, data->file_size);
    if (bytes_read != (ssize_t)data->file_size) {
        perror("read issue\n");
        exit(1);
    }
    dprintf(1, "red %ld \n", bytes_read);

    memcpy(&output[0x18], &data->new_entrypoint, sizeof(void *));
    memcpy(&output[data->offset_ptnote], &data->pt_load, sizeof(Elf64_Phdr));
    
    // Make text segment writable for decryption
    Elf64_Phdr text_phdr;
    memcpy(&text_phdr, &output[data->text_segment_phdr_offset], sizeof(Elf64_Phdr));
    text_phdr.p_flags |= PF_W;  // Add write permission
    memcpy(&output[data->text_segment_phdr_offset], &text_phdr, sizeof(Elf64_Phdr));
    printf("Made text segment writable (flags: 0x%x)\n", text_phdr.p_flags);

    write_shellcode(data, output);
   
    data->output_bytes = output;
    // write(fd_out, output, data->file_size + data->payload_size);
    // dprintf(1, "written\n");
    // return output;
}

void infect_output_data(const char *filename, t_woodyData *data) {
    *data = read_store_headers(filename); 
    data->file_size = lseek(data->fd, 0, SEEK_END); // on recup la taille du fichier
    data->payload_size = sizeof(code);
    printf("data->payload size = %d\n", data->payload_size);
    change_pt_note(data);
    write_output_data(data);
}

void print_ascii_key(const char *str) {
    for (int i = 0; i < KEY_SIZE; i++) {
        char c = str[i] % 60;
        c = c < 0 ? c * -1 : c;
        char save = c;
        if (c < 10)
            c += 48;
        else if (c < 36)
            c = c - 10 + 65;
        else 
            c = c - 36 + 97;
        if (c == '`') {
            printf("wtf> %d\n", (int)save);
        }
       printf("%c", c);
    }
}

void generate_store_key(t_woodyData *data) {
    syscall_random(data->key, KEY_SIZE);
    print_ascii_key(data->key);
    memcpy(&data->output_bytes[data->file_size + data->payload_size], data->key, KEY_SIZE);
    // encrpyt section text 
}

int main(int argc, char *argv[])
{
    t_woodyData data;
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    infect_output_data(argv[1], &data);
    generate_store_key(&data);
   
    // Encrypt the executable PT_LOAD segment
    encrypt(data.key, &data.output_bytes[data.text_segment_offset], data.text_segment_size);
    printf("Encrypted segment at offset 0x%lx, size 0x%lx\n", 
           data.text_segment_offset, data.text_segment_size);
    
    // Write output file (include null terminator after key)
    write(data.fd_out, data.output_bytes, data.file_size + data.payload_size + KEY_SIZE + 1);
    dprintf(1, "written to output\n");
    
    // Make output executable
    fchmod(data.fd_out, 0755);
    
    close(data.fd);
    close(data.fd_out);

    return EXIT_SUCCESS;
}

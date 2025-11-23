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
    0x90,                               // nop slide 16th byte pour alignment  
    // here decrypt
    // instr 1
    // instr 2
    // instr 3
    // loop text len 27
    0x8a, 0x06,                         // mov    al,BYTE PTR [rsi]
    0x8a, 0x1f,                         // mov    bl,BYTE PTR [rdi]
    0x48, 0xff, 0xca,                   // dec    rdx
    0x48, 0x83, 0xfa, 0x00,             // cmp    rdx,0x0
    0x74, 0x14,                         // je     26 <exit> !!
    0x80, 0xfb, 0x00,                   // cmp    bl,0x0
    0x74, 0x0a,                         // jump relative to reset key 
    0x30, 0xd8,                         // xor    al,bl
    0x88, 0x06,                         // mov    BYTE PTR [rsi],al
    0x48, 0xff, 0xc6,                   // inc    rsi
    0x48, 0xff, 0xc7,                   // inc    rdi
    // reset key len 5
    0x4c, 0x89, 0xdf,                   // mov    rdi,r11
    0xeb, 0xdf,                         // jmp    <loop_text> !!  
    
    // jmp apres placeholder 
    0xeb, 0x11,

    0x0, 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0, // placeholder key
    0x0,0x0,0x0,0x0, // placeholder .text offset 
    0x0,0x0,0x0,0x0, // placeholder .text size
    
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
    printf("new endrtypoint %p\n", data->new_entrypoint);
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
    ft_memcpy(shellcode_with_ret + 63, &offset_placeholder, sizeof(uint64_t)); // change offset 
    ft_memcpy(shellcode_with_ret + 76, &data->elf_hdr.e_entry, sizeof(uint64_t)); // change offset
    ft_memcpy(&output[data->file_size], shellcode_with_ret, data->payload_size);
}

void write_output_data(t_woodyData *data) {
    lseek(data->fd, 0, SEEK_SET); // on repart au debut du fichier
    data->fd_out = open("woody", O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (data->fd_out < 3) {
        perror("could not open file\n");
        exit(1);
    }
    data->size_out = data->file_size + data->payload_size + KEY_SIZE + 1 + 8; // 8 bytes for text section len & offset
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

void infect_output_data(t_woodyData *data) {
    data->file_size = lseek(data->fd, 0, SEEK_END); // on recup la taille du fichier
    data->payload_size = sizeof(code);
    printf("data->payload size = %d\n", data->payload_size);
    change_pt_note(data);
    write_output_data(data);
}

void get_ascii_key(t_woodyData *data) {
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

void generate_store_decrypt_data(t_woodyData *data) {
    syscall_random(data->key, KEY_SIZE);
    get_ascii_key(data);
    // printf("readable key is %s\n", data->key);
    // ft_memcpy(&data->output_bytes[data->file_size + data->payload_size], data->key, KEY_SIZE + 1);
    // printf("pos where key is written %lx\n", (data->file_size + data->payload_size));
    // int offset_placeholder = data->file_size + data->payload_size + KEY_SIZE + 1;
    // ft_memcpy(&data->output_bytes[offset_placeholder], &data->text_sec.sh_offset, 4);
    // ft_memcpy(&data->output_bytes[offset_placeholder + 4], &data->text_sec.sh_size, 4);
    printf("readable key is %s\n", data->key);
    ft_memcpy(&data->output_bytes[data->file_size + 16], data->key, KEY_SIZE + 1);
    // printf("pos where key is written %lx\n", (data->file_size + data->payload_size));
    int offset_placeholder = data->file_size + 16 + KEY_SIZE + 1;
    ft_memcpy(&data->output_bytes[offset_placeholder], &data->text_sec.sh_offset, 4);
    ft_memcpy(&data->output_bytes[offset_placeholder + 4], &data->text_sec.sh_size, 4);
}

void write_output_file(t_woodyData *data) {
    printf("fd out %d\n", data->fd_out);
    write(data->fd_out, data->output_bytes, data->size_out);
    dprintf(1, "written\n");
}

int main(int argc, char *argv[])
{
    t_woodyData data;
    ft_memset(&data, 0, sizeof(data));
    if (argc != 2) {
        printf("Wrong number of arguments\n");
        return EXIT_FAILURE;
    }
    data = read_store_headers(argv[1]); 
    infect_output_data(&data);
    generate_store_decrypt_data(&data);
    printf("fd out %d\n", data.fd_out);
    printf("size of text section %lu\n", data.text_sec.sh_size);
    printf("offset  text section %lu\n", data.text_sec.sh_offset);
    printf("offset  text section %lu\n", data.text_sec.sh_offset);
    printf("size of output %d\n", data.size_out);

    encrypt(data.key, &data.output_bytes[data.text_sec.sh_offset] ,data.text_sec.sh_size);
    write_output_file(&data);

    return EXIT_SUCCESS;
    //  objdump -d decrypt.o -M intel -> gets instructions with bytes
}

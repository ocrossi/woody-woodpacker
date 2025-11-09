#include "../includes/woody.h"
#include <elf.h>


t_woodyData read_parse_headers(const char *filename) {
    t_woodyData data;

    memset(&data, 0, sizeof(t_woodyData));
    read_parse_elf_header(filename, &data);
    read_parse_program_headers(&data);
    read_parse_section_headers(&data);

    data.file_size = lseek(data.fd, 0, SEEK_END);

    return data;
}

void create_pt_load(t_woodyData *data) {
    Elf64_Phdr new_ptload;

    memset(&new_ptload, 0, sizeof(Elf64_Phdr));

    // Find the maximum virtual address from existing PT_LOAD segments
    uint64_t max_vaddr = 0;
    for (int i = 0; i < data->elf_hdr.e_phnum; i++) {
        if (data->prgm_hdrs[i].p_type == PT_LOAD) {
            uint64_t end_addr = data->prgm_hdrs[i].p_vaddr + data->prgm_hdrs[i].p_memsz;
            if (end_addr > max_vaddr) {
                max_vaddr = end_addr;
            }
        }
    }
    
    // Align to page boundary (0x1000)
    max_vaddr = (max_vaddr + 0x1000 - 1) & ~(0x1000 - 1);
    
    // Calculate our virtual address maintaining proper alignment
    uint64_t file_offset = data->file_size + sizeof(Elf64_Phdr);
    uint64_t offset_mod = file_offset % 0x1000;
    data->new_entrypoint = max_vaddr + offset_mod;

    new_ptload.p_type = PT_LOAD;
    new_ptload.p_flags = PF_X | PF_R;
    new_ptload.p_offset = file_offset;
    new_ptload.p_vaddr = data->new_entrypoint;
    new_ptload.p_paddr = data->new_entrypoint;

    // new_ptload.p_memsz = data->payload_size;
    // new_ptload.p_filesz = data->payload_size;
    new_ptload.p_memsz = 1024;
    new_ptload.p_filesz = 1024;
    new_ptload.p_align = 0x1000;

    data->pt_load = new_ptload;

    data->elf_hdr.e_phnum++;
    data->old_entrypoint = data->elf_hdr.e_entry;
    data->elf_hdr.e_entry = data->new_entrypoint;
}

char code_template[] = {
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
    0x48, 0x8d, 0x35, 0x26, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x26]  (message)
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
    // Jump to original entry point
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, <old_entry> (to be filled)
    0xFF, 0xE0,                         // jmp rax
    '.','.','.','.','W', 'O', 'O', 'D', 'Y','.','.','.','.', '\n', 0x00
};

void write_output_file(t_woodyData *data) {
    data->output_size = data->file_size + sizeof(Elf64_Phdr) + data->pt_load.p_filesz;

    data->output_bytes = malloc(data->output_size);
    if (data->output_bytes == NULL) {
        perror("Malloc failed on output data\n");
        exit(1);
    }
    memset(data->output_bytes, 0, data->output_size);

    int original_phnum = data->elf_hdr.e_phnum - 1;
    size_t original_headers_end = data->elf_hdr.e_phoff + sizeof(Elf64_Phdr) * original_phnum;

    // Adjust offsets in program headers that point beyond the program header table
    // since we're inserting a new program header
    size_t shift = sizeof(Elf64_Phdr);
    for (int i = 0; i < original_phnum; i++) {
        if (data->prgm_hdrs[i].p_offset >= original_headers_end) {
            data->prgm_hdrs[i].p_offset += shift;
            // For non-LOAD segments, also adjust vaddr and paddr
            // LOAD segments define the virtual address space mapping, so their vaddr is fixed
            // Other segments' addresses are within LOAD segments and follow their data
            if (data->prgm_hdrs[i].p_type != PT_LOAD) {
                data->prgm_hdrs[i].p_vaddr += shift;
                data->prgm_hdrs[i].p_paddr += shift;
            }
        }
    }

    // Adjust section header offset if it exists and points beyond program headers
    if (data->elf_hdr.e_shoff >= original_headers_end) {
        data->elf_hdr.e_shoff += shift;
    }

    memcpy(data->output_bytes, &data->elf_hdr, sizeof(Elf64_Ehdr));
    size_t write_offset = sizeof(Elf64_Ehdr); 
    memcpy(&data->output_bytes[write_offset], data->prgm_hdrs, data->size_prgm_hdrs);
    write_offset += data->size_prgm_hdrs;
    memcpy(&data->output_bytes[write_offset], &data->pt_load, sizeof(Elf64_Phdr));
    write_offset += sizeof(Elf64_Phdr);
    size_t remaining_size = data->file_size - original_headers_end;
    lseek(data->fd, original_headers_end, SEEK_SET);
    size_t bytes_read = read(data->fd, &data->output_bytes[write_offset], remaining_size);
    if (bytes_read != remaining_size) {
        perror("Couldnt read remaining file data correctly\n");
        exit(1);
    }
    if (data->elf_hdr.e_shoff > 0 && data->elf_hdr.e_shnum > 0) {
        size_t sh_offset_in_output = data->elf_hdr.e_shoff;
        for (int i = 0; i < data->elf_hdr.e_shnum; i++) {
            Elf64_Shdr *shdr = (Elf64_Shdr *)&data->output_bytes[sh_offset_in_output + i * sizeof(Elf64_Shdr)];
            if (shdr->sh_offset >= original_headers_end) {
                shdr->sh_offset += shift;
            }
        }
    }

    // Copy shellcode template to output
    size_t shellcode_offset = data->file_size + sizeof(Elf64_Phdr);
    memcpy(&data->output_bytes[shellcode_offset], code_template, sizeof(code_template));
    
    // Fill in the old entry point address in the shellcode (at offset 61, after register restoration)
    uint64_t old_entry = data->old_entrypoint;
    memcpy(&data->output_bytes[shellcode_offset + 61], &old_entry, sizeof(uint64_t));

    data->fd_out = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (data->fd_out < 3) {
        perror("Couldnt open output file woody, exiting\n");
        exit(1);
    }
    write(data->fd_out, data->output_bytes, data->output_size);
}

void infect_output_data(t_woodyData *data) {
    create_pt_load(data);
    write_output_file(data);
}

int main(int argc, char *argv[])
{
    t_woodyData data;
    if (argc != 2) {
        printf("Wrong number of args\n");
        return EXIT_FAILURE;
    }
    data = read_parse_headers(argv[1]); 
    infect_output_data(&data);

    return EXIT_SUCCESS;
}

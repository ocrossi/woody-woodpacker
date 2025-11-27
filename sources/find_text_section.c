#include "../includes/woody.h"

char* read_shstrtab(t_woodyData *data) {
  Elf64_Shdr sh_strtab;
  ft_memset(&sh_strtab, 0, sizeof(Elf64_Shdr));
  lseek(data->fd, data->elf_hdr.e_shoff + data->elf_hdr.e_shstrndx * data->elf_hdr.e_shentsize, SEEK_SET);
  read(data->fd, &sh_strtab, sizeof(Elf64_Shdr));
  lseek(data->fd, sh_strtab.sh_offset, SEEK_SET);
  char *sh_names = malloc(sh_strtab.sh_size);
  if (sh_names == NULL) {
    perror("Malloc for section header names failed\n");
    exit(1);
  }
  read(data->fd, sh_names, sh_strtab.sh_size);

  return sh_names;
}

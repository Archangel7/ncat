#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <langinfo.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <utmp.h>
#include <fcntl.h>

#define BACKLOG 10
typedef struct
{
	bool listen;
	bool execute;
	bool output;

}FLAGS;
FLAGS flags = {false,false,false};
char * exec_command(char *);
int create_socket_on_serverport(const char *PORT,char *argv[]);

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void sendToSocket(int new_fd, char *buffer )
{
   send(new_fd,buffer,strlen(buffer),0);
}


int main(int argc, char **argv, char **envp)
{

	int flag;
	char *shortopts = "l:c:o:";

	while( (flag = getopt(argc,argv,shortopts)) != -1)
	{
		switch(flag)
		{
			case 'l':
				flags.listen = true; break;
			case 'c':
				flags.execute = true; break;
			case ':':
				printf("%s: option '-%c' requires an argument\n",argv[0], optopt); break;
			case'o': 
				flags.output = true;
			case'?':
			default:
				printf("%s: option '-%c' is invalid: ignored\n",argv[0], optopt); break;
		} // end of switch staement
	} // end of while

	if ( argc < 2 ) printf("no cmd line args\n");

	if(flags.listen)
	{
		printf("listen flag is set\n");
		int ret = create_socket_on_serverport(argv[2], argv);

		if (ret == -1)
			exit(-1);
	}
	if(flags.execute)
	{
	   char *ptr = exec_command(argv[2]);
	   printf("%s\n",ptr);
	}
	return 0;
}

char * exec_command(char *command)
{
	char buffer[1024],buffer2[1024];
	char *ptr = buffer2;
	FILE *file = popen(command,"r");
	
	while((fgets(buffer,sizeof buffer, file))!=NULL)
	{
	   strcat(buffer2,buffer);
	}
	buffer2[strlen(buffer2)-1] ='\0';
	pclose(file);
	return ptr; 
}

int create_socket_on_serverport(const char *PORT, char *argv[])
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;

	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) 
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}
	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
						p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");
	char buf[100] = "Connection Established!";

	while(1) 
	{  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1)
		{
			perror("accept");
			continue;
		}
		if (inet_ntop(their_addr.ss_family,get_in_addr((struct sockaddr *)&their_addr),s, sizeof s) != NULL)
		{
			printf("server: got connection from %s\n", s);
		}
		if(!fork())
		{
			char buffer[1024],buffer2[1024];
			while(1)
			{
				fgets(buffer,sizeof(buffer),stdin);
				send(new_fd,buffer,strlen(buffer),0);
			}

		}
		if (!fork()) 
		{ // this is the child process         

			char buffer[1000],buffer2[1000],buffer3[1024];;
			char againMsg[]="Enter another message\n";
			do {
				size_t nBytes;
				close(sockfd); // child doesn't need the listener
				nBytes=recv(new_fd,buffer,sizeof buffer,0);  //receive a message from the client

				if(nBytes<0) { perror("Problem in receive"); exit(1); }
					buffer[nBytes-1]='\0';  //remove the newline and null terminate
					fprintf(stdout,"I got a message: %s\n",buffer);
				
				if (flags.output)
				{
					FILE *fp;
					fp = fopen(argv[4],"a");
					fprintf(fp,buffer);
					fclose(fp);
				}
				if(flags.execute)
				{     
					char buff[1024];
					char *ptr = exec_command(argv[4]);
					strcpy(buff,ptr);
					send(new_fd,buff,strlen(buff),0);
				}
			   }while(true);
			   //close(newfd);
		}

	}
}

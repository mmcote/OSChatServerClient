#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#define MAXCHARS 256

int clientFD;
struct sockaddr_in servAddr;
struct hostent *server;
char buffer[MAXCHARS];

void initializeServerData(int portNo)
{
	server = gethostbyname("localhost");
	if (server == NULL)
	{
		perror ("Error: unable to get \"localhost\"");
        exit (1);
	}

	// Initialize the sockaddr_in struct
	bzero (&servAddr, sizeof(servAddr));
	// Initialize with host data
	bcopy (server->h_addr, &(servAddr.sin_addr), server->h_length);
	servAddr.sin_family = server->h_addrtype;
	servAddr.sin_port = htons(portNo);
}

// 1. Create a socket with the socket()
void createSocket()
{
    clientFD = socket(AF_INET,SOCK_STREAM,0);
    if (clientFD == -1)
    {
        perror ("Error: unable to create server socket");
        exit (1);
    }
}

// 2. Connect the socket to the address of the server using the connect() system call
void connectSocket()
{
	// Try to connect to the server
	if (connect (clientFD, (struct sockaddr*) &servAddr, sizeof (servAddr))) {
		perror ("Error: cannot connect to server");
		exit (1);
	}
}

void recieve()
{
	bzero(buffer,256);
	int n = read(clientFD,buffer,255);
	if (n < 0)
	{
	    perror("Error: reading from socket");
	}
	printf("%s\n",buffer);
    bzero(buffer,256);
}

void menu(char * writeBuffer)
{
    
}

// 3. Send and receive data, use the read() and write() system calls
void sendMessage()
{
    char writeBuffer[MAXCHARS];
    bzero(writeBuffer, MAXCHARS);

    char type;
    int entryNum;

    // 1. Select Query or Update
    printf("Would you like to make a query (1) or update (2)?\n");
    
    char input[10];
    bzero(input, 10);
    fgets(input, 9, stdin);
    if (input[0] == '1')
    {
        printf("You've selected to make a query.\n");
        type = '?';
    } 
    else if (input[0] == '2')
    {
        printf("You've selected to make an update.\n");
        type = '@';
    }
    // 2. Enter Whiteboard Entry
    printf("Which entry would you like to access?\n");
    while(1)
    {
        bzero(input, 10);
        fgets(input, 9, stdin);
        entryNum = atoi(input);
        if (entryNum == 0)
        {
            printf("Invalid entry: Please enter a valid entry.\n");
        }
        else
        {
            printf("Entry: %s\n", input);
            break;
        }
    }

    if (type != '?')
    {
        // 3. Enter Message if necessary
        printf("Please enter your new whiteboard message.\n");

        char buffer[MAXCHARS];
        bzero(buffer, MAXCHARS);
        fgets(buffer, MAXCHARS - 1, stdin);
        int messageLen = strlen(buffer);
        sprintf(writeBuffer, "%c%dp%d\n%s\n", type, entryNum, messageLen, buffer);
    }
    else
    {
        sprintf(writeBuffer, "%c%d\n", type, entryNum);
    }

	int n = write(clientFD,writeBuffer,strlen(writeBuffer));
	if (n < 0)
	{
	    perror("Error: writing to socket");
	}
	bzero(writeBuffer,256);
    recieve();
}

int main(int argc, char **argv) 
{
    if (argc < 4)
    {
        printf("Usage: %s hostname portnumber [keyfile]", argv[0]);
		exit(-1);
    }

    int portNo = atoi(argv[2]);
    if (portNo == 0)
    {
        printf("Invalid Argument: %s must be a valid port number", argv[1]);
        exit(-1);
    }

	createSocket();
	initializeServerData(portNo);
    connectSocket();

    // This recieve is just to take in the initial welcome message
    recieve();

    // The client is continually requesting from the server
    while(1)
    {
        sendMessage();
    }
}
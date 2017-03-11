#include "server.h"

WhiteBoard * createWhiteBoard(int numMessagesRequested)
{
    WhiteBoard * templateWhiteBoard;
    if((templateWhiteBoard = malloc(sizeof *templateWhiteBoard)) != NULL)
    {
        templateWhiteBoard->numMessages = numMessagesRequested;
        templateWhiteBoard->messages = calloc(numMessagesRequested, sizeof(char*));
        templateWhiteBoard->encrypted = calloc(numMessagesRequested, sizeof(char*));
        templateWhiteBoard->messageLen = calloc(numMessagesRequested, sizeof(int*));

        int i = 0;
        for(; i < numMessagesRequested; ++i)
         {
             templateWhiteBoard->messages[i]=NULL;
             templateWhiteBoard->encrypted[i]=0;
             templateWhiteBoard->messageLen[i]=0;
         }
    }
    return templateWhiteBoard;
}

void disconnectUsers()
{
    while (clientNodeHead != NULL)
    {
        fprintf(logFile, "%d\n", *clientNodeHead->fd);

        // Currently the clients only have one thread where
        // they are sending so they cannot listen all the time
        // hense they will be unaware of being disconnected

        close(*clientNodeHead->fd);
        clientNodeHead = remove_front(clientNodeHead);
    }
}

void sigtermViolationHandler(int signal_num)
{
    disconnectUsers();
    saveWhiteBoard();
    closeConnection();
    fclose(logFile);

    exit(-1);
}

void daemonizeProcess()
{
    pid_t pid = 0;
    pid_t sid = 0;

    pid = fork();

    if (pid < 0)
    {
        printf("fork failed!\n");
        exit(1);
    }

    if (pid > 0)
    {
        // in the parent
        printf("pid of child process %d \n", pid);
        exit(0);
    }

    umask(0);

	// open a log file
    logFile = fopen ("logfile.log", "w+");
    if(!logFile){
    	printf("cannot open log file");
    }

    // open the whiteBoard file
    whiteBoardFile = fopen ("whiteboard.all", "w+");
    if(!whiteBoardFile){
    	printf("cannot open whiteboard.all file");
    }

    // create new process group -- don't want to look like an orphan
    sid = setsid();
    if(sid < 0)
    {
        fprintf(logFile, "cannot create new process group");
        exit(1);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        printf("Could not change working directory to /\n");
        exit(1);
    }

	// close standard fds
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

void saveWhiteBoard()
{
    int numMessages = whiteBoard->numMessages;
    if(!whiteBoardFile){
    	printf("cannot open whiteboard save file");
    }
    fprintf(whiteBoardFile,"%d\n", numMessages);
    int i = 0;
    for(; i < numMessages; ++i)
    {
        fprintf(whiteBoardFile,"%d\n",whiteBoard->encrypted[i]);
        fprintf(whiteBoardFile,"%d\n",whiteBoard->messageLen[i]);
        if(whiteBoard->messageLen[i]!=0)
        {
            fprintf(whiteBoardFile,"%s\n",whiteBoard->messages[i]);
        }
    }
    fflush(whiteBoardFile);
    fclose(whiteBoardFile);
}

void loadWhiteBoard(char * stateFile)
{
    // Instead of using the whiteBoardFile we are going to create a new
    // whiteboard pointer as the assignment strictly says dump to the new
    // whiteboard file

    FILE *priorWhiteBoardFile;
    priorWhiteBoardFile = fopen(stateFile, "r");
    if(!priorWhiteBoardFile){
    	printf("Cannot open stateFile given, %s", stateFile);
        exit(-1);
    }
    int tempInt;
    fscanf(priorWhiteBoardFile, "%d", &tempInt);
    whiteBoard = createWhiteBoard(tempInt);

    fclose(priorWhiteBoardFile);
}

void connectionMessage(int * clientFD)
{
    // Create the connection message.
    char header[32] = "CMPUT379 Whiteboard Server v0\n";
    char body[32];
    sprintf(body, "%d\n", whiteBoard->numMessages);

    // Send the connection message to the client that just connected.
    send(*clientFD, header, strlen(header), 0);
    send(*clientFD, body, strlen(body), 0);
}

void maxClientsMessage(int clientFD)
{

}

void sendInfo(int * clientFD, char * response)
{
    int n = write(*clientFD, response, strlen(response));
    if (n < 0)
    {
        perror("ERROR writing to socket");
    }
}

void closeConnection()
{
    close(serverFD);
}

// 1. Create a socket with the socket()
void createSocket()
{
    serverFD = socket(AF_INET,SOCK_STREAM,0);
    if (serverFD == -1)
    {
        perror ("Error: unable to create server socket");
        exit (1);
    }
}

// 2. Bind the socket to an address using the bind()
void bindSocket(int portNoRequested)
{
    // Clear the serverAddr structure
    bzero(&serverAddr,sizeof(serverAddr));

    // Converting the given port number into network format
    // (Host byte order to network byte order)
    serverAddr.sin_port = htons(portNoRequested);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Give serverFD all the details inserted into the serverAddr
    if (bind(serverFD, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        perror ("Error: cannot bind server socket");
		exit (1);
    }
}

// 3. Listen for connections with the listen()
void listenForConnections()
{
    // Backlog (Second Parameter):
    // "The backlog is usually described as the limit for the queue of incoming connections."
    if (listen(serverFD, 10) == -1) {
        perror("Error: Unable to mark the socket as passive.");
        exit(-1);
    }
}

// 4. Accept a connection with the accept()
void acceptConnections()
{
    // There will be many clients so they don't need to be global
    struct sockaddr_in clientAddr;
    int clientLength = sizeof(clientAddr);

    // returns  a  new  file  descriptor referring to the client socket
    // (Creating a new socket for that specific client)
    clientFD = accept (serverFD, (struct sockaddr*) &clientAddr, &clientLength);
    fprintf(logFile, "This is the next clientFD: %d\n", clientFD);
    if (clientFD < 0)
    {
        perror ("Server: accept failed");
        exit (1);
    }

    if (numClients == MAXUSERS)
    {
        maxClientsMessage(clientFD);
    }
    int clientPort=0;
    char clientIP[20];

    // convert IPv4 and IPv6 addresses from binary to text form
    inet_ntop(AF_INET, &clientAddr.sin_addr.s_addr, clientIP, sizeof(clientIP));
    clientPort = htonl (clientAddr.sin_port);

    // increment the number of clients currently subscribed
    sem_wait(&numClientsSem);
    numClients++;
    sem_post(&numClientsSem);

    ClientNode * currentCLientNode = NULL;
    pthread_t clientThreadID;

    sem_wait(&clientLLSem);
    if (clientNodeHead != NULL)
    {
        clientNodeHead = append(clientNodeHead, clientAddr, clientThreadID, clientFD);
    }
    else
    {
        clientNodeHead = createClientNode(clientAddr, clientThreadID, clientFD, NULL);
    }
    currentCLientNode = search(clientNodeHead, clientFD);
    sem_post(&clientLLSem);

    pthread_create(currentCLientNode->threadID, NULL, recieve, (void *) currentCLientNode->fd);
    printf("clientFD: %d\n", currentCLientNode->fd);
    connectionMessage(currentCLientNode->fd);
}

// TODO: Yet to include anything about encryption, the encryption currently
// remains at 0 the whole time currently
void createCRUD(int * clientFD, int entryIndex, char * entryNumStr, int messageLength, char * message)
{
    char buffer[2*MAXCHARS];
    bzero(buffer, 2*MAXCHARS);
    // int * lenStore = calloc(1, sizeof(int));
    // printf("INPUTMESSAGELEN: %d", messageLength);
    // lenStore = messageLength;
    whiteBoard->messageLen[entryIndex] = messageLength;

    char messageLengthStr[4];
    bzero(messageLengthStr, 4);
    sprintf(messageLengthStr, "%d", whiteBoard->messageLen[entryIndex]);

    whiteBoard->messages[entryIndex] = calloc(messageLength, sizeof(char));
    memcpy(whiteBoard->messages[entryIndex], message, messageLength*sizeof(char));
    whiteBoard->messages[entryIndex][messageLength]='\0';

    printf("Message: %s\n", message);

    // write the appropriate response
    // !12e0\n\n
    sprintf(buffer, "!%se%d\n\n", entryNumStr, 0);
    char * bufferPointer = buffer;
    sendInfo(clientFD, bufferPointer);
}

void readCRUD(int * clientFD, char * entryNumStr)
{
    // Response: !12p30\nthisisaresponsetodemothelength\n
    // If 0 length: !12p0\n\n

    int entryIndex = atoi(entryNumStr);
    entryIndex -= 1;
    char messageLengthStr[4];
    bzero(messageLengthStr, 4);
    sprintf(messageLengthStr, "%d", whiteBoard->messageLen[entryIndex]);

    char messageContents[MAXCHARS];
    bzero(messageContents, MAXCHARS);
    sprintf(messageContents, whiteBoard->messages[entryIndex]);
    // printf("MessageContents: %s\n", messageContents);

    char buffer[2*MAXCHARS];
    bzero(buffer, 2*MAXCHARS);

    sprintf(buffer, "!%sp%s\n%s\n", entryNumStr, messageLengthStr, messageContents);

    char * bufferPointer = buffer;
    sendInfo(clientFD, bufferPointer);
}

void updateCRUD(int * clientFD, char * entryNumStr, char * message)
{
    char buffer[2*MAXCHARS];
    bzero(buffer, 2*MAXCHARS);

    int entryIndex = atoi(entryNumStr);
    if (entryIndex < 1 || entryIndex > WHITEBOARDSIZE)
    {
        // !47e14\nNo such entry!\n
        sprintf(buffer, "!%se%d\nNo such entry!\n", entryNumStr, 14);
        char * errorBuffer = buffer;
        sendInfo(clientFD, errorBuffer);
        return;
    }

    // The message may be indexed by one but the array is still zero indexed
    entryIndex -= 1;

    int messageLength = strlen(message);
    if (messageLength > MAXCHARS)
    {
        // !47e14\nNo such entry!\n
        sprintf(buffer, "!%se%d\nToo many characters, max is 256!\n", entryNumStr, 32);
        char * errorBuffer = buffer;
        sendInfo(clientFD, errorBuffer);
        return;
    }

    deleteCRUD(entryIndex);
    createCRUD(clientFD, entryIndex, entryNumStr, messageLength, message);
}

void deleteCRUD(int entryIndex)
{
    if (whiteBoard->messages[entryIndex] == NULL)
    {
        free(whiteBoard->messages[entryIndex]);
        whiteBoard->messages[entryIndex] = NULL;
    }
    whiteBoard->messageLen[entryIndex] = 0;
}

// 5. Send and receive data
void * recieve(void * clientFD)
{
    int * clientFDHeap = (int *) clientFD;
    char buffer[MAXCHARS];

    while(1)
    {
        bzero(buffer, MAXCHARS);

        int n = read(*clientFDHeap, buffer, MAXCHARS - 1);
        if (n < 0)
        {
            perror("ERROR reading from socket");
        }

        // Need to parse query to identify requested action
        //  - Can determine next action by the intial character (?, !, @)
        //  - Can determine the type of message attached (p, e, c)
        //  - Mixed with the length of args found from strtok

        // -- Type of request
        char type = buffer[0];

        // Skip the type
        char * bufferPointer = buffer;
        bufferPointer++;
        char * args;
        args = strtok(bufferPointer,"pec");

        // -- Entry attempting to access/modify
        char entry[4];
        bzero(entry, 4);
        sprintf (entry, args);
        args = strtok(NULL,"\n");

        char messageLength[4];
        char message[MAXCHARS];

        printf("Type: %c\n", type);
        printf("Nth-Message: %s\n", entry);

        if (type != '?')
        {
            bzero(messageLength, 4);
            sprintf (messageLength, args);
            args = strtok(NULL,"\n");

            printf("MessageLenth: %s\n", messageLength);

            // This atoi is safe without checking as the client UI (made by the
            // developer) will only allow numbers >= 0.
            if (atoi(messageLength) != 0)
            {
                bzero(message, MAXCHARS);
                sprintf (message, args);

                printf("Message: %s\n", message);
            }
        }

        if (type == '?') {
            readCRUD(clientFDHeap, entry);
        }
        else if (type == '@')
        {
            updateCRUD(clientFDHeap, entry, message);
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    // create sigaction for handling SIGSEGV
    struct sigaction sigtermViolationAction;
    sigtermViolationAction.sa_handler = sigtermViolationHandler;
    sigemptyset(&sigtermViolationAction.sa_mask);
    sigtermViolationAction.sa_flags = 0;
    sigaction(SIGTERM, &sigtermViolationAction, 0);

    // Create the clients list and initialize semaphores
    clientNodeHead = NULL;

    /*
        int sem_init(sem_t *sem, int pshared, unsigned int value);

        The pshared argument indicates whether this semaphore is to be shared
        between the threads of a process, or between processes.

        If pshared has the value 0, then the semaphore is shared between the
        threads of a process, and should be located at some address that is
        visible to all threads (e.g., a global variable, or a variable
        allocated dynamically on the heap).
    */
    sem_init(&clientLLSem, 0, 1);
    sem_init(&numClientsSem, 0, 1);

    // Usage information
    if (argc < 4)
    {
        printf("Usage: %s portnumber {-f statefile | -n entries}", argv[0]);
		exit(-1);
    }

    // strcmp returns 0 if the strings are equal
    if (strcmp(argv[2], "-f") == 0)
    {
        //get or create the statefile
        // loadWhiteBoard(argv[3]);
        whiteBoard = createWhiteBoard(38);
    }
    else if (strcmp(argv[2], "-n") == 0)
    {
        // Start “fresh” with entries empty whiteboard entries.
        int entries = atoi(argv[3]);
        if (entries == 0)
        {
            printf("Invalid Argument: %s must be a valid entries number.", argv[3]);
            exit(-1);
        }
        whiteBoard = createWhiteBoard(entries);
    }
    else
    {
        // Must be an invalid argument
        printf("Invalid Argument: %s must be either -f or -n", argv[2]);
        exit(-1);
    }

    int portNo = atoi(argv[1]);
    if (portNo == 0)
    {
        printf("Invalid Argument: %s must be a valid port number", argv[1]);
        exit(-1);
    }

    createSocket();
    bindSocket(portNo);

    // Make sure we are able to establish the socket before daemonizeProcess
    daemonizeProcess();

    // If the server is full (MAXUSERS), then listenForConnections will return
    // a -1, else 1 and we can go ahead and accept the connection
    int addedConnection = 0;
    while(1)
    {
        listenForConnections();
        acceptConnections();
    }
    return 0;
}
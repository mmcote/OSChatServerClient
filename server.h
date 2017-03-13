#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <sys/select.h>
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>

#include <signal.h>
#include <errno.h>
#include <sys/user.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>

#define MAXCHARS 1024
#define MAXUSERS 100

// ClientNode struct used in a linkedlist
// to maintain all client information
typedef struct
{
    struct sockaddr_in * addr;
    pthread_t * threadID;
    int * fd;
    struct ClientNode* next;
} ClientNode;

// Create a global array of Clients, size of max users
ClientNode * clientNodeHead;
int numClients = 0;

// Whiteboard struct
typedef struct
{
    int numMessages;
    char ** messages;
    int * encrypted;
    int * messageLen;
} WhiteBoard;

// Create a global whiteboard that the server operates on
WhiteBoard * whiteBoard;

FILE *logFile = NULL;
FILE *whiteBoardFile = NULL;

struct sockaddr_in serverAddr;
int serverFD;

sem_t clientLLSem;
sem_t numClientsSem;
sem_t whiteBoardSem;

pthread_t interruptThread;

WhiteBoard * create(int numMessagesRequested);
void sigtermViolationHandler(int signal_num);
void saveWhiteBoard();
void loadWhiteBoard(char * stateFile);
void connectionMessage(int * clientFD);
void sendInfo(int *clientFD, char * response);
void closeConnection();
void createSocket();
void bindSocket(int portNoRequested);
void listenForConnections();
void acceptConnections();
void createCRUD(int * clientFD, int entryIndex, char * entryNumStr, int messageLength, char * message, char encryptedState);
void readCRUD(int* clientFD, char * entryNumStr);
void updateCRUD(int * clientFD, char * entryNumStr, char * message, char encryptedState);
void deleteCRUD(int entryNum);
void * recieve(void * arg);

// ============================================================================
// Modified linkedlist code from zentut.com
/*
& File     : main.c
* Author   : zentut.com
* Purpose  : C Linked List Data Structure
* Copyright: @ zentut.com
*/

/*
    create a new ClientNode
    initialize the data and next field

    return the newly created ClientNode
*/
ClientNode* createClientNode(struct sockaddr_in address, pthread_t ID, int clientFD, ClientNode * next)
{
    ClientNode* newNode = (ClientNode*)malloc(sizeof(ClientNode));
    if(newNode == NULL)
    {
        printf("Error creating a new ClientNode");
        exit(-1);
    }
    newNode->addr = calloc(1, sizeof(struct sockaddr_in));
    newNode->threadID = calloc(1, sizeof(pthread_t));
    newNode->fd = calloc(1, sizeof(int));

    *newNode->addr = address;
    *newNode->threadID = ID;
    *newNode->fd = clientFD;
    newNode->next = next;

    return newNode;
}

/*
    add a new ClientNode at the end of the list
*/
ClientNode* append(ClientNode* head, struct sockaddr_in address, pthread_t ID, int clientFD)
{
    if(head == NULL)
        return NULL;

    /* go to the last ClientNode */
    ClientNode *cursor = head;
    while(cursor->next != NULL)
        cursor = cursor->next;

    /* create a new ClientNode */
    ClientNode* new_node =  createClientNode(address, ID, clientFD, NULL);
    cursor->next = new_node;

    return head;
}

/*
    remove ClientNode from the front of list
*/
ClientNode* remove_front(ClientNode* head)
{
    if(head == NULL)
        return NULL;
    ClientNode *front = head;
    head = head->next;
    front->next = NULL;
    /* is this the last ClientNode in the list */
    if(front == head)
        head = NULL;

    free(front->addr);
    free(front->threadID);
    free(front->fd);
    free(front);
    return head;
}

/*
    remove ClientNode from the back of the list
*/
ClientNode* remove_back(ClientNode* head)
{
    if(head == NULL)
    {
        return NULL;
    }


    ClientNode *cursor = head;
    ClientNode *back = NULL;
    while(cursor->next != NULL)
    {
        back = cursor;
        cursor = cursor->next;
    }

    if(back != NULL)
    {
        back->next = NULL;
    }

    /* if this is the last ClientNode in the list*/
    if(cursor == head)
    {
        head = NULL;
    }

    free(cursor->addr);
    free(cursor->threadID);
    free(cursor->fd);
    free(cursor);

    return head;
}

/*
    remove a ClientNode from the list
*/
ClientNode* remove_any(ClientNode* head,ClientNode* nd)
{
    if(nd == NULL)
        return NULL;
    /* if the ClientNode is the first ClientNode */
    if(nd == head)
        return remove_front(head);

    /* if the ClientNode is the last ClientNode */
    if(nd->next == NULL)
        return remove_back(head);

    /* if the ClientNode is in the middle */
    ClientNode* cursor = head;
    while(cursor != NULL)
    {
        if(cursor->next == nd)
            break;
        cursor = cursor->next;
    }

    if(cursor != NULL)
    {
        ClientNode* tmp = cursor->next;
        cursor->next = tmp->next;
        tmp->next = NULL;
        free(tmp);
    }
    return head;

}


/*
    Search for a specific ClientNode with input data

    return the first matched ClientNode that stores the input data,
    otherwise return NULL
*/
ClientNode* search(ClientNode* head, int clientFD)
{

    ClientNode *cursor = head;
    while(cursor!=NULL)
    {
        if(*cursor->fd == clientFD)
            return cursor;
        cursor = cursor->next;
    }
    return NULL;
}

/*
    remove all element of the list
*/
void dispose(ClientNode *head)
{
    ClientNode *cursor, *tmp;

    if(head != NULL)
    {
        cursor = head->next;
        head->next = NULL;
        while(cursor != NULL)
        {
            tmp = cursor->next;
            free(cursor->addr);
            free(cursor->threadID);
            free(cursor->fd);
            free(cursor);            
            cursor = tmp;
        }
    }
}

/*
    return the number of elements in the list
*/
int count(ClientNode *head)
{
    ClientNode *cursor = head;
    int c = 0;
    while(cursor != NULL)
    {
        c++;
        cursor = cursor->next;
    }
    return c;
}

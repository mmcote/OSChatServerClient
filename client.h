#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/time.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <ctype.h>

#define MAXCHARS 1024

FILE * keyFile;
int keyFileGiven;

int clientFD;
struct sockaddr_in servAddr;
struct hostent *server;
char buffer[MAXCHARS];
int numEntries;

unsigned char * key; 
unsigned char iv[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

char * encryptedText;
int encryptedCount, decryptedCount = 0;

char *base64encode (const void *b64_encode_this, int encode_this_many_bytes);
char *base64decode (const void *b64_decode_this, int decode_this_many_bytes);
void do_crypt(char* inputText);
char *do_decrypt(char* text, int x, unsigned char *givenKey);
unsigned char * encryptTextToBase64(char * inputText);
char * decryptBase64ToText(unsigned char * inputBase64);
void setKey();
void initializeServerData(int portNo, char * hostname);
void createSocket();
void connectSocket();
void recieve();
void menu(char * writeBuffer);
void sendMessage();
void sigIntViolationHandler(int signal_num);

#endif

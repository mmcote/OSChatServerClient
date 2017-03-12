#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

void initializeServerData(int portNo);
void createSocket();
void connectSocket();
void recieve();
void menu(char * writeBuffer);
void sendMessage();

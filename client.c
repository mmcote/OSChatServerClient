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

unsigned char key[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";//{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
unsigned char iv[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
char * encryptedText;
int encryptedCount, decryptedCount = 0;

// ########################## BASE 64 ENCODE AND DECODE #######################################
char *base64encode (const void *b64_encode_this, int encode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    BUF_MEM *mem_bio_mem_ptr;    //Pointer to a "memory BIO" structure holding our base64 data.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                           //Initialize our memory sink BIO.
    BIO_push(b64_bio, mem_bio);            //Link the BIOs by creating a filter-sink BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);  //No newlines every 64 characters or less.
    BIO_write(b64_bio, b64_encode_this, encode_this_many_bytes); //Records base64 encoded data.
    BIO_flush(b64_bio);   //Flush data.  Necessary for b64 encoding, because of pad characters.
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);  //Store address of mem_bio's memory structure.
    BIO_set_close(mem_bio, BIO_NOCLOSE);   //Permit access to mem_ptr after BIOs are destroyed.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);   //Makes space for end null.
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';  //Adds null-terminator to tail.
    return (*mem_bio_mem_ptr).data; //Returns base-64 encoded data. (See: "buf_mem_st" struct).
}

char *base64decode (const void *b64_decode_this, int decode_this_many_bytes){
    BIO *b64_bio, *mem_bio;      //Declares two OpenSSL BIOs: a base64 filter and a memory BIO.
    char *base64_decoded = calloc( (decode_this_many_bytes*3)/4+1, sizeof(char) ); //+1 = null.
    b64_bio = BIO_new(BIO_f_base64());                      //Initialize our base64 filter BIO.
    mem_bio = BIO_new(BIO_s_mem());                         //Initialize our memory source BIO.
    BIO_write(mem_bio, b64_decode_this, decode_this_many_bytes); //Base64 data saved in source.
    BIO_push(b64_bio, mem_bio);          //Link the BIOs by creating a filter-source BIO chain.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);          //Don't require trailing newlines.
    int decoded_byte_index = 0;   //Index where the next base64_decoded byte should be written.
    while ( 0 < BIO_read(b64_bio, base64_decoded+decoded_byte_index, 1) ){ //Read byte-by-byte.
        decoded_byte_index++; //Increment the index until read of BIO decoded data is complete.
    } //Once we're done reading decoded data, BIO_read returns -1 even though there's no error.
    BIO_free_all(b64_bio);  //Destroys all BIOs in chain, starting with b64 (i.e. the 1st one).
    return base64_decoded;        //Returns base-64 decoded data with trailing null terminator.
}

// ########################## AES 256 ENCODE #######################################
void do_crypt(char* inputText){
    unsigned char outbuf[1024];
    int outlen, tmplen = 0;
    
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv);

    if(!EVP_EncryptUpdate(&ctx, outbuf, &outlen, inputText, strlen(inputText)))
    {
        /* Error */
      return;
    }
    if(!EVP_EncryptFinal_ex(&ctx, outbuf + outlen, &tmplen))
    {
        /* Error */
      return;
    }
    outlen += tmplen;
    encryptedCount = outlen;

    EVP_CIPHER_CTX_cleanup(&ctx);

    encryptedText = calloc(outlen, sizeof(char));
    int i = 0;
    for (; i < outlen; ++i)
    {
        encryptedText[i] = (char) outbuf[i];
    }
}

// ########################## AES 256 DECODE #######################################
char *do_decrypt(char* text, int x, unsigned char *givenKey){
    unsigned char debuf[1024];
    int delen, remainingBytes = 0;
    
    
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, givenKey, iv);

    if(!EVP_DecryptUpdate(&ctx, debuf, &delen, text, x))
    {
        /* Error */
        return NULL;
    }
    if(!EVP_DecryptFinal_ex(&ctx, debuf + delen, &remainingBytes))
    {
        /* Error */
        return NULL;
    }
    delen += remainingBytes;
    decryptedCount = delen;

    EVP_CIPHER_CTX_cleanup(&ctx);
    
    char * decryptedText = calloc(delen, sizeof(char));
    int i = 0;
    for (; i < delen; ++i)
    {
        decryptedText[i] = (char) debuf[i];
    }
    return decryptedText;
}

unsigned char * encryptTextToBase64(char * inputText)
{
  do_crypt(inputText);
  return base64encode(encryptedText, encryptedCount);   //Base-64 encoding.
}

char * decryptBase64ToText(unsigned char * inputBase64)
{
    int len = 1024;
    char outputText[len];
    char lineBuffer[len];
    char * decodedKey;
    char * resultingText;


    bzero(outputText, len);
    bzero(lineBuffer, len);
    
    int numBytesToDecode = strlen(inputBase64); //Number of bytes in string to base64 decode.
    char * base64_decoded = base64decode(inputBase64, numBytesToDecode);   //Base-64 decoding.

    FILE * keyFile = fopen("key.txt","r");
    if(!keyFile)
    {
      printf("\nError reading file\n");
      exit(0);
    }

    while (fgets(lineBuffer, len, keyFile) != NULL)
    {
      decodedKey = base64decode(lineBuffer, strlen(lineBuffer));
      resultingText = do_decrypt(base64_decoded, encryptedCount, decodedKey);
      if (resultingText != NULL){
        strncpy(outputText, resultingText, decryptedCount);
        printf("Key worked: \n%s\n", outputText);
        int textLen = strlen(outputText);
        char * text = calloc(textLen, sizeof(char));
        int i = 0;
        for (; i < textLen; ++i)
        {
          text[i] = (char) outputText[i];
        }
        return text;
      }
      else
      {
        printf("Key did not work\n");
      }
      bzero(lineBuffer, len);
    }
    return NULL;
}

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

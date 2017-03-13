#include "client.h"

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
char *do_decrypt(char* text, int len, unsigned char *givenKey){
    unsigned char debuf[1024];
    int delen, remainingBytes = 0;
    
    
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, givenKey, iv);

    if(!EVP_DecryptUpdate(&ctx, debuf, &delen, text, len))
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
    int lineLen;
    while (fgets(lineBuffer, len, keyFile) != NULL)
    { 
        lineLen = strlen(lineBuffer);
        decodedKey = base64decode(lineBuffer, lineLen);
        int decodedKeyLen = strlen(decodedKey);
        resultingText = do_decrypt(base64_decoded, decodedKeyLen, decodedKey);

        if (resultingText != NULL){
            // strncpy(outputText, resultingText, decryptedCount);
            strcpy(outputText, resultingText);
            int textLen = strlen(outputText);
            char * text = calloc(textLen, sizeof(char));
            int i = 0;
            for (; i < textLen; ++i)
            {
                text[i] = (char) outputText[i];
            }
            rewind(keyFile);
            return text;
        }
        // else
        // {
        //     printf("Key did not work\n");
        // }
        bzero(lineBuffer, len);
    }
    rewind(keyFile);
    return NULL;
}


void setKey()
{
    int len = 1024;
    char lineBuffer[len];
    bzero(lineBuffer, len);

    char * decodedKey;

    if (fgets(lineBuffer, len, keyFile) != NULL)
    {
        int lineLen = strlen(lineBuffer);
        decodedKey = base64decode(lineBuffer, lineLen);
        lineLen = strlen(decodedKey);
        key = calloc(lineLen, sizeof(char));
        key = decodedKey;
    }
    rewind(keyFile);
}

void initializeServerData(int portNo, char * hostname)
{
	server = gethostbyname(hostname);
	if (server == NULL)
	{
		perror ("Error: unable to get \"hostname\"");
        exit (-1);
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

void recieveExit()
{
    bzero(buffer,256);
	int n = read(clientFD,buffer,255);
	if (n < 0)
	{
	    perror("Error: reading from socket");
	}
    else
    {
        printf("Error: Unable to parse server close message.\n");
        exit(-1);
    }
    exit(0);
}

void recieve()
{
    char * args;
    char bufferCopy[MAXCHARS];
	bzero(buffer,MAXCHARS);
    bzero(bufferCopy,MAXCHARS);

	int n = read(clientFD, buffer, MAXCHARS - 1);
	if (n < 0)
	{
	    perror("Error: reading from socket");
	}
    sprintf(bufferCopy, "%s", buffer);

    if (buffer[0] == '!' && keyFileGiven == 0)
    {
        char * bufferPointer = buffer;
        // Skip the !
        bufferPointer++;
        char type;
        while (*bufferPointer) {
            if (isalpha(*bufferPointer))
            {
                type = *bufferPointer;
                break;
            }
            bufferPointer++;
        }

        // Only if it is encrypted do we parse the message
        if (type == 'c' && keyFileGiven == 0)
        {
            // Parse Message out of response
            bufferPointer = buffer;

            // Skip the !
            bufferPointer++;

            // // Skip the type
            args = strtok(bufferPointer,"pc");

            // Grab the message length
            args = strtok(NULL, "\n");
            int messageLen = atoi(args);
            // if the message is not empty 
            if (messageLen > 0)
            {
                args = strtok(NULL, "\n");
                char * decryptedArg = decryptBase64ToText(args);
                if (decryptedArg == NULL)
                {
                    printf("\n> There was an error in decrypting, here is the raw form:\n");
                    printf("%s, bufferCopy");
                }
                else
                {
                    printf("\nCMPUT379 Whiteboard Encrypted v0\n");
                    printf("%s\n", decryptedArg);
                    bzero(buffer,MAXCHARS);
                }
                return;
            }
        }
    }
    printf("Raw Response:\n%s", bufferCopy);
    bzero(buffer, MAXCHARS);
}

void initialMessage()
{
    char * args;

	bzero(buffer, MAXCHARS);
    
    int n = read(clientFD,buffer, MAXCHARS - 1);
    printf("%s\n", buffer);

	if (n < 0)
	{
	    perror("Error: reading from socket");
	}
    char * bufferPointer = buffer;
    args = strtok(bufferPointer, "\n");
    args = strtok(NULL, "\n");

    numEntries = atoi(args);
}



// 3. Send and receive data, use the read() and write() system calls
void sendMessage()
{
    char writeBuffer[MAXCHARS];
    bzero(writeBuffer, MAXCHARS);

    char type;
    int entryNum;

    // 1. Select Query or Update
    printf("Would you like to make a query (1) or update (2) or exit (exit or ctrl-c)?\n");
    
    char input[10];
    char exitArray[10];
    bzero(exitArray, 10);
    strcpy(exitArray, "exit");

    while (1)
    {
        bzero(input, 10);
        fgets(input, 9, stdin);
        if (input[0] == '1')
        {
            printf("You've selected to make a query.\n");
            type = '?';
            break;
        } 
        else if (input[0] == '2')
        {
            printf("You've selected to make an update.\n");
            type = '@';
            break;
        }
        else if (strncmp(input, exitArray, 4) == 0)
        {
            userLogout();
        }
        else
        {
            printf("Please select a valid option.\n");
            continue;
        }
    }

    // 2. Enter Whiteboard Entry
    printf("Which entry would you like to access (Entry Number or exit (exit or ctrl-c)?\n");
    bzero(input, 10);
    fgets(input, 9, stdin);
    if (strncmp(input, exitArray, 4) == 0)
    {
        userLogout();
    }
    entryNum = atoi(input);

    if (type != '?')
    {
        // 3. Enter Message if necessary
        printf("Please enter your new whiteboard message. Or to exit (exit or ctrl-c)\n");
        int messageLen = 0;
        char buffer[MAXCHARS];
        bzero(buffer, MAXCHARS);
        fgets(buffer, MAXCHARS - 1, stdin);
        if (strncmp(buffer, exitArray, 4) == 0)
        {
            userLogout();
        }
        messageLen = strlen(buffer) - 1;
        if (keyFileGiven == 0 && messageLen != 0)
        {
            // This is where we will have the option to encrypt a outgoing update
            printf("\n> Would you like to encrypt the message? Yes (y) or No (n) Or to exit (exit or ctrl-c)\n");
            fgets(input,9, stdin);
            if (strncmp(input, exitArray, 4) == 0)
            {
                userLogout();
            }
        }
        else
        {
            input[0] = 'n';
        }

        messageLen = 0;
        char encrypted = 'p';
        if (input[0] == 'y')
        {
            // Encrypt the message
            printf("\n> Your message is being encrypted.\n");
            char * bufferPointer = buffer;
            unsigned char * base64Arg = encryptTextToBase64(bufferPointer);
            messageLen = strlen(base64Arg);
            bzero(buffer, MAXCHARS);
            sprintf(buffer, "%s", base64Arg);
            encrypted = 'c';
        }
        else if (input[0] == 'n')
        {
            // Proceed as per usual
            printf("\n> Your message is being sent without encryption.\n");
            messageLen = strlen(buffer);
        }
        sprintf(writeBuffer, "%c%d%c%d\n%s\n", type, entryNum, encrypted, messageLen, buffer);

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
	bzero(writeBuffer,MAXCHARS);
    recieve();
}

void userLogout()
{
    char writeBuffer[32];
    bzero(writeBuffer, 32);
    sprintf(writeBuffer, "&000UserLogout");
    int n = write(clientFD, writeBuffer, strlen(writeBuffer));
	if (n < 0)
	{
	    perror("Error: writing to socket");
	}
    exit(0);
}


void sigIntViolationHandler(int signal_num)
{
    userLogout();
    // close(serverFD);
    //exit(-1);
}

int main(int argc, char **argv) 
{
    // create sigaction for handling SIGSEGV
    struct sigaction sigIntViolationAction;
    sigIntViolationAction.sa_handler = sigIntViolationHandler;
    sigemptyset(&sigIntViolationAction.sa_mask);
    sigIntViolationAction.sa_flags = 0;
    sigaction(SIGINT, &sigIntViolationAction, 0);
    keyFileGiven = 0;
    if (argv[3] != NULL)
    {
        keyFile = fopen(argv[3],"r");

        if(!keyFile)
        {
            perror("Error: Unable to open the given keyfile.\n");
            exit(0);
        }
        setKey();

    }
    else
    {
        keyFileGiven = 1;
        printf("No key file given. Therefore decryption and encryption are disabled.\n");
    }

    if (argc < 3)
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
	initializeServerData(portNo, argv[1]);
    connectSocket();

    // This recieve is just to take in the initial welcome message
    initialMessage();

    // The client is continually requesting from the server
    while(1)
    {
        sendMessage();
    }
}

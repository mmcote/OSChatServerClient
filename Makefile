CC_Object = gcc -w 

client.o : client.c
	$(CC_Object) client.c -o client -lcrypto

server.o : server.c 


clean: 
	rm *.o -rf $(MAKE) clean

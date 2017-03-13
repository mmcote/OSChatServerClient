all: client.o server.o

CC_Object = gcc -w 

client.o : client.c
	$(CC_Object) client.c -o wbc379 -l crypto

server.o : server.c 
	$(CC_Object) server.c -o wbs379 -l pthread

clean: 
	rm *.o -rf $(MAKE) clean

CC = gcc
CFLAGS = -pedantic -Wall -g -pthread -lcrypt

OUTPUTCLIENT = crackclient
OUTPUTSERVER = crackserver

all: cc cs
.DEFAULT: all

cc : crackclient.c
	$(CC) $(CFLAGS) crackclient.c -o $(OUTPUTCLIENT)

cs : crackserver.c
	$(CC) $(CFLAGS) crackserver.c -o $(OUTPUTSERVER)

cleanc : 
	rm crackclient

cleans :
	rm crackserver

clean : 
	rm crackclient
	rm crackserver

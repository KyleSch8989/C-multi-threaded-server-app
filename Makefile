CC = gcc
CFLAGS = -pedantic -Wall -g -pthread

OUTPUTCLIENT = crackclient
OUTPUTSERVER = crackserver

all: cc cs
.DEFAULT: all

cc : crackclient.c
	$(CC) $(CFLAGS) crackclient.c -o $(OUTPUTCLIENT) -lcrypt

cs : crackserver.c
	$(CC) $(CFLAGS) crackserver.c -o $(OUTPUTSERVER) -lcrypt

cleanc : 
	rm crackclient

cleans :
	rm crackserver

clean : 
	rm crackclient
	rm crackserver

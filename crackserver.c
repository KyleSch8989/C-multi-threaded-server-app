
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <crypt.h>
#include <semaphore.h>
#include <stdbool.h>
#include <signal.h>

struct Stats {
    sigset_t set;
    sem_t* statsLock;
    int currentClientConnections;
    int totalClients;
    int totalCrackRequests;
    int failedCrackRequests;
    int passedCrackRequests;
    int cryptRequests;
    int encryptionRequests;
};

struct Params { //REF: inspiration taken from LEC8
    int fd;
    char** dictStr;
    int dictLen;
    sem_t* connLock;
    bool isLimited;
    sem_t* crackLock;
    sem_t* crackLock2;
    int threadLim[2];
    char* cyphertext;
    char* salt;
    char* crackResult;
    struct Stats s;
};

/* error_msg_1()
 * --------------
 * Template for error message 1. Prints error message to screen
 * and then exits program with exit code 1.
 *
 * Errors: returns error code 1.
 */
void error_msg_1() {
    fprintf(stderr, "Usage: crackserver [--maxconn connections] "
            "[--port portnum] [--dictionary filename]\n");
    fflush(stderr);
    exit(1);
}

/* error_msg_2()
 * --------------
 * Standard template for error message 2. Takes the name of the file for input
 * and uses it in the error message.
 *
 * filename: name of the file being used for input to the program.
 *
 * Errors: returns error code 2.
 */
void error_msg_2(char* fileName) {
    fprintf(stderr, "crackserver: unable to open dictionary file %c%s%c\n", 
            '"', fileName, '"');
    fflush(stderr);
    exit(2);
}

char** split_by_char(char* str, char split, unsigned int maxFields) {
	char** result = malloc(maxFields * sizeof(char*));
	if (result == NULL) {
		fprintf(stderr, "MEM allocation error\n");
		exit(EXIT_FAILURE);
	}

	int count = 0;
	char* token = strtok(str, &split);
	while (token != NULL && count < maxFields) {
		result[count] = malloc((strlen(token) + 1) * sizeof(char));
		if (result[count] == NULL){
			fprintf(stderr, "Mem allocation error");
			exit(EXIT_FAILURE);
		}
		strcpy(result[count], token);
		count++;
		token = strtok(NULL, &split);
	}

	while (count < maxFields) {
		result[count] = NULL;
		count++;
	}

	return result;
}


char* read_line(FILE* stream) {
	char* line = NULL;
	size_t bufsize = 0;
	ssize_t characters = getline(&line, &bufsize, stream);
	if (characters == -1) {
		if (feof(stream)) {
			return NULL;
		} else {
			fprintf(stderr, "Error reading line\n");
			exit(EXIT_FAILURE);
		}
	}

	if (line[characters - 1] == '\n') {
		line[characters - 1] = '\0';
	}

	return line;
}

/* error_msg_4()
 * --------------
 * Standard template for the error message 4. Prints out the error message,
 * then exits the program with error code 4.
 *
 * Errors: returns error code 4.
 */
void error_msg_4() {
    fprintf(stderr, "crackserver: unable to open socket for listening\n");
    fflush(stderr);
    exit(4);
}

/* command_line_validity()
 * ------------------------
 * Combs through the command line arguments and determines if the comman line
 * is valid.
 *
 * argc: number of command line arguments
 * argv: an array of the command line arguments.
 *
 * Errors: If the commandline is at all invalid, then the program will return
 *      with exit code 1.
 */
void command_line_validity(int argc, char* argv[]) {
    if (argc > 7 || argc == 2 || argc == 4 || argc == 6) {
        error_msg_1();
    }

    for (int i = 1; i < argc; i++) {
        if ((i % 2 == 1) && (strcmp(argv[i], "--maxconn")) && 
                (strcmp(argv[i], "--port")) && 
                (strcmp(argv[i], "--dictionary"))) {
            error_msg_1();
        }

        if ((i % 2 == 0) && (strstr(argv[i], "--"))) {
            error_msg_1();
        }
    }

    if (argc == 5 && (!strcmp(argv[1], argv[3]))) {
        error_msg_1();
    }

    if (argc == 7) {
        if (!strcmp(argv[1], argv[3])) {
            error_msg_1();
        }

        if (!strcmp(argv[1], argv[5])) {
            error_msg_1();
        }

        if (!strcmp(argv[3], argv[5])) {
            error_msg_1();
        }
    }
}

/* filter_dict()
 * -------------
 * takes an open file stream to a dictionary of words and sorts through the
 * words and create a data-structure containing the valid words.
 *
 * dictStream: open file stream pointing to a dictionary.
 *
 * Returns: A data structure containing all of the valid dictionary words.
 *      the data structure is of the type char**.
 * Errors: If the dictionary is empty, then the program will exit with
 *      exit code 3.
 * REF: Inspiration for dictionary filtering taken from 
 * REF: Ed Lession Week 3.2 - file handling/Custom input processing.
 */
char** filter_dict(FILE* dictStream) {
    char* line;
    int lineNum = 0;
    int buffer = 10;
    char** dictionary = malloc(sizeof(char*) * buffer);

    while (1) {
        line = read_line(dictStream);

        if (!line) {
            break;
        }

        if (strlen(line) > 8) {
            continue;
        }

        if (lineNum == buffer - 2) {
            buffer += 10;
            dictionary = realloc(dictionary, sizeof(char*) * buffer);
        }
        
        dictionary[lineNum] = strdup(line);
        lineNum++;
    }
    dictionary[lineNum] = NULL;

    if (lineNum == 0) {
        fprintf(stderr, "crackserver: no plain text words to test\n");
        fflush(stderr);
        exit(3);
    }

    return dictionary;
}

/* get_connect_lim()
 * ------------------
 * Combs through the command line arguments and tries to find an instance
 * of a user defined connection limit to the program.
 *
 * argc: Number of command line arguments.
 * argv: Command line arguments
 *
 * Returns: 0 if there is no user defined connection limit, else the user 
 *      defined limit is returned as an integer.
 * Errors: If the --maxconn flag is given and the user hasn't given a 
 *      following value then the program will exit with an error code 1.
 */
int get_connect_lim(int argc, char* argv[]) {
    int connectionLimit = 0;
    char* tempLimit = NULL;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--maxconn")) {
            tempLimit = strdup(argv[i + 1]);
        }
    }
    
    if (tempLimit) {
        for (int i = 0; tempLimit[i] == '\0'; i++) {
            if (!isdigit(tempLimit[i])) {
                error_msg_1();
            }
        }
        connectionLimit = atoi(tempLimit);
    }
    if (connectionLimit < 0) {
        error_msg_1();
    }
    return connectionLimit;
}

/* get_port_num()
 * ---------------
 * Combs through the command line arguments to try and find a user defined
 * port number.
 *
 * argc: number of command line arguments.
 * argv: command line arguments.
 *
 * Returns: 0 if the user hasn't given a specific port num, else the user's 
 *      defined port number is returned as an integer.
 * Errors: if the --port flag is given and there is no associated value then
 *      program will exit with error code 1.
 */
int get_port_num(int argc, char* argv[]) {
    int port = 0;
    char* tempPort = NULL;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--port")) {
            tempPort = strdup(argv[i + 1]);
        }
    }
    
    if (tempPort) {
        for (int i = 0; i < strlen(tempPort); i++) {
            if (!isdigit(tempPort[i])) {
                error_msg_1();
            }
        }
        port = atoi(tempPort);
    }

    if (port != 0 && (port < 1024 || port > 65535)) {
        error_msg_1();
    }
    
    return port;
}

/* get_dict()
 * ----------
 * Combs through the command line arguments to find a user defined dicitonary.
 * if no dictionary is specified then a standard dictionary is used. The 
 * function will also open the dictionary as a file stream and call for it to
 * be filtered through.
 *
 * argc: number of command line arguments
 * argv: command line arguments
 *
 * Returns: char** data structure of filtered dicitonary. If no dictionary is
 *      supplied to the command line then the program will use a default
 *      dictionary located at "/usr/share/dict/words".
 * Errors: If the dicitonary is unable to be opened then the program will exit
 *      with error code 2.
 */
char** get_dict(int argc, char* argv[]) {
    char* dict = strdup("/usr/share/dict/words");

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--dictionary")) {
            dict = argv[i + 1];
        }
    }

    FILE* dictStream = fopen(dict, "r");
    if (!dictStream) {
        error_msg_2(dict);
    }
    
    char** dictStructure = filter_dict(dictStream);
    fclose(dictStream);
    return dictStructure;
}

/* begin_listen()
 * --------------
 * opens up a socket for the server to then listen for connecitons from
 * clients.
 *
 * port: The specified port number by the user to be used in the listening
 *      socket. If the port number is not specified by the user of the user
 *      has set the port to 0, then the socket will open on an ephemeral port.
 *      Once the socket has been opened, it is binded to the localhost 
 *      address.
 * connLimit: maximum amount of connections to the server.
 *
 * Returns: file descriptor to the opened listening socket. 
 * Errors: If there are any errors regarding the socket such as setting the
 *      options or binding the socket, the program will exit with error 
 *      code 4.
 * REF: Following function heavily inspired from example given on moss at
 * REF: week10/server-multithreaded.c
 */
int begin_listen(int port, int connLimit) {
    //REF: Inspiration taken from week10/server-multithreaded
    char strPort[6]; //integer version of port is already < 6 characters long.
    sprintf(strPort, "%d", port);

    struct addrinfo* ai = 0;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo("localhost", strPort, &hints, &ai);
    if (err) {
        printf("connot determine address\n");
    }

    int listenFd = socket(AF_INET, SOCK_STREAM, 0);

    int optVal = 1;
    if (setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &optVal, 
            sizeof(int)) < 0) {
        error_msg_4();
    }

    if (bind(listenFd, ai->ai_addr, sizeof(struct sockaddr)) < 0) {
        error_msg_4();
    }

    if (listen(listenFd, connLimit) < 0) {
        error_msg_4();
    }

    return listenFd;
}

/* port_num()
 * -----------
 * Uses the file descriptor given by the listening socket and prints out the
 * port number. This is usefull if the port is set as an ephemeral port.
 *
 * listenFd: listening socket file descriptor.
 * Errors: If there is an error when trying to recive the port number the
 *      program will exit with error code 4.
 * REF: Heavy inpiration for function taken from week10/net4.c
 */
void port_num(int listenFd) {
    //REF: instiration taken from week10/net4.c
    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(listenFd, (struct sockaddr*)&ad, &len)) {
        printf("sockname\n");
        fflush(stdout);
        exit(4);
    }
    fprintf(stderr, "%u\n", ntohs(ad.sin_port));
    fflush(stderr);
}

/* crack_thread()
 * ---------------
 * function used to handle the cracking command. When a request to crack is
 * made, 1 or many of these functions is called in unison to crack the
 * cyphertext using the brute force method. The thread recives a range of 
 * indexes from the parent thread, this is the method used to partition up the
 * dictionary into smaller ordered chunks to be tested. The multithreaded
 * cracking will essentially check each word in the dictionary by encrypting
 * the word, then checking if the cyphertext given is the same as the
 * cyphertext being tested. If one of the other cracking threads has found a
 * match then all other threads will immeadiately stop iterating through the
 * dictionary and close. crypt_r() is being used as a thread safe 
 * alternative to the standard crypt().
 *
 * params: large struct unit carring essential information including the
 *      cyphertext being tested and the specific range of indexes for this
 *      thread.
 * 
 * REF: usage of crypt_r() taken from 'man crypt(3)'
 */
void* crack_thread(void* params) {
    struct Params* p = (struct Params*)params;
    struct crypt_data cd;
    memset(&cd, 0, sizeof(cd));
    cd.initialized = 0;
    int range[2];
    int count = 0;
    range[0] = p->threadLim[0];
    range[1] = p->threadLim[1];
    sem_post(p->crackLock);
    crypt_r(p->dictStr[range[0]], p->salt, &cd);

    for (int i = range[0]; i < range[1] + 1; i++) {
        if (strcmp(p->crackResult, ":failed")) {
            break;
        }
        crypt_r(p->dictStr[i], p->salt, &cd);
        count += 1;
        if (!strcmp(cd.output, p->cyphertext)) {
            strcpy(p->crackResult, p->dictStr[i]);
        }
    }

    sem_wait(p->s.statsLock);
    p->s.encryptionRequests += count;
    sem_post(p->s.statsLock);
    return NULL;
}

/* server_crypt()
 * ---------------
 * uses crypt_r as a thread safe way to encrypt plaintext.
 *
 * clientFd: file descriptor for the current client.
 * plaintext: plaintext to be encrypted.
 * salt: additional salt to be used as the setting for the encryption.
 * REF: use of crypt_r() taken from 'man crypt(3)'
 */
void server_crypt(int clientFd, char* plaintext, char* salt, 
        struct Params* p) {
    struct crypt_data cd;
    memset(&cd, 0, sizeof(cd));
    cd.initialized = 0;
    crypt_r(plaintext, salt, &cd);

    char* cypherLn = strdup("");
    sprintf(cypherLn, "%s\n", cd.output);
    write(clientFd, cypherLn, 14);
}

/* server_crack()
 * --------------
 * Spawns the nessesary amount of threads requested to crack a given 
 * cyphertext and then writes the plaintext back to the client.
 *
 * clientFd: file descriptor for the current client.
 * cyphertext: cyphertext to be decrypted.
 * numThreads: number of threads requested to be used during the brute-force.
 * params: large struct containing dictionary and its length in terms of
 *      a word count.
 * REF: slight inspiration taken from week8/thread4.c
 */
void server_crack(int clientFd, char* cyphertext, int numThreads, 
        struct Params* p) {
    sem_wait(p->crackLock2);
    sem_t* crackLock = malloc(sizeof(sem_t));
    sem_init(crackLock, 0, 1);
    pthread_t threadIds[numThreads];
    p->crackLock = crackLock;

    if (p->dictLen < numThreads) {
        numThreads = 1;
    }
    int wordsPerThread = p->dictLen / numThreads;
    int threadLim[2];
    p->salt = malloc(sizeof(char) * 3);
    p->salt[0] = cyphertext[0];
    p->salt[1] = cyphertext[1];
    p->salt[2] = '\0';
    p->cyphertext = strdup(cyphertext);
    p->crackResult = strdup(":failed");

    for (int i = 0; i < numThreads - 1; i++) {
        sem_wait(crackLock);
        threadLim[0] = wordsPerThread * i;
        threadLim[1] = (wordsPerThread * (i + 1)) - 1;
        p->threadLim[0] = threadLim[0];
        p->threadLim[1] = threadLim[1];
        pthread_create(&threadIds[i], NULL, crack_thread, p);
    }
    sem_wait(crackLock);
    threadLim[0] = wordsPerThread * (numThreads - 1);
    threadLim[1] = p->dictLen - 1;
    p->threadLim[0] = threadLim[0];
    p->threadLim[1] = threadLim[1];
    pthread_create(&threadIds[numThreads - 1], NULL, crack_thread, p);
    
    for (int i = 0; i < numThreads; i++) {
        pthread_join(threadIds[i], NULL);
    }
    if (!strcmp(p->crackResult, ":failed")) {
        sem_wait(p->s.statsLock);
        p->s.failedCrackRequests += 1;
        sem_post(p->s.statsLock);
    } else {
        sem_wait(p->s.statsLock);
        p->s.passedCrackRequests += 1;
        sem_post(p->s.statsLock);
    }
    char* clientPlainText = strdup("");
    sprintf(clientPlainText, "%s\n", p->crackResult);
    write(clientFd, clientPlainText, strlen(clientPlainText));
    sem_post(p->crackLock2);
}

/* process_command()
 * ------------------
 * Takes a command from the current client thread and checks for any semantic
 * errors in the command. If there are no errors in the command then, based
 * on the command the program will either crack or crypt for the client.
 * if any of the commands given are semantically incorrect, then the client
 * will recieve ":invalid"
 *
 * clientFd: file descriptor for the current client.
 * command: command given by the client.
 * p: large struct containing data to be used in the cracking process.
 *
 * REF: use of write command taken from 'man write(3)'
 */
void process_command(int clientFd, char* command, struct Params* p) {
    //REF: use of split_by_char inspired by man page split_by_char(3)
    char** fields = split_by_char(command, ' ', 3);
    if (strcmp(fields[0], "crack") && strcmp(fields[0], "crypt")) {
        write(clientFd, ":invalid\n", 9);
        return;
    }
    for (int i = 0; i < 3; i++) {
        if (fields[i] == NULL || !strcmp(fields[i], "")) {
            write(clientFd, ":invalid\n", 9);
            return;
        }
    }

    if (!strcmp(fields[0], "crack")) {
        sem_wait(p->s.statsLock);
        p->s.totalCrackRequests += 1;
        sem_post(p->s.statsLock);
        if (strlen(fields[1]) != 13) {
            write(clientFd, ":invalid\n", 9);
            return;
        }
        for (int i = 0; i < (strlen(fields[2]) - 1); i++) {
            if (!isdigit(fields[2][i])) {
                write(clientFd, ":invalid\n", 9);
                return;
            }
        }
        long numThreads = atol(fields[2]);
        if (numThreads < 1 || numThreads > 50) {
            write(clientFd, ":invalid\n", 9);
            return;
        }
        for (int i = 0; i < 2; i++) {
            if (isalpha(fields[1][i]) || isdigit(fields[1][i]) ||
                    fields[1][i] == '.' || fields[1][i] == '/') {
                continue;
            } else {
                write(clientFd, ":invalid\n", 9);
                return;
            }
        }
        server_crack(clientFd, fields[1], numThreads, p);
        return;
    }

    if (!strcmp(fields[0], "crypt")) {
        sem_wait(p->s.statsLock);
        p->s.cryptRequests += 1;
        sem_post(p->s.statsLock);
        if ((strlen(fields[2]) - 1) != 2) {
            write(clientFd, ":invalid\n", 9);
            return;
        }
        for (int i = 0; i < 2; i++) {
            if (isalpha(fields[2][i]) || isdigit(fields[2][i]) ||
                    fields[2][i] == '.' || fields[2][i] == '/') {
                continue;
            } else {
                write(clientFd, ":invalid\n", 9);
                return;
            }
        }
        server_crypt(clientFd, fields[1], fields[2], p);
        sem_wait(p->s.statsLock);
        p->s.encryptionRequests += 1;
        sem_post(p->s.statsLock);
        return;
    }
}

/* client_thread()
 * ----------------
 * Main thread for handling the actions of a connected client.
 * endlessly recives commands from the client to be process. once the client
 * has disconnected the thread will close. 
 *
 * v: large struct used to send many arguments into threads.
 *
 * REF: use of read command inspired by week10/server-multithreaded.c and
 * REF: 'man read(3)'
 *
 * REF: example of multi-argument thread function taken from Lec 8/Page 33-35.
 */
void* client_thread(void* v) {
    struct Params* p = (struct Params*)v;
    int clientFd = p->fd;
    sem_post(p->s.statsLock);
    char command[1024];
    ssize_t bytesRead;
    ssize_t totalBytes = 0;
    while ((bytesRead = read(clientFd, command + totalBytes, 
                    1024 - totalBytes)) > 0) {
        //Process client input here.
        totalBytes += bytesRead;
        for (int i = 0; i < totalBytes; i++) {
            if (command[i] == '\n') {
                process_command(clientFd, command, p);
                memset(command, 0, sizeof(command));
                totalBytes = 0;
                break;
            }
        }
        
    }
    //process_command(clientFd, command, p);
    //memset(command, 0, sizeof(command));
    printf("client disconnected.\n");
    sem_wait(p->s.statsLock);
    p->s.currentClientConnections -= 1;
    p->s.totalClients += 1;
    sem_post(p->s.statsLock);
    if (bytesRead < 0) {
        perror("error reading from socket in client thread.\n");
        exit(20);
    }

    close(clientFd);
    if (p->isLimited) {
        sem_post(p->connLock);
    }
    return NULL;
}

/* stats_thread()
 * ---------------
 * signal handling thread used to catch endless amounts of SIGHUP signals.
 * once signal is recived, a large collection of stats is printed out to
 * stderr and the program continues to operate.
 *
 * args: large struct that is shared across all client threads.
 *
 * REF: Usage of sigwait() taken from 'man pthead_sigmask(3)'.
 */
void* stats_thread(void* args) {
    struct Params* p = (struct Params*)args;
    int sig;
    while (1) {
        sigwait(&(p->s.set), &sig);
    
        fprintf(stderr, "Connected clients: %i\n", 
                p->s.currentClientConnections);
        fprintf(stderr, "Completed clients: %i\n", p->s.totalClients);
        fprintf(stderr, "Crack requests: %i\n", 
                p->s.totalCrackRequests);
        fprintf(stderr, "Failed crack requests: %i\n", 
                p->s.failedCrackRequests);
        fprintf(stderr, "Successful crack requests: %i\n", 
                p->s.passedCrackRequests);
        fprintf(stderr, "Crypt requests: %i\n", p->s.cryptRequests);
        fprintf(stderr, "crypt()/crypt_r() calls: %i\n", 
                p->s.encryptionRequests);
        fflush(stderr);
    }
}

/* stats_init()
 * ------------
 * Initalizes struct containing all of the statistics for the server.
 *
 * p: large struct that is shared across all threads. Used to store the stats
 *      struct inside of.
 *
 * REF: Usage of pthread_sigmask taken from example shown 
 * REF: on 'man pthread_sigmask(3)'.
 */
void stats_init(struct Params* p) {   
    sigemptyset(&(p->s.set));
    sigaddset(&(p->s.set), SIGHUP);
    pthread_sigmask(SIG_BLOCK, &(p->s.set), NULL);

    sem_t* statsLock = malloc(sizeof(sem_t));
    sem_init(statsLock, 0, 1);

    p->s.statsLock = statsLock;
    p->s.currentClientConnections = 0;
    p->s.totalClients = 0;
    p->s.totalCrackRequests = 0;
    p->s.failedCrackRequests = 0;
    p->s.passedCrackRequests = 0;
    p->s.cryptRequests = 0;
    p->s.encryptionRequests = 0;
}

/* process_connections()
 * ----------------------
 * main event loop for the server that repeatedly accepts client connections
 * to the server and then spawns a new client thread that will then handle the
 * client. 
 *
 * serverFd: file descriptor for the listening socket.
 * dict: data structure containing the filtered dicitonary to be used by the
 *      cracking functionallity.
 * connLimit: user defined limit to the simultaneous amount of clients
 *      connected. if the limit is 0 then there is no limit.
 * 
 * REF: Heavy inspiration for accepting client connections and thread creation
 * REF: from week10/server-multithreaded.c
 *
 * REF: usage of a multi-argument thread function taken from Lec 8/Page 33-35.
 */
void process_connections(int serverFd, char** dict, int connLimit) {
    int dictLen = 0;
    for (int i = 0; dict[i] != NULL; i++) {
        dictLen++;
    }

    int clientFd;
    struct sockaddr_in fromAddr;
    socklen_t fromAddrSize;
    sem_t* connectionLock = malloc(sizeof(sem_t));
    sem_init(connectionLock, 0, connLimit);
    struct Params* p = malloc(sizeof(struct Params));
    struct Stats s;
    memset(&s, 0, sizeof(s));
    p->s = s;
    stats_init(p);

    p->crackLock2 = malloc(sizeof(sem_t));
    sem_init(p->crackLock2, 0, 1);

    pthread_t statsThreadId;
    pthread_create(&statsThreadId, NULL, stats_thread, (void*)p);

    p->dictStr = dict;
    p->dictLen = dictLen;

    if (connLimit != 0) {
        p->connLock = connectionLock;
        p->isLimited = true;
    } else {
        p->isLimited = false;
        p->connLock = NULL;
    }
    //Main event loop
    while (1) {
        fromAddrSize = sizeof(struct sockaddr_in);
        clientFd = accept(serverFd, (struct sockaddr*)&fromAddr, 
                &fromAddrSize);
        if (p->isLimited) {
            sem_wait(p->connLock);
        }

        if (clientFd < 0) {
            perror("Error accepting connection");
            exit(10);
        }
        
        p->fd = clientFd;
        p->s.currentClientConnections += 1;

        pthread_t threadId;
        sem_wait(p->s.statsLock);

        pthread_create(&threadId, NULL, client_thread, (void*)p);
        pthread_detach(threadId);
    }
}

/* main()
 * -------
 * Main entry and exit for the functioning program.
 *
 * argc: number of command line arguments.
 * argv: command line arguments.
 *
 * Returns: 0 if the program runs sucsessfully.
 *
 * REF: Usage for all semaphores throughout the server taken from 
 * REF: week8/race3.c
 */
int main(int argc, char* argv[]) {
    command_line_validity(argc, argv);
    int connLimit = get_connect_lim(argc, argv);
    int port = get_port_num(argc, argv);
    char** dict = get_dict(argc, argv);

    int listenFd = begin_listen(port, connLimit);
    port_num(listenFd);
    process_connections(listenFd, dict, connLimit);
    return(0);
}














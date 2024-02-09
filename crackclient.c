
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <stdbool.h>

/* command_line_validity()
 * ------------------------
 * Combs through the command line arguments to determine its validity. If a 
 * jobfile is specified, it will be used as the command input for the client.
 *
 * argc: number of command line arguments.
 * argv: command line arguments.
 *
 * Returns: specified port number as a string.
 * Errors: If the command line arguments supplied are semantically incorrect,
 *      the program will exit with error code 1. If a jobFile is supplied, and
 *      it is unopenable, then the program will exit with error code 2.
 */
const char* command_line_validity(int argc, char* argv[]) {
    if (argc > 3 || argc < 2) {
        fprintf(stderr, "Usage: crackclient portnum [jobfile]\n");
        fflush(stderr);
        exit(1);
    }

    const char* port = argv[1];

    if (argc == 3) {
        char* jobfile = argv[2];
        FILE* jobStream = fopen(jobfile, "r");
        if (!jobStream) {
            fprintf(stderr, "%s%c%s%c%c",
                    "crackclient: unable to open job file ", '"',
                    jobfile, '"', '\n');
            fflush(stderr);
            exit(2);
        }
        fclose(jobStream);
    }
    return port;
}

/* job_stream()
 * -------------
 * Combs through the command line arguments for a given job file if supplied.
 *
 * argc: number of command line arguments.
 * argv: command line arguments.
 *
 * Returns: A file stream pointing to either the standard input stream or the 
 *      given job file.
 */
FILE* job_stream(int argc, char* argv[]) {
    if (argc == 3) {
        FILE* jobFile = fopen(argv[2], "r");
        return jobFile;
    }
    return stdin;
}

char* read_line(FILE* stream) {
	  char* line = NULL;
	  size_t bufsize = 0;
	  ssize_t characters = getline(&line, &bufsize, stream);
	  if (characters == -1){
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

/* connection()
 * -------------
 * Uses the given port number to open a client socket and then connects to a
 * server listening on the same port.
 *
 * port: given port number from the command line.
 *
 * Returns: file descriptor of the opened socket.
 * Errors: If the client cannot connect to the server using the given port
 *      the client program will exit with error code 3.
 */
int connection(const char* port) {
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo("localhost", port, &hints, &ai);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, ai->ai_addr, sizeof(struct sockaddr))) { 
        fprintf(stderr, "%s%s\n", "crackclient: unable to connect to port ", 
                port);
        fflush(stderr);
        exit(3);
    }
    return fd;
}

/* server_response()
 * ------------------
 * Takes a response written from the connected server and sorts through and
 * prints the appropriate message.
 *
 * rawResponse: raw text being read from the server.
 *
 * Returns: response to user from the client.
 */
char* server_response(char* rawResponse) {
    if (!strcmp(rawResponse, ":invalid")) {
        return "Error in command";
    }

    if (!strcmp(rawResponse, ":failed")) {
        return "Unable to decrypt";
    }

    return rawResponse;
}

/* event_loop()
 * ------------
 * Main event loop for the client that repeatedly waits for commands to send
 * to the connected server and recieve a response.
 *
 * jobStream: File stream pointing to the stream that the input is going to be
 *      taken from.
 * fd: file descriptor for the connected server.
 * 
 * Errors: If the server has terminated its connection to the client, the 
 *      client will exit with error code 4.
 */
void event_loop(FILE* jobStream, int fd) {
    int fd2 = dup(fd);
    FILE* toServer = fdopen(fd, "w");
    FILE* fromServer = fdopen(fd2, "r");

    char* command;
    char* response;
    bool eofDetected = false;

    while (!eofDetected) {

        command = read_line(jobStream);
        fflush(jobStream);
        if (!command) {
            eofDetected = true;
            break;
        }
        if (command[0] == '#' || command[0] == '\0') {
            continue;
        }
        fprintf(toServer, "%s\n", command);
        fflush(toServer);

        response = read_line(fromServer);
        if (!response) {
            fprintf(stderr, "crackclient: server connection terminated\n");
            fflush(stderr);
            exit(4);
        }
        printf("%s\n", server_response(response));
        fflush(fromServer);
    }

    fclose(toServer);
    fclose(fromServer);
    close(fd);
    close(fd2);
}

int main(int argc, char* argv[]) {
    const char* port = command_line_validity(argc, argv);
    int fd = connection(port);
    event_loop(job_stream(argc, argv), fd);
    return 0;
}

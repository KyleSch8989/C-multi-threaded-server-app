# A multi-threaded C server with encryption and decryption capabilities.

**CrackServer:** Networked Passphrase Cracking Tool
**CrackServer** is a network server designed to accept connections from clients, including **CrackClient** which is to be implemented as part of this project. The server's primary function is to receive encrypted passphrases from clients and attempt to crack them, thereby recovering the original unencrypted passphrase. Additionally, clients have the option to request the server to encrypt passwords for later analysis.

Communication between CrackClient and CrackServer is established over TCP using a newline-terminated text command protocol, ensuring efficient and reliable data transfer.

## Key Features:  
**Passphrase Cracking:** The server is capable of decrypting passphrases provided by clients, aiding in password recovery.  
  
**Encryption Service:** Clients can request the server to encrypt passwords for secure storage or analysis purposes.  
  
**TCP Communication:** Communication between the client and server is facilitated over TCP, ensuring robustness and reliability.  
  
**Advanced Functionality:** The server incorporates advanced features such as connection limiting, signal handling, and statistics reporting for enhanced usability and performance.  

## Usage:
1. **Start the server:** Run the '**crackserver**' program to initiate the server.  
   Commandline args: ./crackserver [--maxconn connections] [--port portnum] [--dictionary filename]
     - connections: max number of client connections. No maximum by default.
     - portnum: port number for connection as ip is set as localhost. Random number >5000 by default.
     - filename: a path to a file containing all valid words. /usr/share/dict/words by defualt.
3. **Connect as a client:** Run the '**crackclient**' program with the specific commandline args to connect to the right server.
   Commandline args: ./crackclient portnum [inputfile]
4. Once connected to the server, the client can either choose to send 'crypt' or 'crack' requests to the server in the following form:  
  crypt: 'crypt "plaintext" "salt"'  
  crack: 'crack "cyphertext" [number of requested threads for bruteforce cracking]'

## Getting started: LINUX
To get started on your own please follow the steps provided.
1. Clone this repository into your local Linux machine.
2. Build the two files using the 'make' command from the given makefile.

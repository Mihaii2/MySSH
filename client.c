#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "common_functions.h"

#define CHUNK_SIZE 4096
typedef unsigned long long ull;

int connect_server(int port) {
    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Failed to create socket");
        return 1;
    }

    // Server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Failed to connect to server");
        return 1;
    }
    return sockfd;
}

int authenticate_user(int sockfd, int shared_secret_key) {
    printf("Enter username and password in the following format: <username>:<password>\n");
    while(1) {
        char buf[1000];
        memset(buf, 0, sizeof(buf));
        
        // read username and password from stdin
        fgets(buf, sizeof(buf), stdin);

        encrypt_and_send(buf, sockfd, shared_secret_key, strlen(buf));

        // receive answer from server
        char answer[1000];
        memset(answer, 0, sizeof(answer));
        
        if(read_and_decrypt(sockfd, answer, shared_secret_key) == CONN_TERMINATED) {
            printf("Connection terminated\n");
            exit(1);
        }
        
        if(strcmp(answer, "User authenticated") == 0) {
            return 0;
        }
        printf("Answer: %s\n", answer);
    }
    return 0;
}

int Diffie_Hellman(int sockfd) {

    // Generate public key
    srand(time(NULL) + getpid());
    int base = 2;
    int modulus = 990366163;
    int private_key = rand() % modulus;
    int public_key = (int)powerModulo((ull)base, (ull)private_key, (ull)modulus);

    network_send_integer(sockfd, public_key);

    // Receive public key from the server
    int partner_public_key = network_receive_integer(sockfd);

    // Calculate shared secret
    int shared_secret_key = powerModulo(partner_public_key, private_key, modulus);

    return shared_secret_key;
}

int main(int argc, char** argv) {

    if(argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);

    int sockfd = connect_server(port);

    int shared_secret_key = Diffie_Hellman(sockfd);

    authenticate_user(sockfd, shared_secret_key);

    printf("Authentication successful\n");
    while(1) {
        char command[1024];

        // read command from stdin
        printf("Enter command: ");
        fgets(command, sizeof(command), stdin);
        // remove newline from command
        command[strlen(command) - 1] = '\0';

        encrypt_and_send(command, sockfd, shared_secret_key, strlen(command));

        // receive answer from server
        char answer_chunk[CHUNK_SIZE + 1000];
        memset(answer_chunk, 0, sizeof(answer_chunk));

        while(1) {
            if(read_and_decrypt(sockfd, answer_chunk, shared_secret_key) == CONN_TERMINATED) {
                printf("Connection terminated\n");
                exit(1);
            }
            if(strcmp(answer_chunk, "##MESSAGE_END##") == 0) {
                break;
            }
            printf("%s", answer_chunk);
            memset(answer_chunk, 0, sizeof(answer_chunk));

            encrypt_and_send("ACK", sockfd, shared_secret_key, strlen("ACK"));
        }

    }
    return 0;
}
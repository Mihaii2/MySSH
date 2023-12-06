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

#define CHUNK_SIZE 4096
typedef unsigned long long ull;

int read_command(int sockfd, char* buffer, int buf_size) {
    int codRead = 0, total_bytes = 0;

    while(codRead = read(sockfd, buffer + total_bytes, buf_size - total_bytes)) {
        if(codRead < 0) {
            perror("Error at read in thread:");
            exit(1);
        }

        total_bytes = strlen(buffer);
        if(buffer[total_bytes - 1] == '\n') {
            break;
        }
    }
    if(codRead == 0) {
        //client closed connection, close client sockfd and end thread
        printf("Client with fd %d closed connection\n", sockfd);
        return -1;
    }
}

void network_send_integer(int sockfd, int integer) {
    int network_integer = htonl(integer);
    if (send(sockfd, &network_integer, sizeof(network_integer), 0) == -1) {
        perror("Failed to send integer");
        exit(EXIT_FAILURE);
    }
}

int network_receive_integer(int sockfd) {
    int network_integer;
    if (recv(sockfd, &network_integer, sizeof(network_integer), 0) == -1) {
        perror("Failed to receive integer");
        exit(EXIT_FAILURE);
    }
    return ntohl(network_integer);

}

int accept_connection() {
    
}


int create_socket(int port, struct sockaddr_in* address_ptr) {
    int server_fd;
    int opt = 1;
    
    int addrlen = sizeof(*address_ptr);

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    (*address_ptr).sin_family = AF_INET;
    (*address_ptr).sin_addr.s_addr = INADDR_ANY;
    (*address_ptr).sin_port = htons(port);

    // Bind the socket to the specified address and port
    if (bind(server_fd, (struct sockaddr *)&(*address_ptr), sizeof((*address_ptr))) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}


// Function to calculate power modulo
int powerModulo(ull base, ull exponent, ull modulus) {
    ull result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % modulus;

        exponent = exponent / 2;
        base = (base * base) % modulus;
    }

    return (int)result;
}

void xor_encrypt_decrypt(char* data, int key) {
    size_t len = strlen(data);

    for (size_t i = 0; i < len; ++i) {
        data[i] = data[i] ^ ((char)key);

        // rotate key
        int right = key >> 8;
        int left = ((char)key) << 24;
        key = right | left;
    }
}

int Diffie_Hellman(int sockfd) {
    
    // Generate public key
    srand(time(NULL) + 1);
    int base = 2;
    int modulus = 990366163;
    int private_key = rand() % modulus;
    printf("Private key: %d\n", private_key);
    printf("Base: %d\n", base);
    printf("Modulus: %d\n", modulus);
    int public_key = (int)powerModulo((ull)base, (ull)private_key, (ull)modulus);

    printf("Sending public key: %d\n", public_key);
    network_send_integer(sockfd, public_key);


    // Receive public key from the server
    int partner_public_key = network_receive_integer(sockfd);
    

    // Calculate shared secret
    int shared_secret_key = powerModulo(partner_public_key, private_key, modulus);

    return shared_secret_key;
}

void client_handler(int sockfd) {
    int shared_secret_key = Diffie_Hellman(sockfd);
    printf("Shared secret: %d\n", shared_secret_key);

    while(1) {
        char buffer[1000];
        memset(buffer, 0, 1000);
        // if(read_command(sockfd, buffer, 1000) == -1) {
        //     // Client closed connection
        //     close(sockfd);
        //     return;
        // }
        int codRead = recv(sockfd, buffer, 1000, 0);
        if(codRead == 0) {
            printf("Client disconnected\n");
            break;
        }
        else if(codRead == -1) {
            perror("Failed to read from socket");
            exit(EXIT_FAILURE);
        }

        printf("Received encrypted command: %s\n", buffer);

        xor_encrypt_decrypt(buffer, shared_secret_key);

        printf("Decrypted command: %s", buffer); 
        // Send the message back to client

        xor_encrypt_decrypt(buffer, shared_secret_key);
        printf("Sending: %s\n", buffer);

        send(sockfd, buffer, strlen(buffer), 0);


    }
}

int main(int argc, char** argv)
{
    if(argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in address;
    int client, addrlen = sizeof(address), port = atoi(argv[1]);

    int server_fd = create_socket(port, &address);

    while (1)
    {
        // Accept a new connection
        if ((client = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
        {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        // Fork a new process to handle the client connection
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork failed");
            exit(EXIT_FAILURE);
        }
        else if (pid == 0)
        {
            // Child process
            close(server_fd);

            client_handler(client);

            exit(0);
        }
    }
    return 0;
}


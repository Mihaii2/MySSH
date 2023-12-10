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
#include <pthread.h>

#define CHUNK_SIZE 4096
typedef unsigned long long ull;

unsigned int calculate_hash(const char* str) {
    unsigned int hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // djb2 hash algorithm
    }

    return hash;
}

void insert_hash(char* command, int hash) {
    int network_hash = htonl(hash);
    memcpy(command + strlen(command), &network_hash, sizeof(network_hash));
}

int extract_and_remove_hash(char* command, int encrypted_content_size) {
    int hash;
    memcpy(&hash, command + encrypted_content_size - sizeof(int), sizeof(int));
    memset(command + encrypted_content_size - sizeof(int), 0, sizeof(int));
    return ntohl(hash);
}

void send_encrypted_msg(int sockfd, char* command, int cmd_len) {
    if(-1 == write(sockfd, command, cmd_len)) {
        perror("Failed to write command");
        exit(EXIT_FAILURE);
    }
}

int read_encrypted_msg(int sockfd, char* buffer, int buf_size) {
    int codRead = 0, total_bytes = 0;
    // read message length(from begginning of buffer)
    while(total_bytes < sizeof(int)) {
        codRead = read(sockfd, buffer + total_bytes, sizeof(int) - total_bytes);
        if(codRead < 0) {
            perror("Failed at read():");
            exit(1);
        }
        total_bytes += codRead;
    }
    int msg_len = ntohl(*(int*)buffer);

    // read rest of message
    while(total_bytes < msg_len + sizeof(int)) {
        codRead = read(sockfd, buffer + total_bytes, msg_len + sizeof(int) - total_bytes);
        if(codRead < 0) {
            perror("Failed at read():");
            exit(1);
        }
        total_bytes += codRead;
        if(codRead == 0) {
            printf("Partner closed connection\n");
            return -1;
        }
    }
    return total_bytes;
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
    int total_bytes = 0;
    while(total_bytes < sizeof(int)) {
        int codRead = read(sockfd, &network_integer + total_bytes, sizeof(int) - total_bytes);
        if(codRead < 0) {
            perror("Failed at read():");
            exit(1);
        }
        total_bytes += codRead;
    }

    return ntohl(network_integer);
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
    srand(time(NULL) + getpid());
    int base = 2;
    int modulus = 990366163;
    int private_key = rand() % modulus;
    printf("Private key: %d\n", private_key);
    printf("Base: %d\n", base);
    printf("Modulus: %d\n", modulus);
    int public_key = (int)powerModulo((ull)base, (ull)private_key, (ull)modulus);

    printf("Sending public key: %d\n", public_key);
    network_send_integer(sockfd, public_key);

    // Receive public key from the client
    int partner_public_key = network_receive_integer(sockfd);
    

    // Calculate shared secret
    int shared_secret_key = powerModulo(partner_public_key, private_key, modulus);

    return shared_secret_key;
}

void* client_handler(void* arg) {
    int sockfd = *((int*)arg);
    int shared_secret_key = Diffie_Hellman(sockfd);
    printf("Shared secret: %d\n", shared_secret_key);

    while(1) {
        char full_message[1000];
        char* encrypted_content = full_message + sizeof(int);
        int buf_size = sizeof(full_message);
        int encrypted_content_size, bytes_read;
        int non_encrypted_content_size = sizeof(int);
        memset(full_message, 0, 1000);

        // read encrypted message from client
        if((bytes_read = read_encrypted_msg(sockfd, full_message, 1000)) == -1) {
            // Client closed connection
            close(sockfd);
            pthread_exit(NULL);
        }

        // encrypted content size is full message size - size of integer(message length)
        encrypted_content_size = bytes_read - sizeof(int);

        // decrypt message
        xor_encrypt_decrypt(encrypted_content, shared_secret_key);

        int received_hash = extract_and_remove_hash(encrypted_content, encrypted_content_size);

        // calculate hash
        int hash = calculate_hash(encrypted_content);

        // compare hashes
        if(hash != received_hash) {
            printf("Connection compromised. Something is modifying your messages\n");
            close(sockfd);
            pthread_exit(NULL);
        }

        printf("Received: %s", encrypted_content);

        // insert hash at the end of string
        insert_hash(encrypted_content, hash);

        // encrypt and send the message back to client
        xor_encrypt_decrypt(encrypted_content, shared_secret_key);

        int full_length = encrypted_content_size + non_encrypted_content_size;

        printf("Sending: %s\n", encrypted_content);
        send_encrypted_msg(sockfd, full_message , full_length);

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

        // Create a new thread to handle the client connection
        pthread_t tid;
        int* arg = (int*)malloc(sizeof(int));
        *arg = client;

        if (pthread_create(&tid, NULL, client_handler, (void*)arg) != 0) {
            perror("pthread_create failed");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}
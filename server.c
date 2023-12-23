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
#include <jansson.h>
#include "common_functions.h"

#define CHUNK_SIZE 4096
#define USER_NOT_FOUND 1
typedef unsigned long long ull;

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

int authenticate_user(const int sockfd, const int shared_secret_key) {
    char user_info[1000];
    memset(user_info, 0, sizeof(user_info));

    read_and_decrypt(sockfd, user_info, shared_secret_key);

    char username[100], password[100];
    memset(username, 0, sizeof(username));
    memset(password, 0, sizeof(password));

    // extract username and password from message
    sscanf(user_info, "%[^:]:%s", username, password);

    // check if username and password exist in the json file
    json_t *root;
    json_error_t error;

    root = json_load_file("users.json", 0, &error);
    if(!root) {
        printf("Error loading json file: %s\n", error.text);
        exit(EXIT_FAILURE);
    }

    // search the username in the json file
    json_t *users, *user;
    size_t index;
    users = root;

    if(!json_is_array(users)) {
        printf("Root element is not an array\n");
        exit(EXIT_FAILURE);
    }

    json_array_foreach(users, index, user) {
        const char *username_str = json_string_value(json_object_get(user, "username"));
        if (strcmp(username, username_str) == 0) {
            // Found the user, check if password is correct
            const char *password_str = json_string_value(json_object_get(user, "password"));

            if(strcmp(password, password_str) == 0) {
                json_decref(root);
                break;
            } else {
                json_decref(root);
                return USER_NOT_FOUND;
            }
            
        }
    }

    if(index == json_array_size(users)) {
        // username not found
        json_decref(root);
        return USER_NOT_FOUND;
    }

    json_decref(root);
    encrypt_and_send("User authenticated", sockfd, shared_secret_key, strlen("User authenticated"));

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

    // Receive public key from the client
    int partner_public_key = network_receive_integer(sockfd);
    

    // Calculate shared secret
    int shared_secret_key = powerModulo(partner_public_key, private_key, modulus);

    return shared_secret_key;
}

void* client_handler(void* arg) {
    int sockfd = *((int*)arg);
    int shared_secret_key = Diffie_Hellman(sockfd);

    while(USER_NOT_FOUND == authenticate_user(sockfd, shared_secret_key)) {
        encrypt_and_send("User not found.", sockfd, shared_secret_key, strlen("User not found."));
        printf("User not found. Try again\n");
    }
    printf("User authenticated\n");

    while(1) {
        char client_command[1024];
        memset(client_command, 0, sizeof(client_command));

        if(CONN_TERMINATED == read_and_decrypt(sockfd, client_command, shared_secret_key)) {
            // partner closed connection
            close(sockfd);
            free(arg);
            pthread_detach(pthread_self());
            pthread_exit(NULL);
        }


        // use popen to execute the command and redirect stderr to stdout for the command so the client can receive the error message
        char client_command_with_error_redirection[1030];
        sprintf(client_command_with_error_redirection, "%s 2>&1", client_command);
        FILE* fp = popen(client_command_with_error_redirection, "r");

        if(fp == NULL) {
            perror("Failed to execute command");
            exit(EXIT_FAILURE);
        }

        char output[CHUNK_SIZE + 1000];
        memset(output, 0, sizeof(output));
        int bytes_read;

        while((bytes_read = fread(output, 1, CHUNK_SIZE, fp)) > 0) {
            encrypt_and_send(output, sockfd, shared_secret_key, bytes_read);
            memset(output, 0, sizeof(output));

            // wait for client to receive the message
            char ack[100];
            memset(ack, 0, sizeof(ack));
            read_and_decrypt(sockfd, ack, shared_secret_key);
            if(strcmp(ack, "ACK") != 0) {
                printf("Client did not send ACK\n");
                exit(EXIT_FAILURE);
            }
        }
        encrypt_and_send("##MESSAGE_END##", sockfd, shared_secret_key, strlen("##MESSAGE_END##"));
    }
}

int main(int argc, char** argv) {
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
        if ((client = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
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
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

#define CHUNK_SIZE 4096
#define USER_NOT_FOUND 1
typedef unsigned long long ull;

void shift_and_insert_msg_len(char* command, int msg_len) {
    //shift command to the right by sizeof(int) bytes
    memmove(command + sizeof(int), command, msg_len);
    
    int network_msg_len = htonl(msg_len);
    memcpy(command, &network_msg_len, sizeof(network_msg_len));
}

void send_socket_msg(const int sockfd, const char* buffer, const int buf_len) {
    if(-1 == write(sockfd, buffer, buf_len)) {
        perror("Failed to write buffer");
        exit(EXIT_FAILURE);
    }
}

int read_socket_msg(int sockfd, char* buffer, int buf_size) {
    int codRead = 0, total_bytes = 0;
    // read message length(from begginning of buffer)
    while(total_bytes < sizeof(int)) {
        codRead = read(sockfd, buffer + total_bytes, sizeof(int) - total_bytes);
        if(codRead < 0) {
            perror("Failed at read():");
            exit(1);
        }
        if(codRead == 0) {
            printf("Partner closed connection\n");
            return -1;
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

void encrypt_and_send(const char* const msg, const int sockfd, const int shared_secret_key, const int msg_len) {
    char buffer[CHUNK_SIZE + 1000];
    int buf_size = sizeof(buffer);
    memset(buffer, 0, buf_size);
    memcpy(buffer, msg, msg_len);

    int encrypted_content_size;
    encrypted_content_size = msg_len;

    xor_encrypt_decrypt(buffer, shared_secret_key);

    // insert length at the start of string
    shift_and_insert_msg_len(buffer, encrypted_content_size);
    int non_encrypted_content_size = sizeof(int);

    // length of message to be sent through socket
    int full_length = encrypted_content_size + non_encrypted_content_size;
    
    // send full message to server
    send_socket_msg(sockfd, buffer, full_length);
}

void read_and_decrypt(const int sockfd, char* output_buffer, const int shared_secret_key) {
    char buffer[CHUNK_SIZE + 1000];
    int bytes_read;
    char* encrypted_content = buffer + sizeof(int);
    int encrypted_content_size, non_encrypted_content_size = sizeof(int);
    memset(buffer, 0, sizeof(buffer));

    // read encrypted message from client
    if((bytes_read = read_socket_msg(sockfd, buffer, 1000)) == -1) {
        // Client closed connection
        close(sockfd);
        pthread_exit(NULL);
    }

    // encrypted content size is full message size - size of integer(message length at the beggining of message is not encrypted)
    encrypted_content_size = bytes_read - sizeof(int);

    // decrypt message
    xor_encrypt_decrypt(encrypted_content, shared_secret_key);

    memcpy(output_buffer, encrypted_content, encrypted_content_size);
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

        read_and_decrypt(sockfd, client_command, shared_secret_key);


        // use popen to execute the command and redirect stderr to stdout for the command
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
}#include <sys/types.h>
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

#define CHUNK_SIZE 50
#define USER_NOT_FOUND 1
typedef unsigned long long ull;

void shift_and_insert_msg_len(char* command, int msg_len) {
    //shift command to the right by sizeof(int) bytes
    memmove(command + sizeof(int), command, msg_len);
    
    int network_msg_len = htonl(msg_len);
    memcpy(command, &network_msg_len, sizeof(network_msg_len));
}

void send_socket_msg(const int sockfd, const char* buffer, const int buf_len) {
    if(-1 == write(sockfd, buffer, buf_len)) {
        perror("Failed to write buffer");
        exit(EXIT_FAILURE);
    }
}

int read_socket_msg(int sockfd, char* buffer, int buf_size) {
    int codRead = 0, total_bytes = 0;
    // read message length(from begginning of buffer)
    while(total_bytes < sizeof(int)) {
        codRead = read(sockfd, buffer + total_bytes, sizeof(int) - total_bytes);
        if(codRead < 0) {
            perror("Failed at read():");
            exit(1);
        }
        if(codRead == 0) {
            printf("Partner closed connection\n");
            return -1;
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

void encrypt_and_send(const char* const msg, const int sockfd, const int shared_secret_key, const int msg_len) {
    char buffer[CHUNK_SIZE + 1000];
    int buf_size = sizeof(buffer);
    memset(buffer, 0, buf_size);
    memcpy(buffer, msg, msg_len);

    int encrypted_content_size;
    encrypted_content_size = msg_len;

    xor_encrypt_decrypt(buffer, shared_secret_key);

    // insert length at the start of string
    shift_and_insert_msg_len(buffer, encrypted_content_size);
    int non_encrypted_content_size = sizeof(int);

    // length of message to be sent through socket
    int full_length = encrypted_content_size + non_encrypted_content_size;
    
    // send full message to server
    send_socket_msg(sockfd, buffer, full_length);
}

void read_and_decrypt(const int sockfd, char* output_buffer, const int shared_secret_key) {
    char buffer[CHUNK_SIZE + 1000];
    int bytes_read;
    char* encrypted_content = buffer + sizeof(int);
    int encrypted_content_size, non_encrypted_content_size = sizeof(int);
    memset(buffer, 0, sizeof(buffer));

    // read encrypted message from client
    if((bytes_read = read_socket_msg(sockfd, buffer, 1000)) == -1) {
        // Client closed connection
        close(sockfd);
        pthread_exit(NULL);
    }

    // encrypted content size is full message size - size of integer(message length at the beggining of message is not encrypted)
    encrypted_content_size = bytes_read - sizeof(int);

    // decrypt message
    xor_encrypt_decrypt(encrypted_content, shared_secret_key);

    memcpy(output_buffer, encrypted_content, encrypted_content_size);
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

        read_and_decrypt(sockfd, client_command, shared_secret_key);


        // use popen to execute the command and redirect stderr to stdout for the command
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
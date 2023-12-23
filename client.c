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

void shift_and_insert_msg_len(char* command, int msg_len) {
    //shift command to the right by sizeof(int) bytes
    memmove(command + sizeof(int), command, msg_len);
    
    int network_msg_len = htonl(msg_len);
    memcpy(command, &network_msg_len, sizeof(network_msg_len));
}

int calculate_hash(const char* str) {
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

void send_socket_msg(int sockfd, char* command, int cmd_len) {
    

    if(-1 == write(sockfd, command, cmd_len)) {
        perror("Failed to write command");
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
    if (write(sockfd, &network_integer, sizeof(network_integer)) == -1) {
        perror("Failed to write integer");
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



// Function to calculate power modulo (Using exponentiation by squaring)
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

void encrypt_and_send(const char* const message, const int sockfd, const int shared_secret_key) {
    char buffer[CHUNK_SIZE + 1000];
    int buf_size = sizeof(buffer);
    memset(buffer, 0, buf_size);
    memcpy(buffer, message, strlen(message));

    int encrypted_content_size;
    encrypted_content_size = strlen(message);

    // calculate hash of command
    int hash = calculate_hash(buffer);

    // insert hash at the end of string 
    insert_hash(buffer, hash);
    
    // increase size of encrypted content to include hash
    encrypted_content_size += sizeof(int);

    // encrypt content
    
    xor_encrypt_decrypt(buffer, shared_secret_key);

    // insert length at the start of string
    shift_and_insert_msg_len(buffer, encrypted_content_size);
    int non_encrypted_content_size = sizeof(int);

    // length of message to be sent through socket
    int full_length = encrypted_content_size + non_encrypted_content_size;

    // send full message to server
    send_socket_msg(sockfd, buffer, full_length);
}

int authenticate_user(int sockfd, int shared_secret_key) {
    char buf[1000];
    
    // read username and password from stdin
    printf("Enter username and password in the following format: <username>:<password>\n");
    fgets(buf, sizeof(buf), stdin);

    encrypt_and_send(buf, sockfd, shared_secret_key);


    // receive answer from server
    char full_answer[1000];
    char* encrypted_answer_content = full_answer + sizeof(int);
    memset(full_answer, 0, sizeof(full_answer));
    int msg_length = read_socket_msg(sockfd, full_answer, 1000);
    int encrypted_content_size = msg_length - sizeof(int);

    // decrypt answer
    xor_encrypt_decrypt(encrypted_answer_content, shared_secret_key);

    // calculate hash of answer
    int received_hash = extract_and_remove_hash(encrypted_answer_content, msg_length - sizeof(int));

    encrypted_content_size -= sizeof(int);

    int calculated_hash = calculate_hash(encrypted_answer_content);

    if(received_hash != calculated_hash) {
        printf("Connection compromised. Something is modifying your messages\n");
        close(sockfd);
        return 1;
    }

    printf("Answer: %s", encrypted_answer_content);

    return 0;
}

int Diffie_Hellman(int sockfd) {
    
    // Generate public key
    srand(time(NULL));
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

int main(int argc, char** argv) {

    if(argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }
    int port = atoi(argv[1]);

    int sockfd = connect_server(port);

    int shared_secret_key = Diffie_Hellman(sockfd);

    printf("Shared secret: %d\n", shared_secret_key);

    // TODO - implement server-client authentication

    if(authenticate_user(sockfd, shared_secret_key) == -1) {
        printf("Authentication failed. Terminating process.\n");
        close(sockfd);
        return 1;
    }

    printf("Authentication successful\n");
    while(1) {
        char buf[1000];

        // read command from stdin
        printf("Enter command: ");
        fgets(buf, sizeof(buf), stdin);

        encrypt_and_send(buf, sockfd, shared_secret_key);

        // receive answer from server
        char full_answer[1000];
        char* encrypted_answer = full_answer + sizeof(int);
        memset(full_answer, 0, sizeof(full_answer));
        int msg_len = read_socket_msg(sockfd, full_answer, 1000);
        int encrypted_content_size = msg_len - sizeof(int);

        // decrypt answer
        xor_encrypt_decrypt(encrypted_answer, shared_secret_key);

        // calculate hash of answer
        int received_hash = extract_and_remove_hash(encrypted_answer, encrypted_content_size);

        encrypted_content_size -= sizeof(int);

        int calculated_hash = calculate_hash(encrypted_answer);

        if(received_hash != calculated_hash) {
            printf("Connection compromised. Something is modifying your messages\n");
            close(sockfd);
            return 1;
        }

        printf("Answer: %s", encrypted_answer);
        printf("Size of answer: %ld\n", strlen(encrypted_answer)); 
    }
    
    return 0;
}
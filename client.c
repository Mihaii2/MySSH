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

typedef unsigned long long ull;

void insert_msg_len(char* command, int msg_len) {
    int network_msg_len = htonl(msg_len);
    memcpy(command, &network_msg_len, sizeof(network_msg_len));
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

    while(1) {
        char full_command[1000];
        char* encrypted_content = full_command + sizeof(int);
        int cmd_buf_size = sizeof(full_command);
        memset(full_command, 0, cmd_buf_size);

        fgets(encrypted_content, cmd_buf_size, stdin);
        
        // encrypt content
        xor_encrypt_decrypt(encrypted_content, shared_secret_key);

        insert_msg_len(full_command, strlen(encrypted_content));

        int cmd_len = strlen(encrypted_content) + sizeof(int);

        printf("Sending: %s\n", encrypted_content); 
        send_encrypted_msg(sockfd, full_command, cmd_len);        

        // receive result from server and print it
        char full_answer[1000];
        char* encrypted_answer = full_answer + sizeof(int);
        memset(full_answer, 0, sizeof(full_answer));


        read_encrypted_msg(sockfd, full_answer, 1000);

        // decrypt answer
        xor_encrypt_decrypt(encrypted_answer, shared_secret_key);
        printf("Answer: %s", encrypted_answer);
        printf("Size of answer: %d\n", strlen(encrypted_answer)); 


    }
    
    return 0;
}
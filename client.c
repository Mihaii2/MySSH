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

void send_encrypted_message(int sockfd, char* command, int cmd_len) {
    if(command[cmd_len - 1] != '\n') {
        command[cmd_len] = '\n';
    }
    command[cmd_len] = '\n';
    if(-1 == write(sockfd, command, strlen(command))) {
        perror("Failed to write command");
        exit(EXIT_FAILURE);
    }
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
    if (read(sockfd, &network_integer, sizeof(network_integer)) == -1) {
        perror("Failed to receive integer");
        exit(EXIT_FAILURE);
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
        while(data[i] == '\n') {
            data[i] = data[i] ^ ((char)key);
        }

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
        char command[1000];
        int cmd_len = sizeof(command);
        memset(command, 0, cmd_len);

        fgets(command, cmd_len, stdin);

        printf("Command: %s", command);
        
        // encrypt command
        xor_encrypt_decrypt(command, shared_secret_key);

        printf("Encrypted command: %s\n", command);

        // send_encrypted_message(sockfd, command, cmd_len);

        if(-1 == write(sockfd, command, strlen(command))) {
            perror("Failed to write command");
            exit(EXIT_FAILURE);
        }
        

        // receive result from server and print it
        char answer[1000];
        memset(answer, 0, strlen(answer));
        int codRead = read(sockfd, answer, sizeof(answer));
        if(codRead == 0) {
            printf("Server disconnected\n");
            break;
        }
        else if(codRead == -1) {
            perror("Failed to read from socket");
            exit(EXIT_FAILURE);
        }

        // decrypt answer
        xor_encrypt_decrypt(answer, shared_secret_key);
        printf("Answer: %s", answer);


    }
    
    return 0;
}
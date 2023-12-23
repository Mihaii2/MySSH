#include "common_functions.h" 

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

int read_and_decrypt(const int sockfd, char* output_buffer, const int shared_secret_key) {
    char buffer[CHUNK_SIZE + 1000];
    int bytes_read;
    char* encrypted_content = buffer + sizeof(int);
    int encrypted_content_size, non_encrypted_content_size = sizeof(int);
    memset(buffer, 0, sizeof(buffer));

    // read encrypted message from partner
    if((bytes_read = read_socket_msg(sockfd, buffer, 1000)) == -1) {
        close(sockfd);
        return CONN_TERMINATED;
    }

    // encrypted content size is full message size - size of integer(message length at the beggining of message is not encrypted)
    encrypted_content_size = bytes_read - sizeof(int);

    // decrypt message
    xor_encrypt_decrypt(encrypted_content, shared_secret_key);

    memcpy(output_buffer, encrypted_content, encrypted_content_size);
}
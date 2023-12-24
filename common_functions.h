#ifndef COMMON_FUNCTIONS_H
#define COMMON_FUNCTIONS_H

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned long long ull;
#define CHUNK_SIZE 4096
#define CONN_TERMINATED 2
#define USER_NOT_FOUND 1

void shift_and_insert_msg_len(char* command, int msg_len);
void send_socket_msg(const int sockfd, const char* buffer, const int buf_len);
int read_socket_msg(int sockfd, char* buffer, int buf_size);
void network_send_integer(int sockfd, int integer);
int network_receive_integer(int sockfd);
int powerModulo(ull base, ull exponent, ull modulus);
void xor_encrypt_decrypt(char* data, int key);
void encrypt_and_send(const char* const msg, const int sockfd, const int shared_secret_key, const int msg_len);
int read_and_decrypt(const int sockfd, char* output_buffer, const int shared_secret_key);

#endif
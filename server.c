
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

#define CHUNK_SIZE 4096

int main() {
    FILE *fp;
    char buffer[CHUNK_SIZE];
    size_t bytesRead;

    // Replace "your_command_here" with the actual command you want to execute
    const char *command = "cat /etc/passwd";

    // Open a pipe to the command for reading
    fp = popen(command, "r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    // Read and print output in chunks of 4KB
    do {
        bytesRead = fread(buffer, 1, sizeof(buffer), fp);

        // Process each chunk (4KB) of output
        if (bytesRead > 0) {
            fwrite(buffer, 1, bytesRead, stdout);
        }
    } while (bytesRead == sizeof(buffer));

    // Close the pipe
    if (pclose(fp) == -1) {
        perror("pclose");
        exit(EXIT_FAILURE);
    }

    return 0;
}
#include <stdio.h>
#include <string.h>

void xor_encrypt_decrypt(char* data, int key) {
    size_t len = strlen(data);

    for (size_t i = 0; i < len; ++i) {
        // XOR operation with the least significant byte of the key
        data[i] = data[i] ^ ((char)key);

        // Rotate key
        int right = key >> 8;
        int left = ((char)key) << 24;
        key = right | left;
    }
}

int main() {
    char message[] = "Hello, World!";
    int key = 0xABCD1234; // 32-bit key

    printf("Original Message: %s\n", message);

    // Encryption
    xor_encrypt_decrypt(message, key);
    printf("Encrypted Message: %s\n", message);

    // Decryption (using the same key)
    xor_encrypt_decrypt(message, key);
    printf("Decrypted Message: %s\n", message);

    return 0;
}
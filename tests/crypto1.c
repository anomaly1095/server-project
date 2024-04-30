#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h> // Include for malloc and free

#define SIZE_SALT 16

int main(int argc, const char **argv)
{
    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];
    uint8_t key[crypto_secretbox_KEYBYTES];
    uint8_t ss[SIZE_SALT];
    uint8_t c1[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES]; // Changed size
    uint8_t c2[crypto_box_SEALBYTES + SIZE_SALT]; // Changed size
    uint8_t buf[crypto_box_SEALBYTES + crypto_secretbox_KEYBYTES + crypto_box_SEALBYTES + SIZE_SALT]; // Changed size
    uint8_t res_key[crypto_secretbox_KEYBYTES];
    uint8_t res_ss[SIZE_SALT];
    const char *msg1 = "Hello world";
    size_t mlen = strlen(msg1);
    char *msg2 = (char*)malloc(mlen + 1); // Allocate memory for msg2
    if (msg2 == NULL) {
        printf("Memory allocation failed for msg2.\n");
        return 1;
    }
    uint8_t c3[mlen + crypto_secretbox_MACBYTES];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    
    //initiate crypto context
    if (sodium_init() == -1) {
        printf("Sodium initialization failed.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // generate asymmetric keys (server)
    if (crypto_box_keypair(pk, sk) != 0) {
        printf("Key pair generation failed.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // generate symmetric key (client)
    crypto_secretbox_keygen(key);
    // generate salt  (client)
    randombytes_buf(ss, SIZE_SALT);
    // encrypt symmetric key  (client)
    if (crypto_box_seal(c1, key, crypto_secretbox_KEYBYTES, pk) != 0) {
        printf("Sealing symmetric key failed.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // encrypt salt (client)
    if (crypto_box_seal(c2, ss, SIZE_SALT, pk) != 0) {
        printf("Sealing salt failed.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }

    // join both in buf (client)
    memcpy((void*)buf, (const void*)c1, sizeof c1);
    memcpy((void*)&buf[sizeof c1], (const void*)c2, sizeof c2);

    // decrypt symmetric key (server)
    if (crypto_box_seal_open(res_key, c1, sizeof c1, pk, sk) != 0) {
        printf("Failed to decrypt symmetric key.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // decrypt salt (server)
    if (crypto_box_seal_open(res_ss, c2, sizeof c2, pk, sk) != 0) {
        printf("Failed to decrypt salt.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // compare keys before encryption and after decryption
    if (!memcmp(res_key, key, sizeof key) || !memcmp(res_ss, ss, sizeof ss))
        printf("Identical keys\n");
    else
        printf("Keys do not match\n");

    // encrypt msg with key1
    if (crypto_secretbox_easy(c3, (uint8_t*)msg1, mlen, nonce, key)){
        printf("Failed to encrypt msg.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // decrypt msg with key2
    if (crypto_secretbox_open_easy((uint8_t*)msg2, c3, mlen + crypto_secretbox_MACBYTES, nonce, res_key)){
        printf("Failed to decrypt msg.\n");
        free(msg2); // Free dynamically allocated memory before exiting
        return 1;
    }
    // Null-terminate msg2
    msg2[mlen] = '\0';

    printf("%s\n", msg2);

    free(msg2); // Free dynamically allocated memory before exiting
    return 0;
}

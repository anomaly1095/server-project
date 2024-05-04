
#ifndef SECURITY_H
#define SECURITY_H      1
#include "threads.h"
//===============================================
//          ----SIZEOF AUTH STREAMS----
//===============================================


#define ENCRYPTED_KEY_SIZE crypto_secretbox_KEYBYTES + \
crypto_box_SEALBYTES

#define ENCRYPTED_NONCE_SIZE crypto_secretbox_NONCEBYTES + \
crypto_box_SEALBYTES

#define ENCRYPTED_AUTH_SIZE ENCRYPTED_NONCE_SIZE + \
ENCRYPTED_KEY_SIZE

typedef struct sec_keys
{
  uint8_t enc_key[ENCRYPTED_KEY_SIZE]; // size of asymmetrically encrypted symmetric key 
  uint8_t dec_key[crypto_secretbox_KEYBYTES];
  uint8_t enc_nonce[ENCRYPTED_NONCE_SIZE]; // size of asymmetrically encrypted symmetric key 
  uint8_t dec_nonce[crypto_secretbox_NONCEBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
}sec_keys_t;


/// @brief Initialize libsodium 
/// @return errorcode
errcode_t secu_init(void);

/// @brief generate asymmetric keypair and write to the database
/// @param db_connect MYSQL db connection
errcode_t secu_init_keys(MYSQL *db_connect);

/// @brief checks if password entered is same as in physkey (step 1 authentication)
/// @param pass command line argument entered password
errcode_t secu_check_init_cred(const uint8_t *pass);

/// @brief initialize pollfd structures for incoming data and fd = -1 so that they are ignored by poll
/// @param total_cli__fds all file descriptors available accross all threads
void net_init_clifd(pollfd_t **total_cli__fds);

/**
 * @brief Write the keys to the database.
 * 
 * This function writes the public key (pk) and secret key (sk) to the database.
 * 
 * @param pk Public key.
 * @param sk Secret key.
 * @param db_connect MYSQL database connection.
 * @return Error code indicating success or failure.
 */
errcode_t secu_key_save(uint8_t *pk, uint8_t *sk, MYSQL *db_connect);

/// @brief deletes current key pair present in the db KeyPairs table
/// @param db_connect MYSQL db connection
errcode_t secu_key_del(MYSQL *db_connect);

/**
 * @brief Encrypts a message 'm' of length 'mlen' using the public key 'pk' and stores the cipher in 'c'.
 * 
 * 
 * @param pk Public key.
 * @param c Buffer to contain the cipher.
 * @param m Message to encrypt.
 * @param mlen Length of the message to encrypt.
 * @return Error code indicating the success or failure of the encryption process.
 */
errcode_t secu_asymmetric_encrypt(const uint8_t *pk, uint8_t *c, const void *m, size_t mlen);

/**
 * @brief Decrypts a cipher 'c' of length 'clen' using the public key 'pk' and secret key 'sk', storing the result in 'm'.
 * 
 * 
 * @param pk Public key.
 * @param sk Secret key.
 * @param m Buffer to store the decrypted message.
 * @param c Cipher to decrypt.
 * @param clen Length of the cipher to decrypt.
 * @return Error code indicating the success or failure of the decryption process.
 */
errcode_t secu_asymmetric_decrypt(const uint8_t *pk, const uint8_t *sk, void *m, const uint8_t *c, size_t clen);

/**
 * @brief Encrypts a message 'm' of length 'mlen' using the symmetric key 'key' obtained from the client connection
 *  and the nonce set to him and stores the cipher in 'c'. This function does not use a nonce.
 * 
 * @param key Symmetric key obtained from the client connection.
 * @param n random nonce common between user and client.
 * @param c Buffer to contain the cipher.
 * @param m Message to encrypt.
 * @param mlen Length of the message to encrypt.
 * @return Error code indicating the success or failure of the encryption process.
 */
errcode_t secu_symmetric_encrypt(const uint8_t *key, const uint8_t *n, uint8_t *c, const void *m, size_t mlen);

/**
 * @brief Decrypts a cipher 'c' of length 'clen' using the symmetric key 'key' and the nonce set to the, storing the result in 'm'. This function does not use a nonce.
 * 
 * @param key Symmetric key specific to this connection.
 * @param n random nonce common between user and client.
 * @param m Buffer to store the decrypted message.
 * @param c Cipher to decrypt.
 * @param clen Length of the cipher to decrypt.
 * @return Error code indicating the success or failure of the decryption process.
 */
errcode_t secu_symmetric_decrypt(const uint8_t *key, const uint8_t *n, void *m, const uint8_t *c, size_t clen);


#endif

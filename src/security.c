#include "../include/security.h"

//===============================================
//      INITIALIZE + CHECK PASSPHRASE
//===============================================

/**
 * @brief Initialize libsodium library.
 * 
 * This function initializes the libsodium library.
 * 
 * @return Error code indicating the success or failure of the initialization.
 */
inline errcode_t secu_init(void)
{
  if (sodium_init() == -1)
    return LOG(SECU_LOG_PATH, ESODIUM_INIT, ESODIUM_INIT_M);
  return __SUCCESS__;
}

/**
 * @brief Read the authentication key from the physical key file.
 * 
 * This function reads the authentication key from the physical key file and stores it in the provided buffer.
 * 
 * @param c Buffer to store the ciphered for the authentication key.
 * @return Error code indicating the success or failure of the operation.
 */
static inline errcode_t get_auth_key(uint8_t *c)
{
  FILE *db_privf;
  
  if (!(db_privf = fopen(PATH_PHYSKEY, "rb")))
    return LOG(DB_LOG_PATH, E_FOPEN, E_FOPEN_M);
  
  if (fread((void*)c, 1, crypto_hash_sha512_BYTES, db_privf) < crypto_hash_sha512_BYTES)
    return LOG(DB_LOG_PATH, E_FREAD, E_FREAD_M);
  
  fclose(db_privf);
  return __SUCCESS__;
}

/**
 * @brief Check if the provided password is correct.
 * 
 * This function checks if the provided password is correct by comparing its hash with the stored authentication key.
 * 
 * @param pass Password entered by the user.
 * @return Error code indicating the success or failure of the operation.
 */
errcode_t secu_check_init_cred(const uint8_t *pass)
{
  uint8_t c1[crypto_hash_sha512_BYTES];
  uint8_t c2[crypto_hash_sha512_BYTES];
  
  if (crypto_hash_sha512(c1, pass, strlen(pass)))
    return LOG(SECU_LOG_PATH, E_SHA512, E_SHA512);
  
  if (get_auth_key(c2))
    return E_AUTHKEY;
  
  if (memcmp((const void*)c1, (const void*)c2, crypto_hash_sha512_BYTES) != 0)
    return LOG(SECU_LOG_PATH, E_WRONG_CREDS, E_WRONG_CREDS_M);
  
  return __SUCCESS__;
}

//===============================================
//      ASYMMETRIC KEY GENERATION
//===============================================

/**
 * @brief Generate asymmetric keypair and write it to the database.
 * 
 * This function generates an asymmetric keypair, consisting of a public key and a secret key,
 * and writes them to the database.
 * 
 * @param db_connect MYSQL database connection.
 * @return Error code indicating the success or failure of the key generation and saving process.
 */
errcode_t secu_init_keys(MYSQL *db_connect)
{
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];

  if (crypto_box_keypair(pk, sk))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(sk, crypto_box_SECRETKEYBYTES);
    return LOG(SECU_LOG_PATH, EKEYPAIR_GEN, EKEYPAIR_GEN_M);
  }
  if (secu_key_del(db_connect))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(sk, crypto_box_SECRETKEYBYTES);
    return LOG(SECU_LOG_PATH, EKEYPAIR_DEL, EKEYPAIR_DEL_M);
  }
  if (secu_key_save(pk, sk, db_connect))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(sk, crypto_box_SECRETKEYBYTES);
    return LOG(SECU_LOG_PATH, EKEYPAIR_SAVE, EKEYPAIR_SAVE_M);
  }
  bzero(pk, crypto_box_PUBLICKEYBYTES);
  bzero(sk, crypto_box_SECRETKEYBYTES);
  return __SUCCESS__;
}


//===========================================================================================================
//                SECURITY: ENCRYPTION DECRYPTION WITH ASYMMETRIC CRYPTOS
//===========================================================================================================

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
inline errcode_t secu_asymmetric_encrypt(const uint8_t *pk, uint8_t *c, const void *m, size_t mlen)
{
  const uint8_t *__m = (const uint8_t *)m;
  if (crypto_box_seal(c, __m, mlen, pk))
    return LOG(SECU_LOG_PATH, E_ASYMM_ENCRYPT, E_ASYMM_ENCRYPT_M);
  return __SUCCESS__;
}

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
inline errcode_t secu_asymmetric_decrypt(const uint8_t *pk, const uint8_t *sk, void *m, const uint8_t *c, size_t clen)
{
  uint8_t *__m = (uint8_t *)m;
  if (crypto_box_seal_open(__m, c, clen, pk, sk))
    return LOG(SECU_LOG_PATH, E_ASYMM_DECRYPT, E_ASYMM_DECRYPT_M);
  return __SUCCESS__;
}


//===========================================================================================================
//                SECURITY: ENCRYPTION DECRYPTION WITH SYMMETRIC CRYPTO
//===========================================================================================================

/**
 * @brief Encrypts a message 'm' of length 'mlen' using the symmetric key 'key' obtained from the client connection
 *  and stores the cipher in 'c'. This function does not use a nonce.
 * 
 * @param key Symmetric key obtained from the client connection.
 * @param c Buffer to contain the cipher.
 * @param m Message to encrypt.
 * @param mlen Length of the message to encrypt.
 * @return Error code indicating the success or failure of the encryption process.
 */
inline errcode_t secu_symmetric_encrypt(const uint8_t *key, uint8_t *c, const void *m, size_t mlen)
{
  const uint8_t *__m = (const uint8_t *)m;
  if (crypto_secretbox_easy(c, __m, mlen, NULL, key))
    return LOG(SECU_LOG_PATH, E_SYMM_ENCRYPT, E_SYMM_ENCRYPT_M);
  return __SUCCESS__;
}

/**
 * @brief Decrypts a cipher 'c' of length 'clen' using the symmetric key 'key', storing the result in 'm'. This function does not use a nonce.
 * 
 * @param key Symmetric key specific to this connection.
 * @param m Buffer to store the decrypted message.
 * @param c Cipher to decrypt.
 * @param clen Length of the cipher to decrypt.
 * @return Error code indicating the success or failure of the decryption process.
 */
inline errcode_t secu_symmetric_decrypt(const uint8_t *key, void *m, const uint8_t *c, size_t clen)
{
  uint8_t *__m = (uint8_t *)m;
  if (crypto_secretbox_open_easy(__m, c, clen, NULL, key))
    return LOG(SECU_LOG_PATH, E_SYMM_DECRYPT, E_SYMM_DECRYPT_M);
  return __SUCCESS__;
}

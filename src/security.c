#include "../include/security.h"

//===============================================
//      INITIALIZE + CHECK PASSPHRASE
//===============================================

/// @brief Initialize libsodium 
/// @return errorcode
inline errcode_t secu_init(void)
{
  if (sodium_init() == -1)
    return LOG(SECU_LOG_PATH, ESODIUM_INIT, "Security ctx_init failed");
  return __SUCCESS__;
}


/// @brief reads the authentication file from the physical key and stores in c
/// @param c  cipher buffer to fill 
static inline errcode_t get_auth_key(uint8_t *c)
{
  FILE *db_privf;
  
  if (!(db_privf = fopen(PATH_PHYSKEY, "rb")))
    return LOG(DB_LOG_PATH, E_FOPEN, "Error opening authentication private key file");
  
  if (fread((void*)c, 1, crypto_hash_sha512_BYTES, db_privf) < crypto_hash_sha512_BYTES)
    return LOG(DB_LOG_PATH, E_FREAD, "Error reading authentication private key file missing data!");
  
  fclose(db_privf);
  return __SUCCESS__;
}


/// @brief checks if password entered is correct (step 1 authentication)
/// @param pass command line argument entered password
errcode_t secu_check_init_cred(const uint8_t *pass)
{
  uint8_t c1[crypto_hash_sha512_BYTES];
  uint8_t c2[crypto_hash_sha512_BYTES];
  
  if (crypto_hash_sha512(c1, pass, strlen(pass)))
    return LOG(SECU_LOG_PATH, E_SHA512, "SHA512 cipher failed");
  
  if (get_auth_key(c2))
    return E_AUTHKEY;
  
  if (memcmp((const void*)c1, (const void*)c2, crypto_hash_sha512_BYTES) != 0)
    return LOG(SECU_LOG_PATH, E_WRONG_CREDS, "Error wrong credentials");
  
  return __SUCCESS__;
}

//===============================================
//      ASYMMETRIC KEY GENERATION
//===============================================

/// @brief generate asymmetric keypair and write to the database
/// @param db_connect MYSQL db connection
errcode_t secu_init_keys(MYSQL *db_connect)
{
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];

  if (crypto_box_keypair(pk, sk))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(pk, crypto_box_SECRETKEYBYTES);   
    return LOG(SECU_LOG_PATH, EKEYPAIR_GEN, "Security keypair generation failed");
  }
  if (secu_key_del(db_connect))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(pk, crypto_box_SECRETKEYBYTES);   
    return LOG(SECU_LOG_PATH, EKEYPAIR_DEL, "Security keypair deletion failed");    
  }
  if (secu_key_save(pk, sk, db_connect))
  {
    bzero(pk, crypto_box_PUBLICKEYBYTES);
    bzero(pk, crypto_box_SECRETKEYBYTES);   
    return LOG(SECU_LOG_PATH, EKEYPAIR_SAVE, "Security keypair saving failed");
  }
  bzero(pk, crypto_box_PUBLICKEYBYTES);
  bzero(pk, crypto_box_SECRETKEYBYTES);
  return __SUCCESS__;
}


//===========================================================================================================
//                SECURITY: ENCRYPTION DECRYPTION WITH ASYMMETRIC CRYPTOS
//===========================================================================================================

/// @brief encrypt m of length mlen with pk then store the cipher in c
/// @param pk public key
/// @param c buffer to contain cipher
/// @param m message to encrypt
/// @param mlen length of message to encrypt
inline errcode_t secu_asymmetric_encrypt(const uint8_t *pk, uint8_t *c, const void *m, size_t mlen)
{
  const uint8_t *__m = (const uint8_t *)m;
  if (crypto_box_seal(c, __m, mlen, pk))
    return LOG(SECU_LOG_PATH, E_ASYMM_ENCRYPT, "Security Error during encryption with public key");
  return __SUCCESS__;
}

/// @brief decrypt cipher stored in c of length clen with pk and sk then store result in m 
/// @param pk public key
/// @param sk secret key
/// @param m buffer to store decrypted message
/// @param c cipher to decrypt
/// @param clen length of cipher to decrypt
inline errcode_t secu_asymmetric_decrypt(const uint8_t *pk, const uint8_t *sk, void *m, const uint8_t *c, size_t clen)
{
  uint8_t *__m = (uint8_t *)m;
  if (crypto_box_seal_open(__m, c, clen, pk, sk))
    return LOG(SECU_LOG_PATH, E_ASYMM_DECRYPT, "Security Error during decryption with key pair");
  return __SUCCESS__;
}


//===============================================
//      SYMMETRIC KEY GENERATION
//===============================================




//===========================================================================================================
//                SECURITY: ENCRYPTION DECRYPTION WITH SYMMETRIC CRYPTO
//===========================================================================================================
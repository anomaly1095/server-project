
#ifndef SECURITY_H
#define SECURITY_H      1
#include "base.h"


//===============================================
//          ----SIZEOF AUTH STREAMS----
//===============================================


#define SECRET_SALT_SIZE    32U

#define ENCRYPTED_KEY_SIZE crypto_secretbox_KEYBYTES +\
crypto_secretbox_MACBYTES


#define PATH_PHYSKEY    "/media/amnesia2/PKEY/keys/auth_init.bin"  // path to the key for first step authentication


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


/// @brief encrypt m of length mlen with pk then store the cipher in c
/// @param pk public key
/// @param c buffer to contain cipher
/// @param m message to encrypt
/// @param mlen length of message to encrypt
inline errcode_t secu_asymmetric_encrypt(const uint8_t *pk, uint8_t *c, const void *m, size_t mlen);

/// @brief decrypt cipher stored in c of length clen with pk and sk then store result in m 
/// @param pk public key
/// @param sk secret key
/// @param m buffer to store decrypted message
/// @param c cipher to decrypt
/// @param clen length of cipher to decrypt
errcode_t secu_asymmetric_decrypt(const uint8_t *pk, const uint8_t *sk, void *m, const uint8_t *c, size_t clen);

#endif

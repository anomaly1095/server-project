
#ifndef SECURITY_H
#define SECURITY_H      1
#include "base.h"
#include <sodium.h>

//  security errors 100->150 
#define ESODIUM_INIT    100
#define ESECU_LOG       101
#define EKEYPAIR_GEN    102
#define EKEYPAIR_SAVE   103
#define EKEYPAIR_DEL    104
#define E_WRONG_CREDS   105
#define E_AUTHKEY       106
#define E_SHA512        107
#define E_ASYMM_ENCRYPT 108
#define E_ASYMM_DECRYPT 109
#define E_SYMM_ENCRYPT  110
#define E_SYMM_DECRYPT  111


#define PATH_PHYSKEY    "/media/amnesia2/PKEY/keys/auth_init.bin"  // path to the key for first step authentication

#define QUERY_KEY_DELETE "DELETE FROM KeyPairs;"

#define QUERY_KEY_INSERT "INSERT INTO KeyPairs (pk, sk) VALUES (?, ?);"
#define QUERY_KEY_INSERT_LEN (__builtin_strlen(QUERY_KEY_INSERT))

#define QUERY_SELECT_PK  "SELECT pk FROM KeyPairs;"
#define QUERY_SELECT_PK_LEN (__builtin_strlen(QUERY_SELECT_PK))

#define QUERY_SELECT_SK  "SELECT sk FROM KeyPairs;"
#define QUERY_SELECT_SK_LEN (__builtin_strlen(QUERY_SELECT_SK))

#define QUERY_SELECT_PK_SK  "SELECT pk, sk FROM KeyPairs;"
#define QUERY_SELECT_PK_SK_LEN (__builtin_strlen(QUERY_SELECT_PK_SK))

/// @brief Initialize libsodium 
/// @return errorcode
errcode_t secu_init(void);

/// @brief generate asymmetric keypair and write to the database
/// @param db_connect MYSQL db connection
errcode_t secu_init_keys(MYSQL *db_connect);

/// @brief checks if password entered is same as in physkey (step 1 authentication)
/// @param pass command line argument entered password
errcode_t secu_check_init_cred(const uint8_t *pass);

/// @brief get (public key) from database
/// @param db_connect MYSQL db connection
/// @param pk public key
errcode_t db_get_pk(MYSQL *db_connect, uint8_t *pk);

/// @brief get (secret key) from database
/// @param db_connect MYSQL db connection
/// @param sk secret key
errcode_t db_get_sk(MYSQL *db_connect, uint8_t *sk);

/// @brief get (public key / secret key) from database
/// @param db_connect MYSQL db connection
/// @param pk public key
/// @param sk secret key
errcode_t db_get_pk_sk(MYSQL *db_connect, uint8_t *pk, uint8_t *sk);

#endif

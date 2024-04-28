#include "../include/security.h"

//===============================================
//      INITIALIZE + CHECK PASSPHRASE
//===============================================

/// @brief Initialize libsodium 
/// @return errorcode
inline errcode_t secu_init()
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

//===========================================================================================================
// SECURITY QUERIES: QUERY_KEY_INSERT /QUERY_KEY_DELETE /QUERY_SELECT_PK /QUERY_SELECT_SK /QUERY_SELECT_PK_SK
//===========================================================================================================

/// @brief Fill the parameter values for pk and sk
/// @param params query parameters
static inline void fill_params_KEY_INSERT(MYSQL_BIND *params, uint8_t *pk, uint8_t *sk)
{
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = pk;
  params[0].buffer_length = sizeof pk;

  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = sk;
  params[1].buffer_length = sizeof sk;
}

/// @brief Fill the parameter values for pk
/// @param result query results
static inline void fill_params_KEY_SELECT_PK(MYSQL_BIND *result, uint8_t *pk)
{
  result->buffer_type = MYSQL_TYPE_BLOB;
  result->buffer = pk;
  result->buffer_length = crypto_box_PUBLICKEYBYTES;
}

/// @brief Fill the parameter values for sk 
/// @param result query results
static inline void fill_params_KEY_SELECT_SK(MYSQL_BIND *result, uint8_t *sk)
{
  result->buffer_type = MYSQL_TYPE_BLOB;
  result->buffer = sk;
  result->buffer_length = crypto_box_SECRETKEYBYTES;
}

/// @brief Fill the parameter values for pk and sk
/// @param result query results
static inline void fill_params_KEY_SELECT_PK_SK(MYSQL_BIND *result, uint8_t *pk, uint8_t *sk)
{
  result[0].buffer_type = MYSQL_TYPE_BLOB;
  result[0].buffer = pk;
  result[0].buffer_length = crypto_box_PUBLICKEYBYTES;
  
  result[1].buffer_type = MYSQL_TYPE_BLOB;
  result[1].buffer = sk;
  result[1].buffer_length = crypto_box_SECRETKEYBYTES;
}


/// @brief writing the keys to the database
/// @param pk public key
/// @param sk secure key
/// @param db_connect MYSQL database connection
static errcode_t secu_key_save(uint8_t *pk, uint8_t *sk, MYSQL *db_connect)
{
  MYSQL_STMT *stmt; // statement handle
  MYSQL_BIND params[2]; // Array to hold parameter information (pk, sk)
  memset(params, 0x0, sizeof params); // Initialize the param structs

  // Initialize a statement handle
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement with the INSERT query
  if (mysql_stmt_prepare(stmt, QUERY_KEY_INSERT, QUERY_KEY_INSERT_LEN))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Fill the parameter values for pk and sk
  fill_params_KEY_INSERT(params, pk, sk);

  // Bind the parameters to the statement
  mysql_stmt_bind_param(stmt, params);

  // Execute the statement
  if (!mysql_stmt_execute(stmt))
    goto cleanup;

  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;
  
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief get public key from database
/// @param db_connect MYSQL db connection
/// @param pk public key
errcode_t db_get_pk(MYSQL *db_connect, uint8_t *pk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result;
  memset(&result, 0x0, sizeof(result)); // Initialize the result structure

  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK, QUERY_SELECT_PK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_params_KEY_SELECT_PK(&result, pk);

  mysql_stmt_bind_result(stmt, &result);

  // Execute the statement
  if (!mysql_stmt_execute(stmt))
    goto cleanup;

  // Fetch the result
  if (!mysql_stmt_fetch(stmt))
    goto cleanup;

  mysql_stmt_close(stmt);
  return __SUCCESS__;
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief get secret key from database
/// @param db_connect MYSQL db connection
/// @param pk secret key
errcode_t db_get_sk(MYSQL *db_connect, uint8_t *sk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result;
  memset(&result, 0x0, sizeof result); // Initialize the result structure

  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_SK, QUERY_SELECT_SK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_params_KEY_SELECT_SK(&result, sk);

  mysql_stmt_bind_result(stmt, &result);

  // Execute the statement
  if (!mysql_stmt_execute(stmt))
    goto cleanup;

  // Fetch the result
  if (!mysql_stmt_fetch(stmt))
    goto cleanup;

  mysql_stmt_close(stmt);
  return __SUCCESS__;

cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief get public key & secret key from database
/// @param db_connect MYSQL db connection
/// @param pk public key
/// @param sk secret key
errcode_t db_get_pk_sk(MYSQL *db_connect, uint8_t *pk, uint8_t *sk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result[2];
  memset(&result, 0x0, sizeof result); // Initialize the result structure

  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK_SK, QUERY_SELECT_PK_SK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_params_KEY_SELECT_PK_SK(result, pk, sk);

  mysql_stmt_bind_result(stmt, result);

  // Execute the statement
  if (!mysql_stmt_execute(stmt))
    goto cleanup;

  // Fetch the result
  if (!mysql_stmt_fetch(stmt))
    goto cleanup;

  mysql_stmt_close(stmt);
  return __SUCCESS__;

cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief deletes current key pair present in the db KeyPairs table
/// @param db_connect MYSQL db connection
static inline errcode_t secu_key_del(MYSQL *db_connect)
{
  if (mysql_query(db_connect, QUERY_KEY_DELETE))
    return LOG(DB_LOG_PATH, (int32_t)mysql_errno(db_connect), mysql_error(db_connect));
  return __SUCCESS__;
}

//===============================================
//   KEY GENERATION
//===============================================

/// @brief generate asymmetric keypair and write to the database
/// @param db_connect MYSQL db connection
errcode_t secu_init_keys(MYSQL *db_connect)
{
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];

  if (crypto_box_keypair(pk, sk))
    return LOG(SECU_LOG_PATH, EKEYPAIR_GEN, "Security keypair generation failed");

  if (secu_key_del(db_connect))
    return LOG(SECU_LOG_PATH, EKEYPAIR_DEL, "Security keypair deletion failed");    

  if (secu_key_save(pk, sk, db_connect))
    return LOG(SECU_LOG_PATH, EKEYPAIR_SAVE, "Security keypair saving failed");

  return __SUCCESS__;
}
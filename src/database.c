#include "../include/database.h"

//===============================================
//              AUTHENTICATION
//===============================================

pthread_mutex_t mutex_connection_global;
pthread_mutex_t mutex_connection_fd;
pthread_mutex_t mutex_connection_auth_status;
pthread_mutex_t mutex_connection_key;

#if (ATOMIC_SUPPORT) 
  _Atomic int32_t memory_w = 0;
  
#else
  int32_t memory_w = 0;
  extern pthread_mutex_t mutex_thread_id; // mutex will only be used once by everythread to check id
  extern pthread_mutex_t mutex_memory_w;  // mutex will be used for kernel memory warnings 
#endif


/**
 * @brief Prompt user for the database hostname.
 * 
 * @param host Buffer to store the hostname.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
errcode_t db_get_auth_host(char *host) {
    printf("Enter database hostname: ");
    if (!fgets(host, DB_SIZE_HOST, stdin))
        return __FAILURE__;
    host[strcspn(host, "\n")] = 0X0; // Remove trailing newline
    return __SUCCESS__;
}

/**
 * @brief Prompt user for the database username.
 * 
 * @param user Buffer to store the username.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
errcode_t db_get_auth_user(char *user) {
    printf("Enter database username: ");
    if (!fgets(user, DB_SIZE_USER, stdin))
        return __FAILURE__;
    user[strcspn(user, "\n")] = 0x0; // Remove trailing newline
    return __SUCCESS__;
}

/**
 * @brief Prompt user for the database password.
 * 
 * @param passwd Buffer to store the password.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
errcode_t db_get_auth_pass(char *passwd) {
    printf("Enter database password: ");
    char *input = getpass("");
    strncpy(passwd, input, DB_SIZE_PASS - 1);
    passwd[DB_SIZE_PASS - 1] = 0x0; // Ensure null-termination
    return __SUCCESS__;
}

/**
 * @brief Prompt user for the database name.
 * 
 * @param db Buffer to store the database name.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
errcode_t db_get_auth_db(char *db) {
    printf("Enter database name: ");
    if (!fgets(db, DB_SIZE_DB, stdin))
        return __FAILURE__;
    db[strcspn(db, "\n")] = 0x0; // Remove trailing newline
    return __SUCCESS__;
}

/**
 * @brief Perform realtime authentication from admin.
 * 
 * This function prompts the user for database credentials and populates
 * the db_creds_t structure with the provided values.
 * 
 * @param creds Pointer to db_creds_t structure to store the credentials.
 * @return __SUCCESS__ on success, appropriate error code on failure.
 */
errcode_t db_get_auth(db_creds_t *creds)
{
  memset(creds, 0, sizeof(*creds));
  if (db_get_auth_host(creds->host))
      return LOG(DB_LOG_PATH, EDB_W_HOST, EDB_W_HOST_M);
  if (db_get_auth_user(creds->user))
      return LOG(DB_LOG_PATH, EDB_W_USER, EDB_W_USER_M);
  if (db_get_auth_pass(creds->passwd))
      return LOG(DB_LOG_PATH, EDB_W_PASSWD, EDB_W_PASSWD_M);
  if (db_get_auth_db(creds->db))
      return LOG(DB_LOG_PATH, EDB_W_DB, EDB_W_DB_M);
  creds->port = DB_DEFAULT_PORT; // Assuming DEFAULT_DB_PORT is defined elsewhere
  return __SUCCESS__;
}




//===============================================
//            INITIALISATION
//===============================================

/**
 * @brief Connect to the database using provided credentials.
 * 
 * This function initializes the database connection, retrieves database credentials,
 * and connects to the database using the provided credentials.
 * 
 * @param db_connect Pointer to a MYSQL pointer for storing the database connection.
 * @return __SUCCESS__ on success, appropriate error code on failure.
 */
errcode_t db_init(MYSQL **db_connect) {
    db_creds_t creds;
    
    // Initialize database connection
    *db_connect = mysql_init(NULL);
    if (!*db_connect)
        return LOG(DB_LOG_PATH, EDB_CO_INIT, EDB_CO_INIT_M);

    // Retrieve database credentials
    if (db_get_auth(&creds))
        return EDB_AUTH;

    // Connect to the database
    if (!mysql_real_connect(*db_connect, creds.host, creds.user, creds.passwd, creds.db, creds.port, NULL, 0))
        return LOG(DB_LOG_PATH, mysql_errno(*db_connect), mysql_error(*db_connect));

    return __SUCCESS__;
}


//===========================================================================================================
//ASYMMETRIC QUERIES:QUERY_KEY_INSERT /QUERY_KEY_DELETE /QUERY_SELECT_PK /QUERY_SELECT_SK /QUERY_SELECT_PK_SK
//===========================================================================================================


/**
 * @brief Fill the parameter values for pk and sk.
 * 
 * This function initializes the parameters for the public key (pk) and 
 * secret key (sk) to be inserted into the database.
 * 
 * @param params Query parameters array.
 * @param pk Public key buffer.
 * @param sk Secret key buffer.
 */
static inline void fill_params_KEY_INSERT(MYSQL_BIND *params, uint8_t *pk, uint8_t *sk)
{
    // Parameter for public key (pk)
    params[0].buffer_type = MYSQL_TYPE_BLOB;
    params[0].buffer = pk;
    params[0].buffer_length = sizeof pk;

    // Parameter for secret key (sk)
    params[1].buffer_type = MYSQL_TYPE_BLOB;
    params[1].buffer = sk;
    params[1].buffer_length = sizeof sk;
}

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
errcode_t secu_key_save(uint8_t *pk, uint8_t *sk, MYSQL *db_connect)
{
    MYSQL_STMT *stmt = NULL; // Statement handle
    MYSQL_BIND params[2];    // Array to hold parameter information (pk, sk)
    bzero((void *)params, sizeof(params)); // Initialize the param structs

    // Initialize a statement handle
    if (!(stmt = mysql_stmt_init(db_connect)))
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Prepare the statement with the INSERT query
    if (mysql_stmt_prepare(stmt, QUERY_KEY_INSERT, QUERY_KEY_INSERT_LEN))
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Fill the parameter values for pk and sk
    fill_params_KEY_INSERT(params, pk, sk);

    // Bind the parameters to the statement
    if (mysql_stmt_bind_param(stmt, params))
        goto cleanup;

    // Execute the statement
    if (mysql_stmt_execute(stmt))
        goto cleanup;

    // Close the statement handle
    mysql_stmt_close(stmt);
    return __SUCCESS__;

cleanup:
    mysql_stmt_close(stmt);
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/**
 * @brief Retrieve the public key from the database.
 * 
 * This function retrieves the public key (pk) from the database.
 * 
 * @param db_connect MYSQL database connection.
 * @param pk Public key buffer to store the retrieved key.
 * @return Error code indicating success or failure.
 */
errcode_t db_get_pk(MYSQL *db_connect, uint8_t *pk)
{
  MYSQL_STMT *stmt = NULL;
  MYSQL_BIND result;
  bzero((void *)&result, sizeof(result)); // Initialize the result structure

  // Initialize the statement handle
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK, QUERY_SELECT_PK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  result.buffer_type = MYSQL_TYPE_BLOB;
  result.buffer = pk;
  result.buffer_length = crypto_box_PUBLICKEYBYTES;

  // Bind the result parameter to the statement
  if (mysql_stmt_bind_result(stmt, &result))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Execute the statement
  if (!mysql_stmt_execute(stmt))
    goto cleanup;

  // Fetch the result
  if (!mysql_stmt_fetch(stmt))
    goto cleanup;

  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;

cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}



/**
 * @brief Retrieve the secret key from the database.
 * 
 * This function retrieves the secret key (sk) from the database.
 * 
 * @param db_connect MYSQL database connection.
 * @param sk Secret key buffer to store the retrieved key.
 * @return Error code indicating success or failure.
 */
errcode_t db_get_sk(MYSQL *db_connect, uint8_t *sk)
{
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND result;
    bzero((void *)&result, sizeof(result)); // Initialize the result structure

    // Initialize the statement handle
    if (!(stmt = mysql_stmt_init(db_connect)))
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Prepare the statement
    if (mysql_stmt_prepare(stmt, QUERY_SELECT_SK, QUERY_SELECT_SK_LEN) != 0)
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Parameter for secret key (sk)
    result.buffer_type = MYSQL_TYPE_BLOB;
    result.buffer = sk;
    result.buffer_length = crypto_box_SECRETKEYBYTES;

    // Bind the result parameter to the statement
    if (mysql_stmt_bind_result(stmt, &result))
        return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Execute the statement
    if (!mysql_stmt_execute(stmt))
        goto cleanup;

    // Fetch the result
    if (!mysql_stmt_fetch(stmt))
        goto cleanup;

    // Close the statement handle
    mysql_stmt_close(stmt);
    return __SUCCESS__;

cleanup:
    mysql_stmt_close(stmt);
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/**
 * @brief Fill the parameter values for pk and sk.
 * 
 * This function initializes the parameters for the public key (pk) and secret key (sk)
 * retrieved from the database query result.
 * 
 * @param result Query results array.
 * @param pk Public key buffer.
 * @param sk Secret key buffer.
 */
static inline void fill_result_KEY_SELECT_PK_SK(MYSQL_BIND *result, uint8_t *pk, uint8_t *sk)
{
    // Parameter for public key (pk)
    result[0].buffer_type = MYSQL_TYPE_BLOB;
    result[0].buffer = pk;
    result[0].buffer_length = crypto_box_PUBLICKEYBYTES;
  
    // Parameter for secret key (sk)
    result[1].buffer_type = MYSQL_TYPE_BLOB;
    result[1].buffer = sk;
    result[1].buffer_length = crypto_box_SECRETKEYBYTES;
}

/**
 * @brief Retrieve the public key and secret key from the database.
 * 
 * This function retrieves both the public key (pk) and secret key (sk) from the database.
 * 
 * @param db_connect MYSQL database connection.
 * @param pk Public key buffer to store the retrieved key.
 * @param sk Secret key buffer to store the retrieved key.
 * @return Error code indicating success or failure.
 */
errcode_t db_get_pk_sk(MYSQL *db_connect, uint8_t *pk, uint8_t *sk)
{
    MYSQL_STMT *stmt = NULL;
    MYSQL_BIND result[2];
    bzero((void*)result, sizeof(result)); // Initialize the result structure

    // Initialize the statement handle
    if (!(stmt = mysql_stmt_init(db_connect)))
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Prepare the statement
    if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK_SK, QUERY_SELECT_PK_SK_LEN))
        return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
    // Fill the parameter values for pk and sk
    fill_result_KEY_SELECT_PK_SK(result, pk, sk);

    // Bind the result parameters to the statement
    if (mysql_stmt_bind_result(stmt, result))
        return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

    // Execute the statement
    if (!mysql_stmt_execute(stmt))
        goto cleanup;

    // Fetch the result
    if (!mysql_stmt_fetch(stmt))
        goto cleanup;

    // Close the statement handle
    mysql_stmt_close(stmt);
    return __SUCCESS__;

cleanup:
    mysql_stmt_close(stmt);
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/**
 * @brief Delete the current key pair present in the database KeyPairs table.
 * 
 * This function deletes the current key pair present in the KeyPairs table of the database.
 * 
 * @param db_connect MYSQL database connection.
 * @return Error code indicating success or failure.
 */
inline errcode_t secu_key_del(MYSQL *db_connect)
{
    if (mysql_query(db_connect, QUERY_KEY_DELETE))
        return LOG(DB_LOG_PATH, (int32_t)mysql_errno(db_connect), mysql_error(db_connect));
    return __SUCCESS__;
}




//==========================================================================
//                       CRUD NEW CONNECTONS
//==========================================================================

//---------------------------INSERT

/**
 * @brief Fill the parameters of the insert connection query.
 * 
 * This function fills the parameters of the insert connection query with the values 
 * from the new connection object.
 * 
 * @param params Parameters of the statement.
 * @param co_new New connection object.
 */
static inline void fill_params_co_insert(MYSQL_BIND *params, co_t co_new)
{
  // FILE DESCRIPTOR
  params[0].buffer_type = MYSQL_TYPE_LONG;
  params[0].buffer = &co_new.co_fd;
  params[0].buffer_length = sizeof co_new.co_fd;

  // AUTHENTICATION STEP
  params[1].buffer_type = MYSQL_TYPE_TINY;
  params[1].buffer = &co_new.co_auth_status;
  params[1].buffer_length = sizeof co_new.co_auth_status;

  // ADDRESS FAMILY
  params[2].buffer_type = MYSQL_TYPE_SHORT;
  params[2].buffer = &co_new.co_af;
  params[2].buffer_length = sizeof co_new.co_af;

  // CONNECTION PORT BIG ENDIAN
  params[3].buffer_type = MYSQL_TYPE_SHORT;
  params[3].buffer = &co_new.co_port;
  params[3].buffer_length = sizeof co_new.co_port;

  // CONNECTION IP ADDRESS BIG ENDIAN
  params[4].buffer_type = MYSQL_TYPE_BLOB;
  params[4].buffer = co_new.co_ip_addr;
  params[4].buffer_length = SIZE_IP_ADDR;

  // Connection secret key
  params[5].buffer_type = MYSQL_TYPE_BLOB;
  params[5].buffer = co_new.co_key;
  params[5].buffer_length = crypto_secretbox_KEYBYTES;

  // Connection secret key
  params[6].buffer_type = MYSQL_TYPE_BLOB;
  params[6].buffer = co_new.co_nonce;
  params[6].buffer_length = crypto_secretbox_NONCEBYTES;

}


/// @brief function to insert new connection in database
/// @param db_connect MYSQL database connection
/// @param co_new new connection object
errcode_t db_co_insert(MYSQL *db_connect, const co_t co_new)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[CO_NROWS-2]; // no id binding and no date binding
  bzero((void*)params, sizeof params);
  //initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_INSERT, QUERY_CO_INSERT_LEN))
    goto cleanup;

  // Fill the parameter values for pk and sk
  fill_params_co_insert(params, co_new);

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  pthread_mutex_lock(&mutex_connection_global);
  // Execute the statement
  if (!mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_global);
    goto cleanup;
  }
  pthread_mutex_unlock(&mutex_connection_global);

  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;
  
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}

//---------------------------DELETE

/**
 * @brief Fill parameters for the delete connection by address query.
 * 
 * This function sets up the parameters required for deleting a connection by its address from the database.
 * 
 * @param params An array of MySQL parameter bindings.
 * @param co_ip_addr The BIG ENDIAN binary IP address of the connection.
 * @param co_port The BIG ENDIAN port of the connection.
 */
static inline void fill_params_co_del_byaddr(MYSQL_BIND *params, uint8_t *co_ip_addr, const int16_t co_port)
{
  // FILE DESCRIPTOR
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = co_ip_addr;
  params[0].buffer_length = SIZE_IP_ADDR;

  // AUTHENTICATION STEP
  params[1].buffer_type = MYSQL_TYPE_SHORT;
  params[1].buffer = (void *)&co_port;
  params[1].buffer_length = sizeof co_port;
}


/**
 * @brief Delete a connection from the database by its ID.
 * 
 * This function deletes a connection object from the database using its ID.
 * 
 * @param db_connect The MySQL database connection.
 * @param co_id The ID of the connection to be deleted.
 * @return An error code indicating the success or failure of the operation.
 */
errcode_t db_co_del_byid(MYSQL *db_connect, const id64_t co_id)
{
    char query[QUERY_CO_DEL_BYID_LEN + 24];

    // Construct the query
    sprintf(query, QUERY_CO_DEL_BYID, co_id);
    
    pthread_mutex_lock(&mutex_connection_global);
    // Execute the query
    if (!mysql_real_query(db_connect, query, strlen(query))){
      pthread_mutex_unlock(&mutex_connection_global);
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
    }
    pthread_mutex_unlock(&mutex_connection_global);

    return __SUCCESS__;
}


/**
 * @brief Delete a connection from the database by its file descriptor.
 * 
 * This function deletes a connection object from the database using its file descriptor.
 * 
 * @param db_connect The MySQL database connection.
 * @param co_fd The file descriptor of the connection to be deleted.
 * @return An error code indicating the success or failure of the operation.
 */
errcode_t db_co_del_byfd(MYSQL *db_connect, const sockfd_t co_fd)
{
    char query[QUERY_CO_DEL_BYFD_LEN + 16];

    // Construct the query
    sprintf(query, QUERY_CO_DEL_BYFD, co_fd);
    
    pthread_mutex_lock(&mutex_connection_global);
    // Execute the query
    if (!mysql_real_query(db_connect, query, strlen(query))){
      pthread_mutex_unlock(&mutex_connection_global);
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
    }
    pthread_mutex_unlock(&mutex_connection_global);
    return __SUCCESS__;
}

/**
 * @brief Delete a connection by its address from the database.
 * 
 * This function deletes a connection object from the database using its address.
 * 
 * @param db_connect The MySQL database connection.
 * @param co_ip_addr The BIG ENDIAN binary IP address of the connection.
 * @param co_port The BIG ENDIAN port of the connection.
 * @return An error code indicating the success or failure of the operation.
 */
errcode_t db_co_del_byaddr(MYSQL *db_connect, uint8_t *co_ip_addr, const int16_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];
  bzero((void*)params, sizeof params);

  //initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_DEL_BYADDR, QUERY_CO_DEL_BYADDR_LEN))
    goto cleanup;

  // Fill the parameter values for pk and sk
  fill_params_co_del_byaddr(params, co_ip_addr, co_port);

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  pthread_mutex_lock(&mutex_connection_global);
  // Execute the statement
  if (!mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_global);
    goto cleanup;
  }
  pthread_mutex_unlock(&mutex_connection_global);

  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;
  
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}

/**
 * @brief Delete all connection rows that were not active for a specified duration.
 * 
 * This function deletes all connection rows from the database that have not been active
 * for a specified duration, as set in the database header query.
 * 
 * @param db_connect The MySQL database connection.
 * @return An error code indicating the success or failure of the operation.
 */
errcode_t db_co_cleanup(MYSQL *db_connect)
{
  pthread_mutex_lock(&mutex_connection_global);
  if (mysql_real_query(db_connect, QUERY_CO_CLEANUP, QUERY_CO_CLEANUP_LEN)){
    pthread_mutex_unlock(&mutex_connection_global);  
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_global);
  return __SUCCESS__;
}


/**
 * @brief Reset the Connection table.
 * 
 * This function resets the Connection table in the database, effectively deleting all
 * existing rows and resetting the auto-increment ID.
 * 
 * @param db_connect The MySQL database connection.
 * @return An error code indicating the success or failure of the operation.
 */
errcode_t db_co_res(MYSQL *db_connect)
{
  pthread_mutex_lock(&mutex_connection_global);
  // Execute the query
  if (mysql_real_query(db_connect, QUERY_CO_RESET, QUERY_CO_RESET_LEN)){
    pthread_mutex_unlock(&mutex_connection_global);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  // Execute the query to reset the auto-increment ID
  if (mysql_real_query(db_connect, QUERY_CO_RES_ID, QUERY_CO_RES_ID_LEN)){
    pthread_mutex_unlock(&mutex_connection_global);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_global);
  return __SUCCESS__;
}


//---------------------------SELECT

/**
 * @brief Bind the result columns of the select function queries.
 * 
 * This function binds the result columns of the select function queries to the provided
 * result array. It allocates memory for each column buffer and sets the appropriate buffer
 * type, buffer length, and null indicator.
 * 
 * @param result The result array to bind (should have space for 8 columns).
 */
static inline void db_co_result_bind(MYSQL_BIND *result)
{
  // Column 1: co_id (BIGINT)
  result[0].buffer_type = MYSQL_TYPE_LONGLONG;
  result[0].buffer = malloc(sizeof(uint64_t));
  result[0].buffer_length = sizeof(uint64_t);
  result[0].is_null = 0;

  // Column 2: co_fd (INT)
  result[1].buffer_type = MYSQL_TYPE_LONG;
  result[1].buffer = malloc(sizeof(int32_t));
  result[1].buffer_length = sizeof(int32_t);
  result[1].is_null = 0;

  // Column 3: co_auth_status (TINYINT)
  result[2].buffer_type = MYSQL_TYPE_TINY;
  result[2].buffer = malloc(sizeof(uint8_t));
  result[2].buffer_length = sizeof(uint8_t);
  result[2].is_null = 0;

  // Column 4: co_last_co (DATETIME)
  result[3].buffer_type = MYSQL_TYPE_DATETIME;
  result[3].buffer = malloc(sizeof(MYSQL_TIME));
  result[3].buffer_length = sizeof(MYSQL_TIME);
  result[3].is_null = 0;

  // Column 5: co_af (SMALLINT)
  result[4].buffer_type = MYSQL_TYPE_SHORT;
  result[4].buffer = malloc(sizeof(uint16_t));
  result[4].buffer_length = sizeof(uint16_t);
  result[4].is_null = 0;

  // Column 6: co_port (SMALLINT)
  result[5].buffer_type = MYSQL_TYPE_SHORT;
  result[5].buffer = malloc(sizeof(uint16_t));
  result[5].buffer_length = sizeof(uint16_t);
  result[5].is_null = 0;

  // Column 7: co_ip_addr (BINARY)
  result[6].buffer_type = MYSQL_TYPE_BLOB;
  result[6].buffer = malloc(SIZE_IP_ADDR);
  result[6].buffer_length = SIZE_IP_ADDR;
  result[6].is_null = 0;

  // Column 8: co_key (BINARY)
  result[7].buffer_type = MYSQL_TYPE_BLOB;
  result[7].buffer = malloc(crypto_secretbox_KEYBYTES);
  result[7].buffer_length = crypto_secretbox_KEYBYTES;
  result[7].is_null = 0;

  // Column 8: co_key (BINARY)
  result[8].buffer_type = MYSQL_TYPE_BLOB;
  result[8].buffer = malloc(crypto_secretbox_NONCEBYTES);
  result[8].buffer_length = crypto_secretbox_NONCEBYTES;
  result[8].is_null = 0;


}


/**
 * @brief FUNCTION TO copy the data fetched in the result SQL object to the connection object.
 * 
 * This function copies the data fetched from the database result object to the provided 
 * connection object. It assumes that the result object contains data for each field of 
 * the connection object in the same order as defined in the `co_t` structure.
 * 
 * @param co The connection object to which the data will be copied.
 * @param result The result fetched from the database after the query.
 */
static inline void db_co_res_cpy(co_t *co, MYSQL_BIND *result)
{
  co->co_id = *((id64_t *)result[0].buffer);
  co->co_fd = *((int32_t *)result[1].buffer);
  co->co_auth_status = *((uint8_t *)result[2].buffer);
  memcpy(&co->co_last_co, result[3].buffer, SIZE_MYSQL_DT);
  co->co_af = *((uint16_t *)result[4].buffer);
  co->co_port = *((uint16_t *)result[5].buffer);
  memcpy(co->co_ip_addr, result[6].buffer, SIZE_IP_ADDR);
  memcpy(co->co_key, result[7].buffer, crypto_secretbox_KEYBYTES);
  memcpy(co->co_nonce, result[8].buffer, crypto_secretbox_NONCEBYTES);
}


/**
 * @attention Memory will be allocated internally for the `co` object.
 * 
 * @brief Get all columns by ID from the database.
 * 
 * This function retrieves all columns of a connection identified by the given ID from the database.
 * Memory will be allocated internally for the `co` object to store the retrieved data.
 * 
 * @param db_connect The MYSQL database connection.
 * @param co Pointer to a pointer to a connection object. Memory will be allocated internally for this object.
 * @param co_id The ID of the connection.
 * @return An error code indicating the status of the operation.
 */
errcode_t db_co_sel_all_by_id(MYSQL *db_connect, co_t **co, const id64_t co_id)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  // Initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_ALL_BY_ID, QUERY_CO_SEL_ALL_BY_ID_LEN))
    goto cleanup;

  // Initialize the parameter
  bzero((void*)&param, sizeof(param));
  param.buffer_type = MYSQL_TYPE_LONGLONG;
  param.buffer = (void*)&co_id;
  param.is_null = 0;
  param.length = 0;

  // Bind the parameter to the statement
  if (mysql_stmt_bind_param(stmt, &param))
    goto cleanup;


  // Execute the statement
  if (mysql_stmt_execute(stmt))
    goto cleanup;

  // Bind result set columns to variables
  db_co_result_bind(result);

  // Bind result set to the statement
  if (mysql_stmt_bind_result(stmt, result))
    goto cleanup;

  // Store the result set
  if (mysql_stmt_store_result(stmt))
    goto cleanup;

  // Allocate memory for the result set
  if (!(*co = (co_t*)malloc(sizeof(co_t)))){
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, EMALLOC_FAIL, EMALLOC_FAIL_M1);
  }

  // Fetch rows
  i = 0;
  while (!mysql_stmt_fetch(stmt)){
    db_co_res_cpy(co[i], result);
    bzero((void*)result[CO_NROWS-1].buffer, crypto_secretbox_KEYBYTES);
    ++i;
  }

  // Free memory allocated for result buffers
  for (i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);

  // Close and free the statement
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return __SUCCESS__;

cleanup:
  // Free memory allocated for result buffers
  for (i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);

  // Close and free the statement
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);

  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Get all columns for the connection matching the specified file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co Pointer to a connection object where the fetched data will be stored.
///           Memory will be allocated internally for the connection object.
/// @param co_fd The file descriptor number for which the connection row will be retrieved from the database.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, execute the statement, or fetch rows.
///     - Returns a warning code if no rows are fetched from the query.
errcode_t db_co_sel_by_fd(MYSQL *db_connect, co_t *co, const sockfd_t co_fd)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_ALL_BY_FD, QUERY_CO_SEL_ALL_BY_FD_LEN))
    goto cleanup;

  bzero((void*)&param, sizeof(param));
  param.buffer_type = MYSQL_TYPE_LONG;
  param.buffer = (void*)&co_fd;
  param.is_null = 0;
  param.length = 0;

  // Bind the parameter to the statement
  if (mysql_stmt_bind_param(stmt, &param))
    goto cleanup;

  // Execute the statement
  if (mysql_stmt_execute(stmt))
    goto cleanup;

  // Bind result set columns to variables
  db_co_result_bind(result);

  if (mysql_stmt_bind_result(stmt, result))
    goto cleanup;

  // Store the result set (expecting one row)
  if (mysql_stmt_store_result(stmt))
    goto cleanup;

  // Fetch the row
  if (mysql_stmt_fetch(stmt) != MYSQL_NO_DATA) {
    db_co_res_cpy(co, result);
  } else {
    // No row fetched
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, WDB_NO_ROWS, WDB_NO_ROWS_M1);
  }

  for (size_t i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);

  // Cleanup
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return __SUCCESS__;

cleanup:
  for (size_t i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}



/// @brief Retrieve all columns by connection/authentication status.
///
/// This function fetches all columns from the database where the connection/authentication status matches the specified value.
///
/// @param db_connect The MYSQL database connection.
/// @param co Pointer to a pointer to a connection object (co) where the fetched data will be stored.
///           Memory will be allocated internally based on the number of rows fetched.
/// @param nrow Pointer to a size_t variable where the number of rows fetched will be stored.
/// @param co_auth_status The connection/authentication status to match against in the database query.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, execute the statement, or fetch rows.
///     - Returns a warning code if no rows are fetched from the query.
errcode_t db_co_sel_all_by_auth_stat(MYSQL *db_connect, co_t **co, size_t *nrow, const flag_t co_auth_status)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_ALL_BY_AUTH_STAT, QUERY_CO_SEL_ALL_BY_AUTH_STAT_LEN))
    goto cleanup;

  bzero((void*)&param, sizeof(param));
  param.buffer_type = MYSQL_TYPE_BLOB;
  param.buffer = (void*)&co_auth_status;
  param.buffer_length = SIZE_IP_ADDR;

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, &param))
    goto cleanup;

  // Execute the statement
  if (mysql_stmt_execute(stmt))
    goto cleanup;

  // Bind result set columns to variables
  db_co_result_bind(result);
  
  if (mysql_stmt_bind_result(stmt, result))
    goto cleanup;

  // Store the result set
  if (mysql_stmt_store_result(stmt))
    goto cleanup;

  // Get the number of rows
  if (!(*nrow = mysql_stmt_num_rows(stmt))){
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, WDB_NO_ROWS, WDB_NO_ROWS_M1);
  }
  // Allocate memory for the result set
  if (!(*co = (co_t*)malloc(*nrow * sizeof(co_t)))){
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, EMALLOC_FAIL, EMALLOC_FAIL_M2);
  }

  // Fetch rows
  i = 0;
  while (!mysql_stmt_fetch(stmt)){
    db_co_res_cpy(co[i], result);
    ++i;
  }

  for (i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);
  // Cleanup
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return __SUCCESS__;
cleanup:
  for (i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Fill the parameter values for selecting all columns by IP address.
///
/// This function fills the parameter values required for a database query to select all columns where the IP address matches
/// the specified value.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_ip_addr The IP address in big-endian byte order.
/// @param co_port The connection port number in big-endian byte order.
static inline void fill_params_co_sel_by_addr(MYSQL_BIND *params, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  bzero((void*)params, sizeof(params));
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = (void*)co_ip_addr;
  params[0].buffer_length = SIZE_IP_ADDR;

  params[1].buffer_type = MYSQL_TYPE_SHORT;
  params[1].buffer = (void*)&co_port;
  params[1].buffer_length = sizeof co_port;
}

/// @attention Memory will be allocated internally for co objects and nrow set internally.
/// @brief Get all columns by IP address.
///
/// This function retrieves all columns from the database where the IP address and port number match the specified values.
///
/// @param db_connect The MYSQL database connection.
/// @param co Pointer to a pointer to a connection object (co) where the fetched data will be stored.
///           Memory will be allocated internally based on the number of rows fetched.
/// @param nrow Pointer to a size_t variable where the number of rows fetched will be stored.
/// @param co_ip_addr The IP address in big-endian byte order.
/// @param co_port The connection port number in big-endian byte order.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, execute the statement, or fetch rows.
errcode_t db_co_sel_all_by_addr(MYSQL *db_connect, co_t **co, size_t *nrow, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_ALL_BY_ADDR, QUERY_CO_SEL_ALL_BY_ADDR_LEN))
    goto cleanup;

  fill_params_co_sel_by_addr(params, co_ip_addr, co_port);
  
  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  // Execute the statement
  if (mysql_stmt_execute(stmt))
    goto cleanup;

  // Bind result set columns to variables
  db_co_result_bind(result);
  
  if (mysql_stmt_bind_result(stmt, result))
    goto cleanup;

  // Store the result set
  if (mysql_stmt_store_result(stmt))
    goto cleanup;

  // Get the number of rows
  if (!(*nrow = mysql_stmt_num_rows(stmt))){
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, WDB_NO_ROWS, WDB_NO_ROWS_M1);
  }
  // Allocate memory for the result set
  if (!(*co = (co_t*)malloc(*nrow * sizeof(co_t)))){
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, EMALLOC_FAIL, EMALLOC_FAIL_M2);
  }

  // Fetch rows
  i = 0;
  while (!mysql_stmt_fetch(stmt)){
    db_co_res_cpy(co[i], result);
    ++i;
  }

  for (i = 0; i < 7; ++i)
    free(result[i].buffer);
  // Cleanup
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return __SUCCESS__;
cleanup:
  for (i = 0; i < 7; ++i)
    free(result[i].buffer);
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Get the symmetric key for the client that has the specified socket file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co_key Buffer to store the symmetric key.
/// @param co_fd connection socket file descriptor
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_sel_key_by_fd(MYSQL *db_connect, uint8_t *co_key, uint8_t *co_nonce, sockfd_t co_fd)
{
  char query[QUERY_CO_SEL_KEY_BY_FD_LEN + 16];
  sprintf(query, QUERY_CO_SEL_KEY_BY_FD, co_fd);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  // Fetch the result
  MYSQL_RES *result = mysql_store_result(db_connect);
  if (!result) {
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }

  // Check if there are any rows returned
  MYSQL_ROW row = mysql_fetch_row(result);
  if (!row) {
    mysql_free_result(result);
    return LOG(DB_LOG_PATH, WDB_NO_ROWS, WDB_NO_ROWS_M1);
  }

  // Copy the key from the result to the buffer
  memcpy((void*)co_key, (const void*)row[0], crypto_secretbox_KEYBYTES);

  // Free the result and return success
  mysql_free_result(result);
  return __SUCCESS__;
}



/// @brief Get the symmetric key for the client that has the specified address pair (ip, port).
///
/// This function retrieves the symmetric key for the client that has the specified address pair (ip, port).
///
/// @param db_connect The MYSQL database connection.
/// @param co_key Buffer to store the symmetric key.
/// @param co_ip_addr Connection IP address in BIG ENDIAN BYTE ORDER.
/// @param co_port Connection port number in BIG ENDIAN BYTE ORDER.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_sel_key_by_addr(MYSQL *db_connect, uint8_t *co_key, uint8_t *co_nonce, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2]; // Number of columns in the result set
  MYSQL_BIND result[2];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_KEY_BY_ADDR, QUERY_CO_SEL_KEY_BY_ADDR_LEN))
    goto cleanup;

  fill_params_co_sel_by_addr(params, co_ip_addr, co_port);

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  // Execute the statement
  if (mysql_stmt_execute(stmt))
    goto cleanup;

  // Bind result set columns to variables
  result[0].buffer_type = MYSQL_TYPE_BLOB;
  result[0].buffer = co_key;
  result[0].buffer_length = crypto_secretbox_KEYBYTES;

  result[1].buffer_type = MYSQL_TYPE_BLOB;
  result[1].buffer = co_nonce;
  result[1].buffer_length = crypto_secretbox_NONCEBYTES;

  if (mysql_stmt_bind_result(stmt, result))
    goto cleanup;

  // Store the result set
  if (mysql_stmt_store_result(stmt))
    goto cleanup;

  // Get the number of rows
  if (!mysql_stmt_num_rows(stmt)){
    bzero((void*)params, sizeof params);
    mysql_stmt_close(stmt);
    mysql_stmt_free_result(stmt);
    return LOG(DB_LOG_PATH, WDB_NO_ROWS, WDB_NO_ROWS_M4);
  }

  // Fetch rows
  if (!mysql_stmt_fetch(stmt)){
    memcpy((void*)co_key, (const void*)result[0].buffer, crypto_secretbox_KEYBYTES);
    memcpy((void*)co_nonce, (const void*)result[1].buffer, crypto_secretbox_NONCEBYTES);
  }

  // Cleanup
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return __SUCCESS__;
cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  mysql_stmt_free_result(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Update the connection file descriptor to a new value based on the connection ID.
///
/// This function updates the connection file descriptor in the database to a new value based on the provided connection ID.
///
/// @param db_connect The MYSQL database connection.
/// @param co_fd The new connection file descriptor.
/// @param co_id The connection ID.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_fd_by_id(MYSQL *db_connect, sockfd_t co_fd, id64_t co_id)
{
  char query[QUERY_CO_UP_FD_BY_ID_LEN + 24 + 16];
  sprintf(query, QUERY_CO_UP_FD_BY_ID, co_fd, co_id);
  // Execute the query
  pthread_mutex_lock(&mutex_connection_fd);
  if (mysql_real_query(db_connect, query, strlen(query))){
    pthread_mutex_unlock(&mutex_connection_fd);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_fd);
  return __SUCCESS__;
}

/// @brief Update the connection file descriptor to a new value based on the existing file descriptor.
///
/// This function updates the connection file descriptor in the database to a new value based on the existing file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co_fd_new The new connection file descriptor.
/// @param co_fd The existing connection file descriptor.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_fd_by_fd(MYSQL *db_connect, const sockfd_t co_fd_new, sockfd_t co_fd)
{
  char query[QUERY_CO_UP_FD_BY_FD_LEN + 16 + 16];
  sprintf(query, QUERY_CO_UP_FD_BY_FD, co_fd_new, co_fd);
  pthread_mutex_lock(&mutex_connection_fd);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query))){
    pthread_mutex_unlock(&mutex_connection_fd);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_fd);
  return __SUCCESS__;
}


/// @brief Bind the parameters for the database query to update the connection file descriptor by address.
///
/// This function fills the parameter values required for a database query to update the connection file descriptor by address.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_fd The socket file descriptor.
/// @param co_ip_addr Connection IP address in BIG ENDIAN BYTE ORDER.
/// @param co_port Connection port number in BIG ENDIAN BYTE ORDER.
static inline void fill_params_co_update_fd_by_addr(MYSQL_BIND *params, sockfd_t co_fd, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  // param1: socket file descriptor
  params[0].buffer_type = MYSQL_TYPE_LONG;
  params[0].buffer = (void*)&co_fd;
  params[0].buffer_length = sizeof co_fd;

  // param2: connection ip address BIG ENDIAN BYTE ORDER
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_ip_addr;
  params[1].buffer_length = SIZE_IP_ADDR;

  // param2: connection port BIG ENDIAN BYTE ORDER
  params[2].buffer_type = MYSQL_TYPE_SHORT;
  params[2].buffer = (void*)&co_port;
  params[2].buffer_length = sizeof co_port;
}

/// @brief Update the connection file descriptor for the provided connection address.
///
/// This function updates the connection file descriptor in the database for the provided connection address.
///
/// @param db_connect The MYSQL database connection.
/// @param co_fd The socket file descriptor.
/// @param co_ip_addr Connection IP address in BIG ENDIAN BYTE ORDER.
/// @param co_port Connection port number in BIG ENDIAN BYTE ORDER.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_fd_by_addr(MYSQL *db_connect, sockfd_t co_fd, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[3];
  bzero((void*)params, sizeof params);
  //initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_FD_BYADDR, QUERY_CO_UP_FD_BYADDR_LEN))
    goto cleanup;

  // Fill the parameter values for the query
  fill_params_co_update_fd_by_addr(params, co_fd, co_ip_addr, co_port);

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;
  
  pthread_mutex_lock(&mutex_connection_fd);
  // Execute the statement
  if (!mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_fd);
    goto cleanup;
  }
  
  pthread_mutex_unlock(&mutex_connection_fd);
  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;
  
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Update the connection row to a new authentication status based on the connection ID.
///
/// This function updates the connection row in the database to a new authentication status based on the provided connection ID.
///
/// @param db_connect The MYSQL database connection.
/// @param co_auth_status The new connection status.
/// @param co_id The connection ID.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_auth_stat_by_id(MYSQL *db_connect, flag_t co_auth_status, id64_t co_id)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID_LEN + 24 + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID, co_auth_status, co_id);

  pthread_mutex_lock(&mutex_connection_auth_status);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query))){
    pthread_mutex_unlock(&mutex_connection_auth_status);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_auth_status);
  
  return __SUCCESS__;
}


/// @brief Update the connection row to a new authentication status based on the file descriptor.
///
/// This function updates the connection row in the database to a new authentication status based on the provided file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co_auth_status The new connection status.
/// @param co_fd The file descriptor.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
inline errcode_t db_co_up_auth_stat_by_fd(MYSQL *db_connect, flag_t co_auth_status, sockfd_t co_fd)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD_LEN + 24 + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD, co_auth_status, co_fd);

  pthread_mutex_lock(&mutex_connection_auth_status);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query))){
    pthread_mutex_unlock(&mutex_connection_auth_status);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }
  pthread_mutex_unlock(&mutex_connection_auth_status);

  return __SUCCESS__;
}


/// @brief Bind the parameters for the database query to update authentication status by address.
///
/// This function fills the parameter values required for a database query to update the connection authentication status by address.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_auth_status The new authentication status to set.
/// @param co_ip_addr Connection IP address in BIG ENDIAN BYTE ORDER.
/// @param co_port Connection port number in BIG ENDIAN BYTE ORDER.
static inline void fill_params_co_up_auth_stat_by_sockaddr(MYSQL_BIND *params, flag_t co_auth_status, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  // param 1: connection new authentication status
  params[0].buffer_type = MYSQL_TYPE_TINY;
  params[0].buffer = (void*)&co_auth_status;
  params[0].buffer_length = sizeof co_auth_status;
  // param 2: connection ip address
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_ip_addr;
  params[1].buffer_length = SIZE_IP_ADDR;
  // param 3: peer connection port number
  params[2].buffer_type = MYSQL_TYPE_SHORT;
  params[2].buffer = (void*)&co_port;
  params[2].buffer_length = sizeof co_port;
}

/// @brief Update the connection row to a new authentication status based on the connection address.
///
/// This function updates the connection row in the database to a new authentication status based on the provided connection address.
///
/// @param db_connect The MYSQL database connection.
/// @param co_auth_status The new connection status.
/// @param co_ip_addr Connection IP address in BIG ENDIAN BYTE ORDER.
/// @param co_port Connection port in BIG ENDIAN BYTE ORDER.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_auth_stat_by_addr(MYSQL *db_connect, flag_t co_auth_status, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt; // statement handle
  MYSQL_BIND params[3];
  bzero((void*)params, sizeof params); // Initialize the param structs

  // Initialize a statement handle
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Prepare the statement with the INSERT query
  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_AUTH_AUTH_STAT_BY_ADDR, QUERY_CO_UP_AUTH_AUTH_STAT_BY_ADDR_LEN))
    goto cleanup;

  // Fill the parameter values for pk and sk
  fill_params_co_up_auth_stat_by_sockaddr(params, co_auth_status, co_ip_addr, co_port);

  // Bind the parameters to the statement
  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  pthread_mutex_lock(&mutex_connection_auth_status);
  // Execute the statement
  if (!mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_auth_status);
    goto cleanup;
  }

  pthread_mutex_unlock(&mutex_connection_auth_status);
  // Close the statement handle
  mysql_stmt_close(stmt);
  return __SUCCESS__;
  
cleanup:
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Update connection rows to disconnected status that were last connected a specified number of hours ago.
///
/// This function updates the connection status in the database to disconnected for rows where the last connection
/// occurred a specified number of hours ago.
///
/// @param db_connect The MYSQL database connection.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_up_auth_stat_by_last_co(MYSQL *db_connect)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO_LEN + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO, CO_FLAG_DISCO);
  
  pthread_mutex_lock(&mutex_connection_auth_status);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query))){
    pthread_mutex_unlock(&mutex_connection_auth_status);
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  }

  pthread_mutex_unlock(&mutex_connection_auth_status);
  return __SUCCESS__;
}


/// @brief Bind the parameters for the database query to update the key by connection ID.
///
/// This function fills the parameter values required for a database query to update the connection key by ID.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_key The new connection key.
/// @param co_nonce random bytes
/// @param co_id The ID of the instance in the database.
static inline void fill_params_co_up_key_by_id(MYSQL_BIND *params, const uint8_t *co_key, const uint8_t *co_nonce, id64_t co_id)
{
  // param1: new connection key
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = (void*)co_key;
  params[0].buffer_length = crypto_secretbox_KEYBYTES;

  // param2: new connection nonce random bytes
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_nonce;
  params[1].buffer_length = crypto_secretbox_NONCEBYTES;

  // param3: connection id 
  params[2].buffer_type = MYSQL_TYPE_LONGLONG;
  params[2].buffer = (void*)&co_id;
  params[2].buffer_length = sizeof co_id;

}


/// @brief Update connection key by connection ID.
///
/// This function updates the connection key in the database based on the provided connection ID.
///
/// @param db_connect The MYSQL database connection.
/// @param co_key The new connection key.
/// @param co_nonce random bytes
/// @param co_id The ID of the instance in the database.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, or execute the statement.
errcode_t db_co_up_key_by_id(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_nonce, id64_t co_id)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[3];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_KEY_BY_ID, QUERY_CO_UP_KEY_BY_ID_LEN))
    goto cleanup;

  bzero((void*)params, sizeof params);
  fill_params_co_up_key_by_id(params, co_key, co_nonce, co_id);

  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;
  
  pthread_mutex_lock(&mutex_connection_key);
  if (mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_key);
    goto cleanup;
  }
  pthread_mutex_unlock(&mutex_connection_key);

  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;

cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Bind the parameters for the database query to update the key by file descriptor.
///
/// This function fills the parameter values required for a database query to update the connection key by file descriptor.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_key The new connection key.
/// @param co_nonce random bytes
/// @param co_fd The socket file descriptor.
static inline void fill_params_co_up_key_by_fd(MYSQL_BIND *params, const uint8_t *co_key, const uint8_t *co_nonce, sockfd_t co_fd)
{
  // param1: new connection key
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = (void*)co_key;
  params[0].buffer_length = crypto_secretbox_KEYBYTES;

  // param3: new connection nonce 
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_nonce;
  params[1].buffer_length = crypto_secretbox_NONCEBYTES;

  // param3: connection fd 
  params[2].buffer_type = MYSQL_TYPE_LONG;
  params[2].buffer = (void*)&co_fd;
  params[2].buffer_length = sizeof co_fd;

}

/// @brief Update connection key by file descriptor.
///
/// This function updates the connection key in the database based on the provided file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co_key The new connection key.
/// @param co_nonce random bytes
/// @param co_fd The socket file descriptor.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, or execute the statement.
errcode_t db_co_up_key_by_fd(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_nonce, sockfd_t co_fd)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[3];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_KEY_BY_FD, QUERY_CO_UP_KEY_BY_FD_LEN))
    goto cleanup;

  bzero((void*)params, sizeof params);
  fill_params_co_up_key_by_fd(params, co_key, co_nonce, co_fd);

  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  pthread_mutex_lock(&mutex_connection_key);
  if (mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_key);
    goto cleanup;
  }

  pthread_mutex_unlock(&mutex_connection_key);

  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;
cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief Bind the parameters for the database query to update the key by IP address and port number.
///
/// This function fills the parameter values required for a database query to update the connection key by IP address
/// and port number.
///
/// @param params Pointer to an array of MYSQL_BIND structures where the parameter values will be stored.
/// @param co_key The new connection key.
/// @param co_ip_addr The connection IP address in big-endian byte order.
/// @param co_port The connection port number in big-endian byte order.
static inline void fill_params_co_up_key_by_addr(MYSQL_BIND *params, const uint8_t *co_key, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  // param1: new connection key
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = (void*)co_key;
  params[0].buffer_length = crypto_secretbox_KEYBYTES;

  // param2: connection ip address BIG ENDIAN BYTE ORDER
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_ip_addr;
  params[1].buffer_length = SIZE_IP_ADDR;

  // param3: connection port BIG ENDIAN BYTE ORDER
  params[2].buffer_type = MYSQL_TYPE_SHORT;
  params[2].buffer = (void*)&co_port;
  params[2].buffer_length = sizeof co_port;
}

/// @brief Update connection key by IP address and port number.
///
/// This function updates the connection key in the database based on the provided IP address and port number.
///
/// @param db_connect The MYSQL database connection.
/// @param co_key The new connection key.
/// @param co_ip_addr The connection IP address in big-endian byte order.
/// @param co_port The connection port number in big-endian byte order.
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to initialize the statement,
///       prepare the query, bind parameters, or execute the statement.
errcode_t db_co_up_key_by_addr(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[3];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_KEY_BY_ADDR, QUERY_CO_UP_KEY_BY_ADDR_LEN))
    goto cleanup;

  bzero((void*)params, sizeof params);
  fill_params_co_up_key_by_addr(params, co_key, co_ip_addr, co_port);

  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  pthread_mutex_lock(&mutex_connection_key);
  if (mysql_stmt_execute(stmt)){
    pthread_mutex_unlock(&mutex_connection_key);
    goto cleanup;
  }
  pthread_mutex_unlock(&mutex_connection_key);

  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;
cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


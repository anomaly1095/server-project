#include "../include/database.h"

//===============================================
//              AUTHENTICATION
//===============================================


/// @brief get database hostname from admin
static inline errcode_t db_get_auth_host(char *host)
{
  printf("db hostname: ");
  if (!fgets(host, DB_SIZE_HOST-1, stdin))
    return __FAILURE__;
  host[strlen(host) - 1] = 0x0; // removing \n
  return __SUCCESS__;
}


/// @brief get database username from admin
static inline errcode_t db_get_auth_user(char *user)
{
  printf("db username: ");
  if (!fgets(user, DB_SIZE_USER-1, stdin))
    return __FAILURE__;
  user[strlen(user) - 1] = 0x0; // removing \n
  return __SUCCESS__;
}


/// @brief get database password from admin
static inline errcode_t db_get_auth_pass(char *passwd)
{
  printf("db password: ");
  char *input = getpass("");
  strncpy(passwd, input, DB_SIZE_PASS - 1);
  passwd[strlen(passwd) - 1] = 0x0; // removing \n
  return __SUCCESS__;
}


/// @brief get database name from admin
static inline errcode_t db_get_auth_db(char *db)
{
  printf("db name: ");
  if (!fgets(db, DB_SIZE_DB-1, stdin))
    return __FAILURE__;
  db[strlen(db) - 1] = 0x0; // removing \n
  return __SUCCESS__;
}


/// @brief perform realtime authentication from admin (step 2 authentication)
/// @param creds credentials struct containing (username, password, host...)
static inline errcode_t db_get_auth(db_creds_t *creds)
{
  memset((void*)creds, 0x0, sizeof creds);
  if (db_get_auth_host(creds->host))
    return LOG(DB_LOG_PATH, EDB_W_HOST, EDB_W_HOST_M);
  if (db_get_auth_user(creds->user))
    return LOG(DB_LOG_PATH, EDB_W_USER, EDB_W_USER_M);
  if (db_get_auth_pass(creds->passwd))
    return LOG(DB_LOG_PATH, EDB_W_PASSWD, EDB_W_PASSWD_M);
  if (db_get_auth_db(creds->db))
    return LOG(DB_LOG_PATH, EDB_W_DB, EDB_W_DB_M);
  creds->port = 3306;
  return __SUCCESS__;
}



//===============================================
//            INITIALISATION
//===============================================

/// @brief connects to the database
/// @param db_connect MYSQL db connection
errcode_t db_init(MYSQL **db_connect)
{
  db_creds_t creds;
  // initialize db
  if ( !(*db_connect = mysql_init(NULL)))
    return LOG(DB_LOG_PATH, EDB_CO_INIT, EDB_CO_INIT_M);
  // get admin creds
  if (db_get_auth(&creds))
    return EDB_AUTH;
  // connect to db
  if (!mysql_real_connect(*db_connect, creds.host, creds.user, creds.passwd, creds.db, creds.port, NULL, 0x0))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  return __SUCCESS__;
}


//===========================================================================================================
//ASYMMETRIC QUERIES:QUERY_KEY_INSERT /QUERY_KEY_DELETE /QUERY_SELECT_PK /QUERY_SELECT_SK /QUERY_SELECT_PK_SK
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

/// @brief writing the keys to the database
/// @param pk public key
/// @param sk secure key
/// @param db_connect MYSQL database connection
static errcode_t secu_key_save(uint8_t *pk, uint8_t *sk, MYSQL *db_connect)
{
  MYSQL_STMT *stmt; // statement handle
  MYSQL_BIND params[2]; // Array to hold parameter information (pk, sk)
  bzero((void*)params, sizeof params); // Initialize the param structs

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
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

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


/// @brief Fill the parameter values for pk
/// @param result query results
static inline void fill_result_KEY_SELECT_PK(MYSQL_BIND *result, uint8_t *pk)
{
  result->buffer_type = MYSQL_TYPE_BLOB;
  result->buffer = pk;
  result->buffer_length = crypto_box_PUBLICKEYBYTES;
}

/// @brief get public key from database
/// @param db_connect MYSQL db connection
/// @param pk public key
errcode_t db_get_pk(MYSQL *db_connect, uint8_t *pk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result;
  bzero((void*)&result, sizeof result); // Initialize the result structure


  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK, QUERY_SELECT_PK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_result_KEY_SELECT_PK(&result, pk);

  if (mysql_stmt_bind_result(stmt, &result))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

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


/// @brief Fill the parameter values for sk 
/// @param result query results
static inline void fill_result_KEY_SELECT_SK(MYSQL_BIND *result, uint8_t *sk)
{
  result->buffer_type = MYSQL_TYPE_BLOB;
  result->buffer = sk;
  result->buffer_length = crypto_box_SECRETKEYBYTES;
}

/// @brief get secret key from database
/// @param db_connect MYSQL db connection
/// @param pk secret key
errcode_t db_get_sk(MYSQL *db_connect, uint8_t *sk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result;
  bzero((void*)&result, sizeof result); // Initialize the result structure

  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_SK, QUERY_SELECT_SK_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_result_KEY_SELECT_SK(&result, sk);

  if (mysql_stmt_bind_result(stmt, &result))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

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


/// @brief Fill the parameter values for pk and sk
/// @param result query results
static inline void fill_result_KEY_SELECT_PK_SK(MYSQL_BIND *result, uint8_t *pk, uint8_t *sk)
{
  result[0].buffer_type = MYSQL_TYPE_BLOB;
  result[0].buffer = pk;
  result[0].buffer_length = crypto_box_PUBLICKEYBYTES;
  
  result[1].buffer_type = MYSQL_TYPE_BLOB;
  result[1].buffer = sk;
  result[1].buffer_length = crypto_box_SECRETKEYBYTES;
}

/// @brief get public key & secret key from database
/// @param db_connect MYSQL db connection
/// @param pk public key
/// @param sk secret key
errcode_t db_get_pk_sk(MYSQL *db_connect, uint8_t *pk, uint8_t *sk)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND result[2];
  bzero((void*)result, sizeof result); // Initialize the result structure

  // initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_SELECT_PK_SK, QUERY_SELECT_PK_SK_LEN))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
  
  // Fill the parameter values for pk and sk
  fill_result_KEY_SELECT_PK_SK(result, pk, sk);

  if (mysql_stmt_bind_result(stmt, result))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

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

/// @brief fill parameters of the insert connection query
/// @param params parameters of the statement
/// @param co_new new connection object 
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

//---------------------------DELETE

/// @brief fill parameters of the delete connection by addr query
/// @param params parameters of the statement
/// @param co_ip_addr BIG ENDIAN binary ip address
/// @param co_port BIG ENDIAN port of the connection
static inline void fill_params_co_del_byaddr(MYSQL_BIND *params, uint8_t *co_ip_addr, const int16_t co_port)
{
  // FILE DESCRIPTOR
  params[0].buffer_type = MYSQL_TYPE_BLOB;
  params[0].buffer = co_ip_addr;
  params[0].buffer_length = SIZE_IP_ADDR;

  // AUTHENTICATION STEP
  params[1].buffer_type = MYSQL_TYPE_SHORT;
  params[1].buffer = &co_port;
  params[1].buffer_length = sizeof co_port;
}

/// @brief function to delete connection by address from database
/// @param db_connect MYSQL database connection
/// @param co_ip_addr BIG ENDIAN binary ip address
/// @param co_port BIG ENDIAN port of the connection
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


/// @brief function to delete connection from database by id
/// @param db_connect MYSQL database connection
/// @param co_id connection id
errcode_t db_co_del_byid(MYSQL *db_connect, const id64_t co_id)
{
    char query[QUERY_CO_DEL_BYID_LEN + 24];

    // Construct the query
    sprintf(query, QUERY_CO_DEL_BYID, co_id);
    
    // Execute the query
    if (!mysql_real_query(db_connect, query, strlen(query)))
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
    return __SUCCESS__;
}


/// @brief function to delete all connection rows that where not connected for ... hours (set in the database header query)
/// @param db_connect MYSQL database connection
errcode_t db_co_cleanup(MYSQL *db_connect)
{
  if (mysql_real_query(db_connect, QUERY_CO_CLEANUP, QUERY_CO_CLEANUP_LEN))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  return __SUCCESS__;
}


/// @brief function to reset the Connection table 
/// @param db_connect MYSQL database connection
errcode_t db_co_res(MYSQL *db_connect)
{
  // Execute the query
  if (mysql_real_query(db_connect, QUERY_CO_RESET, QUERY_CO_RESET_LEN))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  // Execute the query to reset the auto-increment ID
  if (mysql_real_query(db_connect, QUERY_CO_RES_ID, QUERY_CO_RES_ID_LEN))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  return __SUCCESS__;
}


//---------------------------SELECT

/// @brief binding thge result columns of the select function queries
/// @param result result to bind (7 columns)
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
}

/// @brief FUNCTION TO copy the dataa fetched in the result sql object to the connection object
/// @param co connection object
/// @param result result fetched from the database after the query
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
}


/// @attention Memory will be allocated internally for co object
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_id id of the connection
errcode_t db_co_sel_all_by_id(MYSQL *db_connect, co_t **co, const id64_t co_id)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(db_connect), mysql_stmt_error(db_connect));

  // Prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_SEL_ALL_BY_ID, QUERY_CO_SEL_ALL_BY_ID_LEN))
    goto cleanup;

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
    bzero((void*)result[CO_NROWS-1].buffer, crypto_secretbox_KEYBYTES));
    ++i;
  }

  for (i = 0; i < CO_NROWS; ++i)
    free(result[i].buffer);
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


/// @attention Memory will be allocated internally for co objects and nrow set internally
/// @attention Should only be used in case of short interval db_cleanups 
/// @brief get all columns of all rows matching co_fd
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param nrow number of rows returned by the query 
/// @param co_fd file descriptor number we are looking for
errcode_t db_co_sel_all_by_fd(MYSQL *db_connect, co_t **co, size_t *nrow, const sockfd_t co_fd)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(db_connect), mysql_stmt_error(db_connect));

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


/// @attention Memory will be allocated internally
/// @brief get all columns by connection / authenticcation status
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param nrow number of rows returned by the query 
/// @param co_auth_status connection status
errcode_t db_co_sel_all_by_auth_stat(MYSQL *db_connect, co_t **co, size_t *nrow, const flag_t co_auth_status)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND param;
  MYSQL_BIND result[CO_NROWS]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(db_connect), mysql_stmt_error(db_connect));

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

/// @attention Memory will be allocated internally for co objects and nrow set internally
/// @brief get all columns by ip address
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param nrow number of rows returned by the query 
/// @param co_ip_addr ip address big endian byte order
/// @param co_port connection port number big endian byte order
errcode_t db_co_sel_all_by_addr(MYSQL *db_connect, co_t **co, size_t *nrow, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];
  MYSQL_BIND result[]; // Number of columns in the result set
  size_t i;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(db_connect), mysql_stmt_error(db_connect));

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

/// @attention Memory will be allocated internally for co objects and nrow set internally
/// @brief get symmetric key for client that has that address pair (ip, port)
/// @param db_connect MYSQL database connection
/// @param key symmetric key
/// @param co_ip_addr connection ip address big endian byte order
/// @param co_port  connection port big endian byte order
errcode_t db_co_sel_key_by_addr(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_ip_addr, const in_port_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2]; // Number of columns in the result set
  MYSQL_BIND result;

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(db_connect), mysql_stmt_error(db_connect));

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
  result.buffer_type = MYSQL_TYPE_BLOB;
  result.buffer = co_key;
  result.buffer_length = crypto_secretbox_KEYBYTES;

  if (mysql_stmt_bind_result(stmt, &result))
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
  if (!mysql_stmt_fetch(stmt))
    memcpy((void*)co_key, (const void*)result.buffer, crypto_secretbox_KEYBYTES);

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


//---------------------------UPDATE

/// @brief update connection file descriptor to <co_fd> has id <co_id>
/// @param db_connect MYSQL database connection
/// @param co_fd connection file descriptor
/// @param co_fd connection id
errcode_t db_co_up_fd_by_id(MYSQL *db_connect, sockfd_t co_fd, id64_t co_id)
{
  char query[QUERY_CO_UP_FD_BY_ID_LEN + 24 + 16];
  sprintf(query, QUERY_CO_UP_FD_BY_ID, co_fd, co_id);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  return __SUCCESS__;
}

/// @brief update connection file descriptor to <co_fd_new> has fd <co_fd>
/// @param db_connect MYSQL database connection
/// @param co_fd_new new connection file descriptor
/// @param co_fd connection file descriptor
errcode_t db_co_up_fd_by_fd(MYSQL *db_connect, const sockfd_t co_fd_new, sockfd_t co_fd);
{
  char query[QUERY_CO_UP_FD_BY_FD_LEN + 16 + 16];
  sprintf(query, QUERY_CO_UP_FD_BY_FD, co_fd_new, co_fd);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  return __SUCCESS__;
}


/// @brief bind the parameters for the database query
/// @param params parameters
/// @param co_fd socket file descriptor
/// @param co_ip_addr connection ip address BIG ENDIAN BYTE ORDER
/// @param co_port conenction port number BIG ENDIAN BYTE ORDER
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

/// @brief update connection file descriptor of the <co_ip_addr co_port> address pair
/// @param db_connect MYSQL database connection
/// @param co_fd socket file descriptor
/// @param co_ip_addr connection ip address BIG ENDIAN
/// @param co_port connection port BIG ENDIAN
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


/// @brief update connection row to <co_auth_status> status that has id = <co_id>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_id connection id
errcode_t db_co_up_auth_stat_by_id(MYSQL *db_connect, flag_t co_auth_status, id64_t co_id)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID_LEN + 24 + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID, co_auth_status, co_id);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  
  return __SUCCESS__;
}


/// @brief update connection row to <co_auth_status> status that has fd = <co_fd>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_id file descriptor
inline errcode_t db_co_up_auth_stat_by_fd(MYSQL *db_connect, flag_t co_auth_status, sockfd_t co_fd)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD_LEN + 24 + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD, co_auth_status, co_fd);
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
  
  return __SUCCESS__;
}


/// @brief bindthe parameters for the database query
/// @param params parameters to bind for the query
/// @param co_auth_status new authentication status to set
/// @param co_ip_addr connection ip address BIG ENDIAN BYTE ORDER
/// @param co_port conenction port number BIG ENDIAN BYTE ORDER
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

/// @brief update connection row to <co_auth_status> status that have idaddr = <co_ip_addr> and portnum = <co_port>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_ip_addr connection ip address BIG ENDIAN
/// @param co_port connection port BIG ENDIAN
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


/// @brief update connection rows to <co_auth_status> status to disconnected that last connected <hours> hours ago
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param hours hours of interval with last connection
errcode_t db_co_up_auth_stat_by_last_co(MYSQL *db_connect)
{
  char query[QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO_LEN + 8];
  sprintf(query, QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO, CO_FLAG_DISCO);
  
  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)))
    return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  return __SUCCESS__;
}


/// @brief bind the parameters for the database query
/// @param params parameters
/// @param co_key symmetric key sent by the client
/// @param co_id id of the instance in the db
static inline void fill_params_co_up_key_by_id(MYSQL_BIND *params, const uint8_t *co_key, id64_t co_id)
{
  // param1: new connection key
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_key;
  params[1].buffer_length = crypto_secretbox_KEYBYTES;

  // param2: connection id 
  params[0].buffer_type = MYSQL_TYPE_LONGLONG;
  params[0].buffer = (void*)&co_id;
  params[0].buffer_length = sizeof co_id;

}

/// @brief 
/// @param db_connect 
/// @param co_key 
/// @param co_id 
/// @return 
errcode_t db_co_up_key_by_id(MYSQL *db_connect, const uint8_t *co_key, id64_t co_id)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_KEY_BY_ID, QUERY_CO_UP_KEY_BY_ID_LEN))
    goto cleanup;

  bzero((void*)params, sizeof params);
  fill_params_co_up_key_by_id(params, co_key, co_id);

  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;
  
  if (mysql_stmt_execute(stmt))
    goto cleanup;
    
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;

cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief bind the parameters for the database query
/// @param params parameters
/// @param co_fd socket file descriptor
/// @param co_ip_addr connection ip address BIG ENDIAN BYTE ORDER
/// @param co_port conenction port number BIG ENDIAN BYTE ORDER
static inline void fill_params_co_up_key_by_fd(MYSQL_BIND *params, const uint8_t *co_key, sockfd_t co_fd)
{
  // param1: new connection key
  params[1].buffer_type = MYSQL_TYPE_BLOB;
  params[1].buffer = (void*)co_key;
  params[1].buffer_length = crypto_secretbox_KEYBYTES;

  // param2: connection id 
  params[0].buffer_type = MYSQL_TYPE_LONG;
  params[0].buffer = (void*)&co_fd;
  params[0].buffer_length = sizeof co_fd;
}

/// @brief 
/// @param db_connect 
/// @param co_key 
/// @param co_fd 
/// @return 
errcode_t db_co_up_key_by_fd(MYSQL *db_connect, const uint8_t *co_key, sockfd_t co_fd)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];

  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  if (mysql_stmt_prepare(stmt, QUERY_CO_UP_KEY_BY_FD, QUERY_CO_UP_KEY_BY_FD_LEN))
    goto cleanup;

  bzero((void*)params, sizeof params);
  fill_params_co_up_key_by_fd(params, co_key, co_fd);

  if (mysql_stmt_bind_param(stmt, params))
    goto cleanup;

  if (mysql_stmt_execute(stmt))
    goto cleanup;

  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;
cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


/// @brief bind the parameters for the database query
/// @param params parameters
/// @param co_fd socket file descriptor
/// @param co_ip_addr connection ip address BIG ENDIAN BYTE ORDER
/// @param co_port conenction port number BIG ENDIAN BYTE ORDER
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

/// @brief 
/// @param db_connect 
/// @param co_key 
/// @param co_ip_addr 
/// @param co_port 
/// @return 
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

  if (mysql_stmt_execute(stmt))
    goto cleanup;

  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return __SUCCESS__;
cleanup:
  bzero((void*)params, sizeof params);
  mysql_stmt_close(stmt);
  return LOG(DB_LOG_PATH, mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
}


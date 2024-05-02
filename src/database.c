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
    return LOG(DB_LOG_PATH, EDB_W_HOST, "Error getting host");
  if (db_get_auth_user(creds->user))
    return LOG(DB_LOG_PATH, EDB_W_USER, "Error getting username");
  if (db_get_auth_pass(creds->passwd))
    return LOG(DB_LOG_PATH, EDB_W_PASSWD, "Error getting password");
  if (db_get_auth_db(creds->db))
    return LOG(DB_LOG_PATH, EDB_W_DB, "Error getting database name");
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
    return LOG(DB_LOG_PATH, EDB_CO_INIT, "Database error during db_connect");
  // get admin creds
  if (db_get_auth(&creds))
    return EDB_AUTH;
  // connect to db
  if (!mysql_real_connect(*db_connect, creds.host, creds.user, creds.passwd, creds.db, creds.port, NULL, 0x0))
    return LOG(DB_LOG_PATH, EDB_CONNECT, "Error connecting to database");

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


/// @brief Fill the parameter values for pk
/// @param result query results
static inline void fill_params_KEY_SELECT_PK(MYSQL_BIND *result, uint8_t *pk)
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


/// @brief Fill the parameter values for sk 
/// @param result query results
static inline void fill_params_KEY_SELECT_SK(MYSQL_BIND *result, uint8_t *sk)
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
inline errcode_t secu_key_del(MYSQL *db_connect)
{
  if (mysql_query(db_connect, QUERY_KEY_DELETE))
    return LOG(DB_LOG_PATH, (int32_t)mysql_errno(db_connect), mysql_error(db_connect));
  return __SUCCESS__;
}



//==========================================================================
//                  CRUD NEW CONNECTONS
//==========================================================================

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
}

/// @brief function to insert new connection in database
/// @param db_connect MYSQL database connection
/// @param co_new new connection object
errcode_t db_co_insert(MYSQL *db_connect, co_t co_new)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[5];
  bzero((void*)params, sizeof params);
  //initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_INSERT, QUERY_CO_INSERT_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Fill the parameter values for pk and sk
  fill_params_co_insert(params, co_new);

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


/// @brief fill parameters of the delete connection by addr query
/// @param params parameters of the statement
/// @param co_ip_addr BIG ENDIAN binary ip address
/// @param co_port BIG ENDIAN port of the connection
static inline void fill_params_co_del_byaddr(MYSQL_BIND *params, uint8_t *co_ip_addr, int16_t co_port)
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
errcode_t db_co_del_byaddr(MYSQL *db_connect, uint8_t *co_ip_addr, int16_t co_port)
{
  MYSQL_STMT *stmt;
  MYSQL_BIND params[2];
  bzero((void*)params, sizeof params);

  //initialize the statement
  if (!(stmt = mysql_stmt_init(db_connect)))
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // prepare the statement
  if (mysql_stmt_prepare(stmt, QUERY_CO_DEL_BYADDR, QUERY_CO_DEL_BYADDR_LEN) != 0)
    return LOG(DB_LOG_PATH, (int32_t)mysql_stmt_errno(stmt), mysql_stmt_error(stmt));

  // Fill the parameter values for pk and sk
  fill_params_co_del_byaddr(params, co_ip_addr, co_port);

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


/// @brief minimalistic function to delete connection from database by id
/// @param db_connect MYSQL database connection
/// @param co_id connection id
inline errcode_t db_co_del_byid(MYSQL *db_connect, id64_t co_id)
{
    char query[QUERY_CO_DEL_BYID_LEN + 24];

    // Construct the query
    sprintf(query, QUERY_CO_DEL_BYID, co_id);
    
    // Execute the query
    if (!mysql_real_query(db_connect, query, strlen(query)))
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));
    return __SUCCESS__;
}


/// @attention Memory will be allocated internally
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_id id of the connection
errcode_t db_co_get_all_by_id(MYSQL *db_connect, co_t *co, id64_t co_id)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  char query[QUERY_CO_SELECT_ALL_BY_ID_LEN + 24];

  // Construct the query
  sprintf(query, QUERY_CO_SELECT_ALL_BY_ID, co_id);

  // Execute the query
  if (mysql_real_query(db_connect, query, strlen(query)) != 0)
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  // Store the result set
  if (!(res = mysql_store_result(db_connect)))
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect));

  // Fetch the row
  row = mysql_fetch_row(res);
  if (!row){
      mysql_free_result(res);
      return LOG(DB_LOG_PATH, mysql_errno(db_connect), mysql_error(db_connect)); // Row not found
  }

  co = (co_t*)malloc(sizeof co);
  co->co_id = co_id;
  co->co_fd = atoi(row[1]);   // Convert char* to int32_t
  co->co_auth_status = row[2];// uint8_t
  memcpy((void*)co->co_last_co, (const void*)row[3], SIZE_MYSQL_DT);
  co->co_last_co = row[3];


  // Free the result set
  mysql_free_result(res);

  return __SUCCESS__;
}



/// @attention Memory will be allocated internally
/// @attention Should only be used in case of short interval db_cleanups 
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_fd file descriptor number we are looking for
errcode_t db_co_get_all_by_fd(MYSQL *db_connect, co_t *co, size_t *nrow, sockfd_t co_fd)
{

}


/// @attention Memory will be allocated internally
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_auth_status 
errcode_t db_co_get_all_by_authstat(MYSQL *db_connect, co_t *co, size_t *nrow, flag_t co_auth_status)
{

}


/// @attention Memory will be allocated internally
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_ip_addr
errcode_t db_co_get_all_by_ip(MYSQL *db_connect, co_t *co, size_t *nrow, uint8_t *co_ip_addr)
{

}


errcode_t db_co_cleanup(MYSQL *db_connect)
{

}
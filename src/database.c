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
  host[strlen(host) - 1] = 0x0;
  return __SUCCESS__;
}

/// @brief get database username from admin
static inline errcode_t db_get_auth_user(char *user)
{
  printf("db username: ");
  if (!fgets(user, DB_SIZE_USER-1, stdin))
    return __FAILURE__;
  user[strlen(user) - 1] = 0x0;
  return __SUCCESS__;
}

/// @brief get database password from admin
static inline errcode_t db_get_auth_pass(char *passwd)
{
  printf("db password: ");
  char *input = getpass("");
  strncpy(passwd, input, DB_SIZE_PASS - 1);
  passwd[strlen(passwd) - 1] = 0x0;
  return __SUCCESS__;
}
/// @brief get database name from admin
static inline errcode_t db_get_auth_db(char *db)
{
  printf("db name: ");
  if (!fgets(db, DB_SIZE_DB-1, stdin))
    return __FAILURE__;
  db[strlen(db) - 1] = 0x0;
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

//===============================================
//                  DATA_IO
//===============================================


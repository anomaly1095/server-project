

#ifndef DATABASE_H
#define DATABASE_H      1
#include "security.h"

// DB ERRORS: 200->300
// many errnos are defined in MYSQL API
#define EDB_LOG         200
#define EDB_CO_INIT     201 
    
#define EDB_GET_PKEY    205
#define EDB_FOPEN       206
#define EDB_FREAD       207
#define EDB_AUTH        208
#define EDB_W_HOST      209
#define EDB_W_USER      210
#define EDB_W_PASSWD    211
#define EDB_W_DB        212
#define EDB_W_PORT      213
#define EDB_CONNECT     214
    
#define DB_SIZE_HOST    256
#define DB_SIZE_USER    33
#define DB_SIZE_PASS    33
#define DB_SIZE_DB      65
#define SIZE_MYSQL_DT   20 // mysql datetime
#define SIZE_IP_ADDR    16 // mysql datetime

///@brief BIGINT FOR THE ID
typedef uint64_t id64_t;
typedef uint32_t id32_t;


///@brief DATABASE CREDENTIALS FOR AUTHENTICATION 
typedef struct DBCreds
{
    char host[DB_SIZE_HOST];
    char user[DB_SIZE_USER];
    char passwd[DB_SIZE_PASS];
    char db[DB_SIZE_DB];
    uint32_t port;
}db_creds_t;


///     TABLE TO HOLD PRIMARY KEY & SECRET KEY

///@brief key table
// CREATE TABLE KeyPairs (
//     pk BINARY(32) NOT NULL,
//     sk BINARY(32) NOT NULL,
//     PRIMARY KEY (pk, sk)
// );


///@brief QUERIES TO THE DATABASE
#define QUERY_KEY_DELETE    "DELETE FROM KeyPairs;"

#define QUERY_KEY_INSERT    "INSERT INTO KeyPairs (pk, sk) VALUES (?, ?);"
#define QUERY_KEY_INSERT_LEN (__builtin_strlen(QUERY_KEY_INSERT))

#define QUERY_SELECT_PK     "SELECT pk FROM KeyPairs;"
#define QUERY_SELECT_PK_LEN (__builtin_strlen(QUERY_SELECT_PK))

#define QUERY_SELECT_SK     "SELECT sk FROM KeyPairs;"
#define QUERY_SELECT_SK_LEN (__builtin_strlen(QUERY_SELECT_SK))

#define QUERY_SELECT_PK_SK  "SELECT pk, sk FROM KeyPairs;"
#define QUERY_SELECT_PK_SK_LEN (__builtin_strlen(QUERY_SELECT_PK_SK))

///   CONNECTION OBJECT

/// @brief individual connection table
// CREATE TABLE Connection (
//     co_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
//     co_fd INT NOT NULL,
//     co_auth_status TINYINT UNSIGNED, -- Nullable
//     co_last_co DATETIME, -- Nullable
//     co_af SMALLINT UNSIGNED, -- Nullable
//     co_port SMALLINT UNSIGNED, -- Nullable
//     co_ip_addr BINARY(16) -- Nullable
// );

///@brief CONNECTION 
typedef struct Connection
{
  uint64_t co_id;
  sockfd_t co_fd;
  flag_t co_auth_status;  // steps of authentication
  char co_last_co[SIZE_MYSQL_DT];
  uint16_t co_af;  // address family
  uint16_t co_port;  // port
  uint8_t co_ip_addr[SIZE_IP_ADDR]; // fits ipv4 or ipv6
}co_t;


///@brief query to delete from database by id
#define QUERY_CO_DEL_BYID   "DELETE FROM Connection WHERE id = %llu;"
#define QUERY_CO_DEL_BYID_LEN \
(__builtin_strlen(QUERY_CO_DEL_BYID))

///@brief query to delete from database by ip address and port num
#define QUERY_CO_DEL_BYADDR "DELETE FROM Connection WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_DEL_BYADDR_LEN \
(__builtin_strlen(QUERY_CO_DEL_BYADDR))

///@brief query to add new connection to database 
#define QUERY_CO_INSERT     "INSERT INTO Connection \
(co_fd, co_auth, co_last_co, co_af, co_port, co_ip_addr) \
VALUES (?, ?, NOW(), ?, ?, ?);"
#define QUERY_CO_INSERT_LEN \
(__builtin_strlen(QUERY_CO_INSERT))

///@brief query to get all data by id 
#define QUERY_CO_SELECT_ALL_BY_ID "SELECT * FROM Connection WHERE co_id = %llu;"
#define QUERY_CO_SELECT_ALL_BY_ID_LEN \
(__builtin_strlen(QUERY_CO_SELECT_ALL_BY_ID))

///@brief query to get all data by file descriptor
#define QUERY_CO_SELECT_ALL_BY_FD ";"
#define QUERY_CO_SELECT_ALL_BY_FD_LEN \
(__builtin_strlen(QUERY_CO_SELECT_ALL_BY_FD))

///@brief query to get all data by authentication status 
#define QUERY_CO_SELECT_ALL_BY_AUTH_STAT ";"
#define QUERY_CO_SELECT_ALL_BY_AUTH__STAT_LEN \
(__builtin_strlen(QUERY_CO_SELECT_ALL_BY_AUTH_STAT))

///@brief query to get all data with ip address
#define QUERY_CO_SELECT_ALL_BY_IP ";"
#define QUERY_CO_SELECT_ALL_BY_IP_LEN \
(__builtin_strlen(QUERY_CO_SELECT_ALL_BY_IP))



//---------DATABASE RELATED FUNCTIONS------------

/// @brief Initializee the database
/// @param db_connect MYSQL db connection
errcode_t db_init(MYSQL **db_connect);

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
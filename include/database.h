

#ifndef DATABASE_H
#define DATABASE_H      1
#include "security.h"



#define SIZE_MYSQL_DT   sizeof(MYSQL_TIME) // mysql datetime
#define SIZE_IP_ADDR    16 // mysql datetime

///@brief DATABASE ID TYPES 
typedef unsigned long long int id64_t;
typedef uint32_t id32_t;

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

//==========================================================================
//                       DB CREDENTIALS SECTION
//==========================================================================

///@brief DATABASE CREDENTIALS FOR AUTHENTICATION 
typedef struct DBCreds
{
    char host[DB_SIZE_HOST];
    char user[DB_SIZE_USER];
    char passwd[DB_SIZE_PASS];
    char db[DB_SIZE_DB];
    uint32_t port;
}db_creds_t;

/// @brief Initialize the database
/// @param db_connect MYSQL db connection
errcode_t db_init(MYSQL **db_connect);

/// used by the new-db module
#define QUERY_NEW_DB "CREATE DATABASE %s;"

/// used by the new-db module
#define QUERY_CREATE_CO "CREATE TABLE Connection (\
  co_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,\
  co_fd INT NOT NULL DEFAULT 4,\
  co_auth_status TINYINT UNSIGNED NOT NULL DEFAULT 0,\
  co_last_co DATETIME NOT NULL DEFAULT '0000-00-00 00:00:00',\
  co_af SMALLINT UNSIGNED NOT NULL DEFAULT 0,\
  co_port SMALLINT UNSIGNED NOT NULL DEFAULT 0,\
  co_ip_addr BINARY(16) NOT NULL DEFAULT 0x0,\
  co_key BINARY(32) NOT NULL DEFAULT 0x0,\
  co_nonce BINARY(24) NOT NULL DEFAULT 0x0\
);"

/// used by the new-db module
#define QUERY_CREATE_KEYPAIR "CREATE TABLE `KeyPairs` (\
  `pk` binary(32) NOT NULL,\
  `sk` binary(32) NOT NULL,\
  PRIMARY KEY (`pk`,`sk`)\
);"

#define MAX_QUERY_LENGTHX 64

//==========================================================================
//                       ASYMMETRIC KEYS SECTION
//==========================================================================


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



//==========================================================================
//                       NETWORK CONNECTION OBJECT
//==========================================================================


///@brief CONNECTION STRUCT
typedef struct Connection
{
  uint64_t co_id;
  sockfd_t co_fd;
  flag_t co_auth_status;  // steps of authentication
  MYSQL_TIME co_last_co;
  sa_family_t co_af;  // address family
  in_port_t co_port;  // port
  uint8_t co_ip_addr[SIZE_IP_ADDR]; // fits ipv4 or ipv6 BIG ENDIAN
  uint8_t co_key[crypto_secretbox_KEYBYTES]; // symmetric key
  uint8_t co_nonce[crypto_secretbox_NONCEBYTES]; // random bytes
}co_t;
#define CO_NROWS 9

//----VALUES OF THE co_auth_status FLAG---
/// @brief the client has connected but not done any authentication steps
#define CO_FLAG_NO_AUTH     0b00000000 
/// @brief the client received the public key
#define CO_FLAG_RECVD_PK    0b00000001 
/// @brief the client has sent the encrypted key and the nonce
#define CO_FLAG_SENT_KEY    0b00000010 
/// @brief the client has received the encrypted ping
#define CO_FLAG_SENT_PING  0b00000100 
/// @brief the client has responded with the correct ping
#define CO_FLAG_RECV_PING   0b00001000 
/// @brief the client is fully authenticated
#define CO_FLAG_AUTH        0b00010000 
/// @brief the client has disconnected
#define CO_FLAG_DISCO       0b00100000 
/// @brief the client has made a repeated 3 times mistake during decryption or encryption (ADD to BLACKLIST)
#define CO_FLAG_INSECURE    0b01000000 
/// @brief the client ....
#define CO_FLAG_STEP8       0b10000000 


#define FD_DISCO            -1
//---------------------------INSERT

///@brief query to add new connection to database 
#define QUERY_CO_INSERT     "INSERT INTO Connection \
(co_fd, co_auth_status, co_last_co, co_af, co_port, co_ip_addr, co_key, co_nonce) \
VALUES (?, ?, NOW(), ?, ?, ?, ?, ?);"
#define QUERY_CO_INSERT_LEN \
(__builtin_strlen(QUERY_CO_INSERT))

/// @brief function to insert new connection in database
/// @param db_connect MYSQL database connection
/// @param co_new new connection object
errcode_t db_co_insert(MYSQL *db_connect, const co_t co_new);

//---------------------------DELETE

///@brief query to delete from database by id
#define QUERY_CO_DEL_BYID   "DELETE FROM Connection WHERE id = %llu;"
#define QUERY_CO_DEL_BYID_LEN \
(__builtin_strlen(QUERY_CO_DEL_BYID))

/// @brief function to delete connection from database by id
/// @param db_connect MYSQL database connection
/// @param co_id connection id
errcode_t db_co_del_byid(MYSQL *db_connect, const id64_t co_id);

//--------------------

///@brief query to delete from database by fd
#define QUERY_CO_DEL_BYFD   "DELETE FROM Connection WHERE fd = %d;"
#define QUERY_CO_DEL_BYFD_LEN \
(__builtin_strlen(QUERY_CO_DEL_BYFD))

/// @brief function to delete connection from database by id
/// @param db_connect MYSQL database connection
/// @param co_fd connection fd
errcode_t db_co_del_byfd(MYSQL *db_connect, const sockfd_t co_fd);

//--------------------

///@brief query to delete from database by ip address and port num
#define QUERY_CO_DEL_BYADDR "DELETE FROM Connection WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_DEL_BYADDR_LEN \
(__builtin_strlen(QUERY_CO_DEL_BYADDR))

/// @brief function to delete connection by address from database
/// @param db_connect MYSQL database connection
/// @param co_ip_addr BIG ENDIAN binary ip address
/// @param co_port BIG ENDIAN port of the connection
errcode_t db_co_del_byaddr(MYSQL *db_connect, uint8_t *co_ip_addr, const int16_t co_port);

//--------------------

///@brief query to get all data by datetime of last connection
#define QUERY_CO_CLEANUP "DELETE FROM Connection WHERE \
co_last_co <= NOW() - INTERVAL " STR(CLEANUP_HOURS) " HOUR;"
#define QUERY_CO_CLEANUP_LEN \
(__builtin_strlen(QUERY_CO_CLEANUP))

/// @brief function to delete all connection rows that where not connected for ... hours (set in the database header query)
/// @param db_connect MYSQL database connection
errcode_t db_co_cleanup(MYSQL *db_connect);

//--------------------

#define QUERY_CO_RESET "DELETE FROM Connection"
#define QUERY_CO_RESET_LEN \
(__builtin_strlen(QUERY_CO_RESET))

#define QUERY_CO_RES_ID "ALTER TABLE Connection AUTO_INCREMENT = 1"
#define QUERY_CO_RES_ID_LEN \
(__builtin_strlen(QUERY_CO_RES_ID))

/// @brief function to reset the Connection table 
/// @param db_connect MYSQL database connection
errcode_t db_co_res(MYSQL *db_connect);


//---------------------------SELECT

///@brief query to get all data by id 
#define QUERY_CO_SEL_ALL_BY_ID "SELECT * FROM Connection WHERE co_id = %llu;"
#define QUERY_CO_SEL_ALL_BY_ID_LEN \
(__builtin_strlen(QUERY_CO_SEL_ALL_BY_ID))

/// @attention Memory will be allocated internally for co object
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param co_id id of the connection
errcode_t db_co_sel_all_by_id(MYSQL *db_connect, co_t **co, const id64_t co_id);

//--------------------

///@brief query to get all data by file descriptor
#define QUERY_CO_SEL_ALL_BY_FD "SELECT * FROM Connection WHERE co_fd = %d;"
#define QUERY_CO_SEL_ALL_BY_FD_LEN \
(__builtin_strlen(QUERY_CO_SEL_ALL_BY_FD))

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
errcode_t db_co_sel_all_by_fd(MYSQL *db_connect, co_t *co, const sockfd_t co_fd);
//--------------------

///@brief query to get all data by authentication status 
#define QUERY_CO_SEL_ALL_BY_AUTH_STAT "SELECT * FROM Connection WHERE co_auth_status = %u;"
#define QUERY_CO_SEL_ALL_BY_AUTH_STAT_LEN \
(__builtin_strlen(QUERY_CO_SEL_ALL_BY_AUTH_STAT))

/// @attention Memory will be allocated internally
/// @brief get all columns by id
/// @param db_connect MYSQL database connection
/// @param co non allocated connection object
/// @param nrow number of rows returned by the query 
/// @param co_auth_status 
errcode_t db_co_sel_all_by_auth_stat(MYSQL *db_connect, co_t **co, size_t *nrow, const flag_t co_auth_status);

//--------------------

///@brief query to get all data with ip address
#define QUERY_CO_SEL_ALL_BY_ADDR "SELECT * FROM Connection WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_SEL_ALL_BY_ADDR_LEN \
(__builtin_strlen(QUERY_CO_SEL_ALL_BY_ADDR))

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
errcode_t db_co_sel_all_by_addr(MYSQL *db_connect, co_t **co, size_t *nrow, const uint8_t *co_ip_addr, const in_port_t co_port);
//--------------------


///@brief query to get all data with ip address
#define QUERY_CO_SEL_KEY_BY_FD "SELECT co_key, co_nonce  FROM Connection WHERE co_fd = %d;"
#define QUERY_CO_SEL_KEY_BY_FD_LEN \
(__builtin_strlen(QUERY_CO_SEL_KEY_BY_FD))

/// @brief Get the symmetric key for the client that has the specified socket file descriptor.
///
/// @param db_connect The MYSQL database connection.
/// @param co_key Buffer to store the symmetric key.
/// @param co_fd connection socket file descriptor
///
/// @return 
///     - Returns __SUCCESS__ upon successful execution.
///     - Returns an error code if an error occurs, such as failure to execute the query.
errcode_t db_co_sel_key_by_fd(MYSQL *db_connect, uint8_t *co_key, uint8_t *co_nonce, sockfd_t co_fd);


//--------------------


///@brief query to get all data with ip address
#define QUERY_CO_SEL_KEY_BY_ADDR "SELECT co_key, co_nonce FROM Connection WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_SEL_KEY_BY_ADDR_LEN \
(__builtin_strlen(QUERY_CO_SEL_KEY_BY_ADDR))

/// @attention Memory will be allocated internally for co objects and nrow set internally
/// @brief get symmetric key for client that has that address pair (ip, port)
/// @param db_connect MYSQL database connection
/// @param co_key symmetric key
/// @param co_nonce random bytes
/// @param co_ip_addr connection ip address big endian byte order
/// @param co_port  connection port big endian byte order
errcode_t db_co_sel_key_by_addr(MYSQL *db_connect, uint8_t *co_key, uint8_t *co_nonce, const uint8_t *co_ip_addr, const in_port_t co_port);

//---------------------------UPDATE

#define QUERY_CO_UP_FD_BY_ID "UPDATE Connection \
SET co_fd = %d WHERE co_id = %llu;"
#define QUERY_CO_UP_FD_BY_ID_LEN \
(__builtin_strlen(QUERY_CO_UP_FD_BY_ID))

/// @brief update connection file descriptor to <co_fd> has id <co_id>
/// @param db_connect MYSQL database connection
/// @param co_fd connection file descriptor
/// @param co_id connection id
errcode_t db_co_up_fd_by_id(MYSQL *db_connect, sockfd_t co_fd, id64_t co_id);

//--------------------

#define QUERY_CO_UP_FD_BY_FD "UPDATE Connection \
SET co_fd = %d WHERE co_fd = %d;"
#define QUERY_CO_UP_FD_BY_FD_LEN \
(__builtin_strlen(QUERY_CO_UP_FD_BY_ID))

/// @brief update connection file descriptor to <co_fd_new> has fd <co_fd>
/// @param db_connect MYSQL database connection
/// @param co_fd connection file descriptor
/// @param co_fd_new new connection file descriptor
errcode_t db_co_up_fd_by_fd(MYSQL *db_connect, const sockfd_t co_fd_new, sockfd_t co_fd);

//--------------------

#define QUERY_CO_UP_FD_BYADDR "UPDATE Connection \
SET co_fd = ? WHERE co_ip_addr = ? and co_port = ?;"
#define QUERY_CO_UP_FD_BYADDR_LEN \
(__builtin_strlen(QUERY_CO_UP_FD_BYADDR))

/// @brief update connection file descriptor of the <co_ip_addr co_port> addresss pair
/// @param db_connect MYSQL database connection
/// @param co_fd socket file descriptor
/// @param co_ip_addr connection ip address BIG ENDIAN
/// @param co_port connection port BIG ENDIAN
errcode_t db_co_up_fd_by_addr(MYSQL *db_connect, sockfd_t co_fd, const uint8_t *co_ip_addr, const in_port_t co_port);

//--------------------

#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID "UPDATE Connection \
SET co_auth_status = %u WHERE co_id = %llu;"
#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID_LEN \
(__builtin_strlen(QUERY_CO_UP_AUTH_AUTH_STAT_BY_ID))

/// @brief update connection row to <co_auth_status> status that has id = <co_id>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_id connection id
errcode_t db_co_up_auth_stat_by_id(MYSQL *db_connect, flag_t co_auth_status, id64_t co_id);

//--------------------

#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD "UPDATE Connection \
SET co_auth_status = %u WHERE co_fd = %d;"
#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD_LEN \
(__builtin_strlen(QUERY_CO_UP_AUTH_AUTH_STAT_BY_FD))

/// @brief update connection row to <co_auth_status> status that has fd = <co_fd>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_id file descriptor
errcode_t db_co_up_auth_stat_by_fd(MYSQL *db_connect, flag_t co_auth_status, sockfd_t co_fd);

//--------------------

#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_ADDR "UPDATE Connection \
SET co_auth_status = ? WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_ADDR_LEN \
(__builtin_strlen(QUERY_CO_UP_AUTH_AUTH_STAT_BY_ADDR))

/// @brief update connection row to <co_auth_status> status that have idaddr = <co_ip_addr> and portnum = <co_port>
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param co_ip_addr connection ip address BIG ENDIAN
/// @param co_port connection port BIG ENDIAN
errcode_t db_co_up_auth_stat_by_addr(MYSQL *db_connect, flag_t co_auth_status, const uint8_t *co_ip_addr, const in_port_t co_port);

//--------------------

#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO "UPDATE Connection \
SET co_auth_status = %u WHERE co_last_co >= NOW() - INTEVAL " STR(DISCO_HOURS) " HOUR;"
#define QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO_LEN \
(__builtin_strlen(QUERY_CO_UP_AUTH_AUTH_STAT_BY_LAST_CO))

/// @brief update connection rows to <co_auth_status> 
//// status to disconnected that last connected <hours> hours ago
/// @param db_connect MYSQL database connection
/// @param co_auth_status new connection status
/// @param hours hours of interval with last connection
errcode_t db_co_up_auth_stat_by_last_co(MYSQL *db_connect);

//--------------------

#define QUERY_CO_UP_KEY_BY_ID "UPDATE Connection SET co_key = ?, co_nonce = ? WHERE co_id = ?;"
#define QUERY_CO_UP_KEY_BY_ID_LEN (__builtin_strlen(QUERY_CO_UP_KEY_BY_ID))

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
errcode_t db_co_up_key_by_id(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_nonce, id64_t co_id);

//--------------------

#define QUERY_CO_UP_KEY_BY_FD "UPDATE Connection SET co_key = ?, co_nonce = ? WHERE co_fd = ?;"
#define QUERY_CO_UP_KEY_BY_FD_LEN (__builtin_strlen(QUERY_CO_UP_KEY_BY_FD))

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
errcode_t db_co_up_key_by_fd(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_nonce, sockfd_t co_fd);

//--------------------

#define QUERY_CO_UP_KEY_BY_ADDR "UPDATE Connection SET co_key = ? WHERE co_ip_addr = ? AND co_port = ?;"
#define QUERY_CO_UP_KEY_BY_ADDR_LEN (__builtin_strlen(QUERY_CO_UP_KEY_BY_ADDR))

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
errcode_t db_co_up_key_by_addr(MYSQL *db_connect, const uint8_t *co_key, const uint8_t *co_ip_addr, const in_port_t co_port);

//--------------------


#endif
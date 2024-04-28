

#ifndef BASE_H
#define BASE_H      1
#include <poll.h>
#include <netdb.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <mariadb/mysql.h>


typedef int32_t errcode_t;
typedef struct in6_addr in6_addr_t;
typedef int32_t sockfd_t;
typedef struct pollfd pollfd_t;
typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in6 sockaddr_in6_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct hostent hostent_t;
typedef struct addrinfo addrinfo_t;

typedef struct Users
{
  int32_t id;
  char    *username;
  uint8_t *password;
  uint8_t sym_key;
  char    *creation_time;
  char    *modif_time;
  char    *modif_time;
}user_t;


#define MAX_AUTH_SIZE 128

#define __SUCCESS__   00
#define __FAILURE__   01
#define ELOG          02
#define E_FOPEN       03
#define E_FREAD       04
#define E_FWRITE      05
#define E_AUTH        06
#define E_PASS_LEN    07
#define E_INVAL_PASS  010
#define E_INIT        011
#define E_GETPASS     012
#define EINVALID_CHAR 013

/// @brief Danger return values (cleanup and exit)
#define D_NET_EXIT    014
#define D_SECU_EXIT   015
#define D_DB_EXIT     016
#define D_CORE_EXIT   017


#define DATETIME_FORM (const char *)"%Y-%m-%d %H:%M:%S"
#define LOG_FORMAT    (const char *)"|  [%s]  |  [%d]  |  [%s]  |"
#define DB_LOG_PATH   (const char *)"logs/security.log"
#define SECU_LOG_PATH (const char *)"logs/security.log"
#define NET_LOG_PATH  (const char *)"logs/network.log"
#define REQ_LOG_PATH  (const char *)"logs/request.log"

#define DEV_MODE      1
#define TEST_MODE     0
#define PROD_MODE     0

#if (DEV_MODE)
  #define SERVER_THREAD_NO    1
  #define SERVER_BACKLOG      16    // number of clients allowed

#elif (DEV_MODE || PROD_MODE)
  #define SERVER_THREAD_NO    2 // change this base on system limit and testings
  #define SERVER_BACKLOG      1024    // number of clients allowed

#endif

#if (SERVER_THREAD_NO > 32)
  #error "Max number of threads reached"
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) /// we use ATOMIC

#define MUTEX_SUPPORT         1
/// @brief struct that will be used by threads as argument to handle requests etc...
typedef struct ThreadArgs
{
  sockaddr_t  server_addr;    // no race condition issues with these 2 we will only perform read on them
  sockfd_t    server_fd;      // no race condition issues with these 2 we will only perform read on them
  pollfd_t    total_cli__fds[SERVER_THREAD_NO][SERVER_BACKLOG]; // THIS WILL REQUIRE GOOD HANDLING BY US  
  MYSQL      *db_connect;     // all threads will access the db concurrently but it is the db that handles concurrency
  _Atomic uint32_t    thread_no;  // number of thread set by each iteration in run_thread()
}thread_arg_t;
  
#else /// we use mutex

#define MUTEX_SUPPORT           0
/// @brief struct that will be used by threads as argument to handle requests etc...
typedef struct ThreadArgs
{
  sockaddr_t  server_addr;    // no race condition issues with these 2 we will only perform read on them
  sockfd_t    server_fd;      // no race condition issues with these 2 we will only perform read on them
  pollfd_t    total_cli__fds[SERVER_THREAD_NO][SERVER_BACKLOG]; // THIS WILL REQUIRE GOOD HANDLING BY US  
  MYSQL      *db_connect;     // all threads will access the db concurrently but it is the db that handles concurrency
  uint32_t    thread_no;  // number of thread set by each iteration in run_thread()
}thread_arg_t;
pthread_mutex_t __mutex;
#endif

extern errcode_t  log_write(const char *log_path, errcode_t __err, const char *__msg);
extern errcode_t  get_pass(char *pass);
extern errcode_t  check_pass(const char *pass);
extern errcode_t  total_cleanup(MYSQL *db_connect, pthread_t *threads, errcode_t __err);

#define LOG(__lp, __err, __msg) log_write(__lp, __err, __msg);



#endif

#ifndef BASE_H
#define BASE_H      1
#include "errors.h"
#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <mysql/mysql.h>


typedef uint8_t flag_t;
typedef int32_t sockfd_t;
typedef struct pollfd pollfd_t;
typedef struct sockaddr sockaddr_t;
typedef struct hostent  hostent_t;


#define MAX_AUTH_SIZE 128U
#define DATETIME_MAX_LEN 21U
#define DATETIME_FORMAT (const char *)"%Y-%m-%d %H:%M:%S"
#define LOG_FORMAT    (const char *)"|  [%s]  |  [%d]  |  [%s]  |"
#define DB_LOG_PATH   (const char *)"logs/security.log"
#define SECU_LOG_PATH (const char *)"logs/security.log"
#define NET_LOG_PATH  (const char *)"logs/network.log"
#define REQ_LOG_PATH  (const char *)"logs/request.log"


extern errcode_t  log_write(const char *log_path, errcode_t __err, const char *__msg);
extern errcode_t  get_pass(char *pass);
extern errcode_t  check_pass(const char *pass);
extern errcode_t  total_cleanup(MYSQL *db_connect, pthread_t *threads, errcode_t __err);
#define LOG(__lp, __err, __msg) log_write(__lp, __err, __msg)

#endif

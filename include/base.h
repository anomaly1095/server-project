#ifndef BASE_H
#define BASE_H      1
#include "errors.h"
#include ".config.h"
#include <poll.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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


#define DATETIME_MAX_LEN 21U
#define DATETIME_FORMAT (const char *)"%Y-%m-%d %H:%M:%S"
#define LOG_FORMAT    (const char *)"| [%s] |[%d][%s]\n"
#define DB_LOG_PATH   (const char *)"logs/security.log"
#define SECU_LOG_PATH (const char *)"logs/security.log"
#define NET_LOG_PATH  (const char *)"logs/network.log"
#define REQ_LOG_PATH  (const char *)"logs/request.log"


/**
 * @brief Prompt the user to enter a passphrase.
 * 
 * @param pass Buffer to store the passphrase (maximum size: MAX_AUTH_SIZE).
 * @return __SUCCESS__ if the passphrase is obtained successfully, or an error code if the operation fails.
 */
errcode_t get_pass(char *pass);


/**
 * @brief Check the validity of a passphrase.
 * 
 * @param pass Passphrase entered by the user.
 * @return __SUCCESS__ if the passphrase is valid, or an error code if it is invalid.
 */
errcode_t check_pass(const char *pass);


/**
 * @brief Write a log entry to the specified log file.
 * 
 * @param log_path Path to the log file.
 * @param __err Error code.
 * @param __msg Error message.
 * @return __SUCCESS__ if the log entry is written successfully, or an error code if writing fails.
 */
errcode_t log_write(const char *log_path, errcode_t __err, const char *__msg);
#define LOG(__lp, __err, __msg) log_write(__lp, __err, __msg);


/**
 * @brief Prompt the user to enter a passphrase.
 * 
 * @param pass Buffer to store the passphrase (maximum size: MAX_AUTH_SIZE).
 * @return __SUCCESS__ if the passphrase is obtained successfully, or an error code if the operation fails.
 */
errcode_t get_pass(char *pass);


errcode_t  total_cleanup(MYSQL *db_connect, pthread_t *threads, errcode_t __err);


#endif
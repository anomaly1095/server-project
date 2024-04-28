

#ifndef BASE_H
#define BASE_H      1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mariadb/mysql.h>
#include <errno.h>

typedef int32_t errcode_t;

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

#define DATETIME_FORM (const char *)"%Y-%m-%d %H:%M:%S"
#define LOG_FORMAT    (const char *)"|  [%s]  |  [%d]  |  [%s]  |"
#define DB_LOG_PATH   (const char *)"logs/security.log"
#define SECU_LOG_PATH (const char *)"logs/security.log"
#define NET_LOG_PATH  (const char *)"logs/network.log"

#define DEV_MODE      1
#define TEST_MODE     0
#define PROD_MODE     0

extern errcode_t log_write(const char *log_path, errcode_t __err, const char *__msg);
extern errcode_t get_pass(char *pass);
extern errcode_t pass_check_arg(const char *pass);
static errcode_t pass_check_char(const char c);


#define LOG(__lp, __err, __msg) log_write(__lp, __err, __msg);

#endif
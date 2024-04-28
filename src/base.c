#include "../include/base.h"

/// @brief get system time 
/// @param datetime format: "%Y-%m-%d %H:%M:%S"
inline void get_time(char *datetime)
{
  time_t current_time;
  time(&current_time);
  strftime(datetime, sizeof(datetime), DATETIME_FORM, localtime(&current_time));
}

/// @brief internal function used to write log statatement
/// @param logf log file
/// @param log_path path to log file
/// @param __err error code
/// @param __msg error message
/// @param datetime provided by get_time()
static inline void __logw(FILE *logf, const char *log_path, errcode_t __err, const char *__msg, char datetime[20])
{
  if (!(logf = fopen(log_path, "a"))) exit(ELOG);
  if (fprintf(logf, LOG_FORMAT, datetime, __err, __msg) < 0) exit(__err);
  return __SUCCESS__;
}

/// @brief write log to specified log file
/// @param log_path path to log file
/// @param __err error code
/// @param __msg error message
inline errcode_t log_write(const char *log_path, errcode_t __err, const char *__msg)
{
  FILE *logf;
  char datetime[20];
  get_time(datetime);
  __logw(logf, log_path, __err, __msg, datetime);
  fclose(logf);
  return __err;
}

/// @brief get passphrasse from user 
/// @param pass passphrase max size: MAX_AUTH_SIZE
inline errcode_t get_pass(char *pass)
{
  // get password from stdin
  if (!fgets(pass, MAX_AUTH_SIZE, stdin))
    return LOG(SECU_LOG_PATH, E_GETPASS, "Error getting password)");
  pass[strlen(pass)] = 0x0;
  return __SUCCESS__;
}

/// @brief check passphrase validity
/// @param pass passphrase entered by user
inline errcode_t check_pass(const char *pass)
{
  size_t plen = strlen(pass);
  if (plen > MAX_AUTH_SIZE)
    return LOG(SECU_LOG_PATH, E_PASS_LEN, "Security invalid password length ");
  for (size_t i = 0; i < plen; i++)
    if (pass_check_char(pass[i]))
      return LOG(SECU_LOG_PATH, E_INVAL_PASS, "Security invalid password character");
  return __SUCCESS__;
}

/// @brief check passphrase character (internal function)
/// @param c char
static inline errcode_t pass_check_char(const char c)
{
  // Check if the character is within the valid range of ASCII printable characters
  if (c < 32 || c > 126)
    return LOG(SECU_LOG_PATH, EINVALID_CHAR, "Invalid character found during passphrase check");
  return __SUCCESS__;
}

/// @brief cleanups in case of killing/terminating the process
/// (no security keys to destroy since all will be generated again each time the process in ran)
/// @param db_connect database connection
/// @param threads list of threads 
/// @param __err errorcode
inline errcode_t total_cleanup(MYSQL *db_connect, pthread_t *threads, errcode_t __err)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
    free(threads+i);

  mysql_close(db_connect);
  return __err;
}

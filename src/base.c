#include "../include/base.h"


/**
 * @brief Get the current system time in the specified format.
 * 
 * @param datetime Output buffer to store the formatted date and time (format: "%Y-%m-%d %H:%M:%S").
 */
inline void get_time(char *datetime)
{
  time_t current_time;
  time(&current_time);
  strftime(datetime, DATETIME_MAX_LEN, DATETIME_FORMAT, localtime(&current_time));
}

/**
 * @brief Internal function to write a log statement to the specified log file.
 * 
 * @param logf File pointer to the log file.
 * @param log_path Path to the log file.
 * @param __err Error code.
 * @param __msg Error message.
 * @param datetime Formatted datetime string.
 * @return __SUCCESS__ if the log entry is written successfully, or an error code if writing fails.
 */
inline errcode_t __logw(FILE *logf, const char *log_path, errcode_t __err, const char *__msg, const char *datetime)
{
  logf = fopen(log_path, "a");
  if (!logf) return ELOG;

  if (fprintf(logf, LOG_FORMAT, datetime, __err, __msg) < 0)
  {
    fclose(logf);
    return __err;
  }
  fclose(logf);
  return __SUCCESS__;
}


/**
 * @brief Write a log entry to the specified log file.
 * 
 * @param log_path Path to the log file.
 * @param __err Error code.
 * @param __msg Error message.
 * @return __SUCCESS__ if the log entry is written successfully, or an error code if writing fails.
 */
inline errcode_t log_write(const char *log_path, errcode_t __err, const char *__msg)
{
  char datetime[DATETIME_MAX_LEN];
  get_time(datetime);
  return __logw(NULL, log_path, __err, __msg, datetime);
}


/**
 * @brief Prompt the user to enter a passphrase.
 * 
 * @param pass Buffer to store the passphrase (maximum size: MAX_AUTH_SIZE).
 * @return __SUCCESS__ if the passphrase is obtained successfully, or an error code if the operation fails.
 */
inline errcode_t get_pass(char *pass)
{
  printf("Enter server password: ");
  // Get password from stdin
  if (!fgets(pass, MAX_AUTH_SIZE, stdin))
    return LOG(SECU_LOG_PATH, E_GETPASS, E_GETPASS_M);

  // Remove trailing newline character
  pass[strcspn(pass, "\n")] = 0x0;

  return __SUCCESS__;
}

/**
 * @brief Check if a character is a valid ASCII printable character.
 * 
 * @param c Character to check.
 * @return __SUCCESS__ if the character is valid, or an error code if it is invalid.
 */
static inline errcode_t pass_check_char(const char c)
{
  // Check if the character is within the valid ASCII printable range
  if (c < 32 || c > 126)
    return LOG(SECU_LOG_PATH, EINVALID_CHAR, EINVALID_CHAR_M);

  return __SUCCESS__;
}


/**
 * @brief Check the validity of a passphrase.
 * 
 * @param pass Passphrase entered by the user.
 * @return __SUCCESS__ if the passphrase is valid, or an error code if it is invalid.
 */
errcode_t check_pass(const char *pass)
{
  size_t plen = strlen(pass);

  // Check passphrase length
  if (plen > MAX_AUTH_SIZE)
    return LOG(SECU_LOG_PATH, E_PASS_LEN, E_PASS_LEN_M);

  // Check passphrase characters
  for (size_t i = 0; i < plen; i++)
    if (pass_check_char(pass[i]))
      return LOG(SECU_LOG_PATH, E_INVAL_PASS, E_INVAL_PASS_M);

  return __SUCCESS__;
}




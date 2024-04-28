#include "../include/base.h"

inline void get_time(char *datetime)
{
  time_t current_time;
  time(&current_time);
  strftime(datetime, sizeof(datetime), DATETIME_FORM, localtime(&current_time));
}

errcode_t log_write(const char *log_path, errcode_t __err, const char *__msg)
{
  FILE *logf;
  char datetime[20];
  get_time(datetime);

  if (!(logf = fopen(log_path, "a"))) exit(ELOG);
  if (fprintf(logf, LOG_FORMAT, datetime, __err, __msg) < 0) exit(__err);
  fclose(logf);
  
  return __err;
}


inline errcode_t get_pass(char *pass)
{
  // get password from stdin
  if (!fgets(pass, MAX_AUTH_SIZE, stdin))
    return E_GETPASS;
  pass[strlen(pass)] = 0x0;
  return __SUCCESS__;
}


inline errcode_t pass_check_arg(const char *pass)
{
  size_t plen = strlen(pass);
  if (plen > MAX_AUTH_SIZE)
    return E_PASS_LEN;
  for (size_t i = 0; i < plen; i++)
    if (pass_check_char(pass[i]))
      return E_INVAL_PASS;
  
  return __SUCCESS__;
}


static inline errcode_t pass_check_char(const char c)
{
  // Check if the character is within the valid range of ASCII printable characters
  if (c < 32 || c > 126) {
    return LOG(SECU_LOG_PATH, EINVALID_CHAR, "Invalid character found during passphrase check");
  return __SUCCESS__;
}
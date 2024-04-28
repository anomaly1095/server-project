#include "../include/core.h"



errcode_t __init__(MYSQL **db_connect)
{
  *db_connect = NULL;
  char *pass = (char*)malloc(MAX_AUTH_SIZE);

  // get password
  if (get_pass(pass))
    return LOG(SECU_LOG_PATH, E_GETPASS, "Error getting password)");
  
  // check password for invalid chars
  if (check_pass(pass))
    LOG(SECU_LOG_PATH, E_INVAL_PASS, pass);
  
  // initialize libsodium
  if (secu_init())
    return __FAILURE__;

  // check passphrase
  if (secu_check_init_cred((const uint8_t *)pass))
    return __FAILURE__;

  // set memory to 0 for security reasons
  memset(pass, 0x0, MAX_AUTH_SIZE);       // at this point we can remove the physkey

  // initialize database
  if (db_init(&db_connect))
    return __FAILURE__;
  return __SUCCESS__;
}

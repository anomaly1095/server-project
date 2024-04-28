#include "../include/init.h"


/// @brief step 1 authentication + step 2 authentication and connection to db and initialize call
/// @param thread_arg 
/// @return 
errcode_t __init__(thread_arg_t thread_arg)
{
  thread_arg.db_connect = NULL;
  char *pass = (char*)malloc(MAX_AUTH_SIZE);

  // get password (step 1 auth)
  if (get_pass(pass))
    return __FAILURE__;
  
  // check password for invalid chars
  if (check_pass(pass))
    return __FAILURE__;
  
  // initialize libsodium
  if (secu_init())
    return __FAILURE__;

  // check passphrase 
  if (secu_check_init_cred((const uint8_t *)pass))
    return __FAILURE__;

  // set memory to 0 for security reasons
  memset(pass, 0x0, MAX_AUTH_SIZE);
  
  // initialize database (step 2 auth)
  if (db_init(&thread_arg.db_connect))
    return __FAILURE__;
  
  // initialize pollfds for polling
  net_init_clifd(thread_arg.total_cli__fds);

  // delete old asymmetric keys generate new ones save them
  if (secu_init_keys(thread_arg.db_connect))
    return __FAILURE__;

  return __SUCCESS__;
}

/// @brief 
/// @param  
/// @return 
inline pthread_t *thread_init(void)
{
  pthread_t *threads = (pthread_t*)malloc(sizeof (pthread_t) * SERVER_THREAD_NO);
  return threads;
}


/// @brief 
/// @param threads list of threads to be ran
/// @param thread_arg 
inline void run_threads(pthread_t *threads, thread_arg_t *thread_arg)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
  {
    #if (!MUTEX_SUPPORT)
      pthread_mutex_lock(&__mutex);
    #endif
    thread_arg->thread_no = i;
    pthread_create(threads + i, NULL, &net_communication_handler, (void*)thread_arg);
  }
}


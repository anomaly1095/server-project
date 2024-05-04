#include "../include/network.h"


/**
 * @brief Initialize the server and authenticate the user.
 * 
 * This function performs the following steps:
 *   1. Authenticate the user.
 *   2. Initialize cryptographic libraries.
 *   3. Verify the passphrase.
 *   4. Initialize the database connection.
 *   5. Initialize pollfds for polling.
 *   6. Delete old asymmetric keys, generate new ones, and save them.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @return __SUCCESS__ if initialization is successful, or an error code if it fails.
 */
errcode_t __init(thread_arg_t *thread_arg)
{
  thread_arg->db_connect = NULL;
  char *pass = (char *)malloc(MAX_AUTH_SIZE);

  // Step 1: Get and validate passphrase
  if (get_pass(pass))
    return __FAILURE__;
  if (check_pass(pass))
    return __FAILURE__;

  // Step 2: Initialize cryptographic libraries and check passphrase
  if (secu_init())
    return __FAILURE__;
  if (secu_check_init_cred((const uint8_t *)pass))
    return __FAILURE__;

  // Securely clear memory containing the passphrase
  memset(pass, 0x0, MAX_AUTH_SIZE);
  free(pass);

  // Step 3: Initialize database connection
  if (db_init(&thread_arg->db_connect))
    return __FAILURE__;

  // Step 4: Initialize pollfds for polling
  net_init_clifd(thread_arg->total_cli_fds);

  // Step 5: Delete old asymmetric keys, generate new ones, and save them
  if (secu_init_keys(thread_arg->db_connect))
    return __FAILURE__;

  return __SUCCESS__;
}

/**
 * @brief ..
 * Initialize an array to hold thread identifiers. 
 * creat"e the mutexes
 * Create and run server threads with there unique identifiers.
 * 
 * @param threads Array of thread identifiers.
 * @param thread_arg Pointer to the thread_arg_t structure.
 */
void run_threads(pthread_t **threads, thread_arg_t *thread_arg)
{
  *threads = (pthread_t *)malloc(sizeof(pthread_t) * SERVER_THREAD_NO);
  // Initialize mutexes
  pthread_mutex_init(&mutex_connection_global, NULL);
  pthread_mutex_init(&mutex_connection_fd, NULL);
  pthread_mutex_init(&mutex_connection_auth_status, NULL);
  pthread_mutex_init(&mutex_connection_key);
#if (!ATOMIC_SUPPORT) // these wont be used in case of atomicity cpu & compiler support

  pthread_mutex_init(&mutex_thread_id, NULL);
  pthread_mutex_init(&mutex_memory_w, NULL);
#endif
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
  {
    #if (!ATOMIC_SUPPORT)
      pthread_mutex_lock(&mutex_thread_id);
    #endif
    thread_arg->thread_id = i;
    pthread_create(*threads + i, NULL, &net_communication_handler, (void *)thread_arg);
  }
}

/**
 * @brief Perform cleanup in case of process termination.
 * 
 * This function frees allocated memory, closes the database connection, and destroys mutexes.
 * 
 * @param db_connect Pointer to the MySQL database connection.
 * @param threads Array of thread identifiers.
 * @param __err Error code.
 * @return The error code provided as input.
 */
inline errcode_t total_cleanup(MYSQL *db_connect, pthread_t *threads, errcode_t __err)
{
  // Free memory allocated for threads
  if (threads)
    free(threads);
  
  // Close database connection
  mysql_close(db_connect);

  // Destroy mutexes
  pthread_mutex_destroy(&mutex_connection_global);
  pthread_mutex_destroy(&mutex_connection_fd);
  pthread_mutex_destroy(&mutex_connection_auth_status);
  pthread_mutex_destroy(&mutex_connection_key);
  
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_destroy(&mutex_thread_id);
    pthread_mutex_destroy(&mutex_memory_w);
  #endif
  
  return __err;
}



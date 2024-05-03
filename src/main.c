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
extern errcode_t __init__(thread_arg_t thread_arg);


/**
 * @brief
 * Initialize an array to hold thread identifiers. 
 * creat"e the mutexes
 * Create and run server threads with there unique identifiers.
 * 
 * @param threads Array of thread identifiers.
 * @param thread_arg Pointer to the thread_arg_t structure.
 */
extern void run_threads(pthread_t **threads, thread_arg_t *thread_arg);


/**
 * @brief Main entry point of the server program.
 * 
 * This function initializes the server, sets up network configurations,
 * and runs the main thread and child threads to handle incoming connections and data.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return Error code indicating the success or failure of the server.
 */
errcode_t main(int32_t argc, const char **argv)
{
  // Initialize thread argument structure and status
  thread_arg_t thread_arg;
  errcode_t status;
  pthread_t *threads;

  // Initialize libsodium, physical authentication, database connection, and asymmetric key generation
  status = __init__(thread_arg);
  if (status != __SUCCESS__) return total_cleanup(thread_arg.db_connect, threads, E_INIT);

  // Server setup (socket options, bind, listen)
  status = net_server_setup(&thread_arg.server_addr, &thread_arg.server_fd);
  if (status != __SUCCESS__) return total_cleanup(thread_arg.db_connect, threads, status);

  // Run child threads to handle incoming data and communications
  run_threads(&threads, &thread_arg);

  // Run main thread to handle incoming connections
  status = net_connection_handler(&thread_arg);
  
  // Cleanup and return status
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_destroy(&mutex_thread_id);
    pthread_mutex_destroy(&mutex_memory_w);
  #endif
  return total_cleanup(thread_arg.db_connect, threads, status);
}

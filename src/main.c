#include "../include/init.h"

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

  // Allocate memory for threads
  pthread_t *threads = thread_init();
  if (threads == NULL) return E_MEM_ALLOC;

  // Initialize libsodium, physical authentication, database connection, and asymmetric key generation
  status = __init__(&thread_arg);
  if (status != __SUCCESS__) return total_cleanup(thread_arg.db_connect, threads, E_INIT);

  // Server setup (socket options, bind, listen)
  status = net_server_setup(&thread_arg.server_addr, &thread_arg.server_fd);
  if (status != __SUCCESS__) return total_cleanup(thread_arg.db_connect, threads, status);
  
  // Initialize mutexes
  pthread_mutex_init(&mutex_connection_global, NULL);
  pthread_mutex_init(&mutex_connection_fd, NULL);
  pthread_mutex_init(&mutex_connection_auth_status, NULL);
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_init(&mutex_thread_id, NULL);
    pthread_mutex_init(&mutex_memory_w, NULL);
  #endif

  // Run child threads to handle incoming data and communications
  run_threads(threads, &thread_arg);

  // Run main thread to handle incoming connections
  status = net_connection_handler(&thread_arg);
  
  // Cleanup and return status
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_destroy(&mutex_thread_id);
    pthread_mutex_destroy(&mutex_memory_w);
  #endif
  return total_cleanup(thread_arg.db_connect, threads, status);
}


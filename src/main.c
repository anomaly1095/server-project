#include "../include/init.h"


errcode_t main(int32_t argc, const char **argv)
{
  thread_arg_t thread_arg;
  errcode_t status;
  // allocate memory for threads
  pthread_t *threads = thread_init();
  // initialize libsodium / physical authentication / db connection / asymmetric key generation
  if (__init__(thread_arg))
    return E_INIT;

  // server setup (socket options bind listen)
  if (net_server_setup(&thread_arg.server_addr, &thread_arg.server_fd))
    return total_cleanup(thread_arg.db_connect, threads, __FAILURE__);
  
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_init(&mutex_thread_id, NULL);
    pthread_mutex_init(&mutex_memory_w, NULL);
  #endif
  // run child threads to handle incoming data and communications
  run_threads(threads, &thread_arg);

  // run main thread to handle incoming connections
  if (status = net_connection_handler(thread_arg.server_addr, thread_arg.server_fd, thread_arg.total_cli__fds))
    return total_cleanup(thread_arg.db_connect, threads, status);
  
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_destroy(&mutex_thread_id);
    pthread_mutex_destroy(&mutex_memory_w);
  #endif
  return total_cleanup(thread_arg.db_connect, threads, __SUCCESS__); // not yet sure about this step
}


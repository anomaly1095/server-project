#include "../include/init.h"


errcode_t main(int32_t argc, const char **argv)
{
  thread_arg_t thread_arg;
  errcode_t status;
  pthread_t *threads = thread_init();
  pthread_mutex_init(&__mutex, NULL);
  if (__init__(thread_arg))
    return E_INIT;

  if (net_server_setup(&thread_arg.server_addr, &thread_arg.server_fd))
    return total_cleanup(thread_arg.db_connect, threads, __FAILURE__);
  
  if (status = net_connection_handler(thread_arg.server_addr, thread_arg.server_fd, thread_arg.total_cli__fds))
    return total_cleanup(thread_arg.db_connect, threads, status);
  
  run_threads(threads, &thread_arg);

  return __SUCCESS__;
}


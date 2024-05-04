

#ifndef __THREADS_H
#define __THREADS_H     1
#include ".config.h"
#include "base.h"



#if (SERVER_THREAD_NO > 32U)
#error "Max number of threads reached"
#endif

//===============================================
//                  MUTEX / ATOMIC
//===============================================

#if defined(__STDC_NO_ATOMICS__) || (__STDC_VERSION__ < 201112L) /// we use ATOMIC

  #define ATOMIC_SUPPORT        0
  /// @brief struct that will be used by threads as argument to handle requests etc...
  typedef struct ThreadArgs
  {
    sockaddr_t  server_addr;    // no race condition issues with these 2 we will only perform read on them
    sockfd_t    server_fd;      // no race condition issues with these 2 we will only perform read on them
    pollfd_t    total_cli__fds[SERVER_THREAD_NO][SERVER_BACKLOG]; // THIS WILL REQUIRE GOOD HANDLING BY US  
    MYSQL      *db_connect;     // all threads will access the db concurrently but it is the db that handles concurrency
    uint32_t    thread_id;  // number of thread set by each iteration in run_thread()
  }thread_arg_t;

  int32_t memory_w = 0;
  pthread_mutex_t mutex_thread_id; // mutex will only be used once by everythread to check id
  pthread_mutex_t mutex_memory_w;  // mutex will be used for kernel memory warnings 
#else /// we use mutex

  #define ATOMIC_SUPPORT         1
  /// @brief struct that will be used by threads as argument to handle requests etc...
  typedef struct ThreadArgs
  {
    sockaddr_t  server_addr;    // no race condition issues with these 2 we will only perform read on them
    sockfd_t    server_fd;      // no race condition issues with these 2 we will only perform read on them
    pollfd_t    total_cli_fds[SERVER_THREAD_NO][SERVER_BACKLOG]; // THIS WILL REQUIRE GOOD HANDLING
    MYSQL      *db_connect;     // all threads will access the db concurrently but it is the db that handles concurrency
    _Atomic uint32_t    thread_id;  // thread identifier
  }thread_arg_t;

  _Atomic  int32_t memory_w = 0;

#endif

pthread_mutex_t mutex_connection_global;
pthread_mutex_t mutex_connection_fd;
pthread_mutex_t mutex_connection_auth_status;
pthread_mutex_t mutex_connection_key;

#endif
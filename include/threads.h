

#ifndef __THREADS_H
#define __THREADS_H     1
#include "database.h"

///@brief developement mode (small values and only ipv4) mainthread + 1 extra thread
#if (DEV_MODE && !TEST_MODE && !PROD_MODE) // developement mode

  #define SERVER_THREAD_NO    1 // change this base on system limit and testings
  #define SERVER_BACKLOG      16    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)

///@brief ipv4 || ipv6 || domain name + system limit backlog
/// system limit 1024 __fds || mainthread + 2 extra thread
#elif (!DEV_MODE && TEST_MODE && !PROD_MODE) // testing mode

  #define SERVER_THREAD_NO    2 // change this base on system limit and testings
  #define SERVER_BACKLOG      1024    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)


///@brief we go full throttle ipv4 || ipv6 || domain name 
/// encrease system limit backlog by 4 ||  main thread + 4 extra threads 
#elif (!DEV_MODE && !TEST_MODE && PROD_MODE) // production mode

  #define SERVER_THREAD_NO    4
  #define SERVER_BACKLOG      4096    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)
  
#else
  #error "Only one Mode can be chosen out of dev || test || prod\n"
#endif

#if (SERVER_THREAD_NO > 32)
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
    co_t        **co_head;
    pollfd_t    total_cli_fds[SERVER_THREAD_NO][SERVER_BACKLOG]; // THIS WILL REQUIRE GOOD HANDLING
    MYSQL      *db_connect;     // all threads will access the db concurrently but it is the db that handles concurrency
    _Atomic uint32_t    thread_id;  // thread identifier
  }thread_arg_t;

  _Atomic  int32_t memory_w = 0;

#endif

pthread_mutex_t mutex_connection_global;
pthread_mutex_t mutex_connection_fd;
pthread_mutex_t mutex_connection_auth_status;
  
#endif
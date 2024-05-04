#ifndef __THREADS_H
#define __THREADS_H     1

#include "base.h"

#if (SERVER_THREAD_NO > 32U)
#error "Max number of threads reached"
#endif

//===============================================
//                  MUTEX / ATOMIC
//===============================================

#if defined(__STDC_NO_ATOMICS__) || (__STDC_VERSION__ < 201112L) /// we use ATOMIC

  #define ATOMIC_SUPPORT        0
  typedef struct ThreadArgs
  {
    sockaddr_t  server_addr;
    sockfd_t    server_fd;
    pollfd_t    total_cli__fds[SERVER_THREAD_NO][SERVER_BACKLOG];
    MYSQL      *db_connect;
    uint32_t    thread_id;
  }thread_arg_t;

  extern int32_t memory_w; // Declare memory_w as extern
  extern pthread_mutex_t mutex_thread_id;
  extern pthread_mutex_t mutex_memory_w;
#else /// we use mutex

  #define ATOMIC_SUPPORT         1
  typedef struct ThreadArgs
  {
    sockaddr_t  server_addr;
    sockfd_t    server_fd;
    pollfd_t    total_cli_fds[SERVER_THREAD_NO][SERVER_BACKLOG];
    MYSQL      *db_connect;
    _Atomic uint32_t    thread_id;
  }thread_arg_t;

  extern _Atomic int32_t memory_w; // Declare memory_w as extern
#endif

extern pthread_mutex_t mutex_connection_global;
extern pthread_mutex_t mutex_connection_fd;
extern pthread_mutex_t mutex_connection_auth_status;
extern pthread_mutex_t mutex_connection_key;

#endif

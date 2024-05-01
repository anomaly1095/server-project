
#ifndef CORE_H
#define CORE_H      1
#include "network.h"


/// @brief 
/// @param thread_arg 
/// @return 
extern errcode_t __init__(thread_arg_t thread_arg);

/// @brief initialize threads and malloc memory
/// @return pointer to the heap allocated threads
extern pthread_t *thread_init(void);

/// @brief run pthread_create for each of the functions to call the event loops
/// @param threads array of threads
/// @param thread_arg struct to be passwed as void* to each thread
static inline void run_threads(pthread_t *threads, thread_arg_t *thread_arg);

/// @brief setting up the server (socket / bind / options / listen)
/// @param server_addr server's address
/// @param server_fd server's socket file descriptor
errcode_t net_server_setup(sockaddr_t *server_addr, sockfd_t *server_fd);

/// @brief handler for incoming client connections (called by the program's main thread)
/// @param thread_arg struct to be passwed as to each thread 
/// in this case it is the main thread
errcode_t net_connection_handler(thread_arg_t *thread_arg);


/// @brief handler for incoming client data (called by the additionally created threads)
/// @brief this ufunction will be passed to threads as function pointers and not directly
/// @param args hint to the struct defined in /include/base.h (thread_arg_t *thread_arg)
/// @return errcode status
void *net_communication_handler(void *args);

#endif

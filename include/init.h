
#ifndef CORE_H
#define CORE_H      1
#include "network.h"


/// @brief 
/// @param thread_arg struct to be passwed as void* to each thread
extern errcode_t __init__(thread_arg_t thread_arg);

/// @brief initialize threads and malloc memory
/// @return pointer to the heap allocated threads
extern pthread_t *thread_init(void);

/// @brief run pthread_create for each of the functions to call the event loops
/// @param threads array of threads
/// @param thread_arg struct to be passwed as void* to each thread
static inline void run_threads(pthread_t *threads, thread_arg_t *thread_arg);

#endif

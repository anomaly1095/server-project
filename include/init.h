
#ifndef CORE_H
#define CORE_H      1
#include "database.h"
#include "network.h"


/// @brief 
/// @param thread_arg 
/// @return 
extern errcode_t __init__(thread_arg_t thread_arg);

/// @brief 
/// @param  
/// @return 
extern pthread_t *thread_init(void);

/// @brief 
/// @param threads 
/// @param thread_arg 
static inline void run_threads(pthread_t *threads, thread_arg_t *thread_arg);

#endif

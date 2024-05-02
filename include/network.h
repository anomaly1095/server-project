

#ifndef NETWORK_H
#define NETWORK_H       1
#include "request.h"


#define DATA_AVAILABLE      1
#define DATA_UNAVAILABLE    0

#define PING_HELLO          (unsigned char*)"Hello"
#define PING_HELLO_LEN     (size_t)__builtin_strlen(PING_HELLO)


//===============================================
//              ----MODES----
//===============================================


///@brief developement mode (small values and only ipv4) mainthread + 1 extra thread
#if (DEV_MODE && !TEST_MODE && !PROD_MODE) // developement mode

  #define SERVER_DOMAIN       "127.0.0.1"
  #define SERVER_PORT         6969  // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP

///@brief ipv4 || ipv6 || domain name + system limit backlog
/// system limit 1024 __fds || mainthread + 2 extra thread
#elif (!DEV_MODE && TEST_MODE && !PROD_MODE) // testing mode
  
  #define SERVER_DOMAIN       "192.168.1.78"
  #define SERVER_PORT         6969    // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP

///@brief we go full throttle ipv4 || ipv6 || domain name 
/// encrease system limit backlog by 4 ||  main thread + 4 extra threads 
#elif (!DEV_MODE && !TEST_MODE && PROD_MODE) // production mode

  #define SERVER_DOMAIN       "41.228.24.124" // change to domain name
  #define SERVER_PORT         6969  // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP

#else
  #error "Only one Mode can be chosen out of dev || test || prod\n"
#endif

/// @brief if test mode or production mode are enabled 
/// we can type an IPV6 or a domain name thanks to DNS lookups
#if (TEST_MODE || PROD_MODE)

  #define IS_IPV4_ADDRESS(domain) ({ \
    struct sockaddr_in sa; \
    int result = inet_pton(AF_INET, domain, &(sa.sin_addr)); \
    result == 1; \
  })
  #define IS_IPV6_ADDRESS(domain) ({ \
    struct sockaddr_in6 sa; \
    int result = inet_pton(AF_INET6, domain, &(sa.sin6_addr)); \
    result == 1; \
  })
  /// @brief IPV4 ENTERED 
  #if IS_IPV4_ADDRESS(SERVER_DOMAIN)
    #define SERVER_AF     AF_INET
    #define USING_IP      1
    #define USING_HN      0
  /// @brief IPV6 ENTERED
  #elif IS_IPV6_ADDRESS(SERVER_DOMAIN)
    #define SERVER_AF     AF_INET6
    #define USING_IP      1
    #define USING_HN      0
  /// @brief DOMAIN NAME ENTERED
  #else
    #define SERVER_AF     AF_UNSPEC
    #define USING_IP      0
    #define USING_HN      1
  #endif

#else

  #define SERVER_AF       AF_INET
  #define USING_IP        1
  #define USING_HN        0

#endif

//===============================================
//                  OPTIONS
//===============================================

int32_t __KEEPALIVE  = 1;  // ON
int32_t __REUSEADDR  = 1;  // ON
int32_t __IDLETIME  = 60; // 60 seconds 
int32_t __INTRLTIME = 10; // 10 seconds
int32_t __KEEPCNTR  = 5;  // 5 repetitions

#define SET__KEEPALIVE(fd) (setsockopt(fd, SOL_SOCKET,  SO_KEEPALIVE,  &__KEEPALIVE, sizeof(int)))
#define SET__REUSEADDR(fd) (setsockopt(fd, SOL_SOCKET,  SO_REUSEADDR,  &__REUSEADDR, sizeof(int)))
#define SET__IDLETIME(fd)  (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,  &__IDLETIME,  sizeof(int)))
#define SET__INTRLTIME(fd) (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &__INTRLTIME, sizeof(int)))
#define SET__KEEPCNTR(fd)  (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &__KEEPCNTR,  sizeof(int)))
#define GET__MSS(clifd, mss, mss_len) (getsockopt(clifd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len))


#define CONN_POLL_TIMEOUT -1  // poll untill new connection received
#define COMM_POLL_TIMEOUT 10  // 10 milliseconds

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

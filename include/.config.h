

#ifndef CONFIG_H
  #define CONFIG_H    1


  #define PATH_PHYSKEY    "/media/amnesia2/PKEY/keys/auth_init.bin"  // path to the key for first step authentication

  #define DB_DEFAULT_PORT 3306U

  #define DEV_MODE      1
  #define TEST_MODE     0
  #define PROD_MODE     0

  #define DISCO_HOURS         1
  #define CLEANUP_HOURS       24

//===============================================
//              ----MODES----
//===============================================

///@brief developement mode (small values and only ipv4) mainthread + 1 extra thread
#if (DEV_MODE && !TEST_MODE && !PROD_MODE) // developement mode

  #define SERVER_DOMAIN       "127.0.0.1"
  #define SERVER_PORT         6969U  // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP
  #define SERVER_THREAD_NO    1U // change this base on system limit and testings
  #define SERVER_BACKLOG      16U    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)

///@brief ipv4 || ipv6 || domain name + system limit backlog
/// system limit 1024 __fds || mainthread + 2 extra thread
#elif (!DEV_MODE && TEST_MODE && !PROD_MODE) // testing mode
  
  #define SERVER_DOMAIN       "192.168.1.78"
  #define SERVER_PORT         6969U    // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP
  #define SERVER_THREAD_NO    2U // change this base on system limit and testings
  #define SERVER_BACKLOG      1024U    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)

///@brief we go full throttle ipv4 || ipv6 || domain name 
/// encrease system limit backlog by 4 ||  main thread + 4 extra threads 
#elif (!DEV_MODE && !TEST_MODE && PROD_MODE) // production mode

  #define SERVER_DOMAIN       "41.228.24.124" // change to domain name
  #define SERVER_PORT         6969U  // host byte order
  #define SERVER_SOCK_TYPE    SOCK_STREAM | SOCK_NONBLOCK
  #define SERVER_SOCK_PROTO   IPPROTO_TCP
  #define SERVER_THREAD_NO    4U
  #define SERVER_BACKLOG      4096U    // number of clients allowed
  #define CLIENTS_PER_THREAD  (SERVER_BACKLOG / SERVER_THREAD_NO)

#else
  #error "Only one Mode can be chosen out of dev || test || prod\n"
#endif

#endif
#include "../include/network.h"

//==========================================================================
//                        SERVER SETUP INIT
//==========================================================================

//=====================IP CONVERSION / DNS LOOKUPS========================== 

#if (USING_HN)
/// @brief this functions gets called
/// @param server_addr 
/// @return 
static inline errcode_t net_get_ipaddr_byhost(sockaddr_t *server_addr) {
  struct hostent *hptr;
  if (!(hptr = gethostbyname(SERVER_DOMAIN)))
    return LOG(NET_LOG_PATH, h_errno, "Error during server DNS lookup");
  // get the first address binded to that ip address
  switch (hptr->h_length)
  {
  case 4:
    server_addr->sa_family = AF_INET;
    inet_pton(AF_INET, hptr->h_addr_list[0], &server_addr->sa_data[2]);
    return __SUCCESS__;
  case 16:
    server_addr->sa_family = AF_INET6;
    inet_pton(AF_INET6, hptr->h_addr_list[0], &server_addr->sa_data[2]);
    return __SUCCESS__;
  default: return LOG(NET_LOG_PATH, E_INVAL_ADDRLEN, "Invalid address len resulting of DNS resolving");
  }
}
#endif

/// @brief if SERVER_DOMAIN is an ip address we convert to network byte order binary
///        if SERVER_DOMAIN is a domain name we do DNS lookup
static inline errcode_t net_get_ipaddr(sockaddr_t *server_addr)
{
  // ip address entered
  #if (USING_IP)
    if (inet_pton(SERVER_AF, SERVER_DOMAIN, (void*)&server_addr->sa_data[2]) != 1)
      return LOG(NET_LOG_PATH, errno, strerror(errno));
  #else
    if (net_get_ipaddr_byhost(server_addr))
      return ERR_IP_HANDLER;
  #endif
  return __SUCCESS__;
}
//==========================================================================

//=========================INIT SOCKADDR_T================================== 

/// @brief filling up server's sockaddr struct 
static inline errcode_t net_server_init(sockaddr_t *server_addr)
{
  memset((void*)server_addr, 0x0, sizeof server_addr);
  server_addr->sa_family = SERVER_AF;
  server_addr->sa_data[0] = (__BYTE_ORDER == __BIG_ENDIAN) ? (SERVER_PORT >> 8) : (SERVER_PORT & 0xFF);
  server_addr->sa_data[1] = (__BYTE_ORDER == __BIG_ENDIAN) ? (SERVER_PORT & 0xFF) : (SERVER_PORT >> 8);
  if (net_get_ipaddr(server_addr))
    return ERR_IP_HANDLER;
  return __SUCCESS__;
}

//=====================SETTING SOCKET OPTIONS=============================== 

/// @brief setting up needed options for server socket
static inline errcode_t net_set_server_opts(sockfd_t server_fd)
{
  if (SET__KEEPALIVE(server_fd) == -1 || 
      SET__REUSEADDR(server_fd) == -1 || 
      SET__IDLETIME(server_fd)  == -1 || 
      SET__INTRLTIME(server_fd) == -1 || 
      SET__KEEPCNTR(server_fd)  == -1)
      return LOG(NET_LOG_PATH, errno, strerror(errno));
    return __SUCCESS__;
}

//==========================================================================

//=====================SERVER SETUP MAIN====================================

/// @brief setting up the server (socket / bind / options / listen)
/// @param server_addr server's address
/// @param server_fd server's socket file descriptor
errcode_t net_server_setup(sockaddr_t *server_addr, sockfd_t *server_fd)
{
  if (net_server_init(server_addr))
    return E_SERVER_SETUP;
  if ((*server_fd = socket(SERVER_AF, SERVER_SOCK_TYPE, SERVER_SOCK_PROTO)) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));
  
  if (bind(*server_fd, server_addr, sizeof server_addr) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));
  
  if (net_set_server_opts(*server_fd))
    return ENET_OPT_FAIL;

  if (listen(*server_fd, SERVER_BACKLOG) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));

  return __SUCCESS__;
}


//==========================================================================
//                        EVENT HANDLING & POLLING NEW CONNECTIONS
//==========================================================================

//===========================INITIALIZERS AND ERROR HANDLERS================  

/// @brief initialize pollfd structures for incoming data and fd = -1 so that they are ignored by poll
/// @param total_cli__fds all file descriptors available accross all threads
inline void net_init_clifd(pollfd_t **total_cli__fds)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
    for (size_t j = 0; j < CLIENTS_PER_THREAD; j++){
      total_cli__fds[i][j].fd = -1;
      total_cli__fds[i][j].events = POLLIN | POLLPRI;
      total_cli__fds[i][j].revents = 0;
    }
}


/// @brief add new client connection to pollfds being bolled by specific thread thread's 
/// @param thread_cli__fds file descriptors being polled by a thread
/// @param new_cli_fd new client's file descriptor
static inline errcode_t net_add_clifd_to_thread(pollfd_t *thread_cli__fds, sockfd_t new_cli_fd)
{
  for (size_t i = 0; i < CLIENTS_PER_THREAD; i++)
    if (thread_cli__fds[i].fd == -1){
      thread_cli__fds[i].fd = new_cli_fd;
      return __SUCCESS__;
    }
  return MAX_FDS_IN_THREAD;
}

/// @brief add new client connection to pollfd being polled by one of the thread
/// @param total_cli__fds all file descriptors available accross all threads
/// @param new_cli_fd new client's file descriptor
static inline errcode_t net_add_clifd(pollfd_t **total_cli__fds, sockfd_t new_cli_fd)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
    if (!net_add_clifd_to_thread(total_cli__fds[i], new_cli_fd))
      return __SUCCESS__;
      
  return LOG(NET_LOG_PATH, MAX_FDS_IN_PROGRAM, "WARNING max_file descriptors reached for system");
}


/// @brief poll error handler 
/// @param __err value of errno passed as argument
/// @return __SUCCESS__--> resume process D_NET_EXIT--> cleanup and exit
static inline errcode_t net_handle_poll_err(int __err)
{
  static int32_t memory_w = 0;
  LOG(NET_LOG_PATH, __err, strerror(__err));
  switch (__err){
    case EFAULT: 
      return D_NET_EXIT;
    case EINTR: 
      break;
    case EINVAL: 
      return D_NET_EXIT;
    case ENOMEM: 
      memory_w++;
      sleep(2);
      break;
    default: return __SUCCESS__;
  }
  return (memory_w == 4) ? D_NET_EXIT : __SUCCESS__;
}

//===========================HANDLING NEW CONNECTION========================

/// @brief accept new connection from client and add it to one of pollfds managed by threads
/// @param server_addr server address struct
/// @param server_fd server file descriptor
/// @param total_cli__fds all file descriptors available accross all threads
static inline errcode_t net_accept_save_new_co(sockaddr_t server_addr, sockfd_t server_fd, pollfd_t **total_cli__fds)
{
  sockaddr_t new_addr;
  sockfd_t new_fd;
  if ((new_fd = accept(server_fd, NULL, NULL)) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));
  if (net_add_clifd(total_cli__fds, new_fd))
    return MAX_FDS_IN_PROGRAM;
  return __SUCCESS__;
}


//===========================MAIN EVENT LOOP========================  


/// @brief handler for incoming client connections (called by the program's main thread)
/// @param server_addr server address struct
/// @param server_fd server file descriptor
/// @param total_cli__fds all file descriptors available accross all threads
errcode_t net_connection_handler(sockaddr_t server_addr, sockfd_t server_fd, pollfd_t **total_cli__fds)
{
  pollfd_t __fds[1] = {[0].fd = server_fd, [0].events = POLLIN | POLLPRI, [0].revents = 0};
  int32_t n_events = 0;

  for (;;)
  {
    n_events = poll(__fds, 1, CONN_POLL_TIMEOUT);
    // handling error
    if (n_events == -1){
      if (net_handle_poll_err(errno))
        return D_NET_EXIT;
      continue;
    }
    net_accept_save_new_co(server_addr, server_fd, total_cli__fds);
  }
  return __SUCCESS__;
}

//==========================================================================
//              EVENT HANDLING & POLLING COMMUNICATION AND DATA IO
//==========================================================================









//===========================MAIN EVENT LOOP========================  

/// @brief handler for incoming client data (called by the additionally created threads)
/// @param args hint to the struct defined in /include/base.h
/// @return errcode status
void *net_communication_handler(void *args)
{
  thread_arg_t *thread_arg = (thread_arg_t *)args;
  int32_t array_num = thread_arg->thread_no, n_events;
  #if (!MUTEX_SUPPORT)
    pthread_mutex_unlock(&__mutex);
  #endif
  for (;;)
  {
    
  }
}
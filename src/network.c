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

//==========================================================================
//                        CONNECTION HANDLING
//==========================================================================


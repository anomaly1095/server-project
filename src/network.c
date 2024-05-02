#include "../include/network.h"

static errcode_t net_ping_cli(pollfd_t *__fds, size_t i, const char *buf, size_t len);


//==========================================================================
//                        SERVER SETUP
//==========================================================================


#if (USING_HN)
/// @brief this functions gets called
/// @param server_addr 
/// @return 
static inline errcode_t net_get_ipaddr_byhost(sockaddr_t *server_addr) {
  struct hostent *hptr;
  if (!(hptr = gethostbyname(SERVER_DOMAIN)))
    return LOG(NET_LOG_PATH, h_errno, EGET_HOSTBYNAME_M);
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
  default: return LOG(NET_LOG_PATH, E_INVAL_ADDRLEN, E_INVAL_ADDRLEN_M);
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
//                  EVENT HANDLING & POLLING NEW CONNECTIONS
//==========================================================================

/// @brief 
/// @param co_new 
/// @param new_cli_fd 
/// @param new_addr 
/// @param addr_len 
/// @return 
static errcode_t net_co_create(co_t *co_new, sockfd_t new_cli_fd, sockaddr_t new_addr, socklen_t addr_len)
{
  // Check if the size of the address structure matches the expected size for IPv4 or IPv6
  if (addr_len != sizeof(struct sockaddr_in) && addr_len != sizeof(struct sockaddr_in6))
    return LOG(NET_LOG_PATH, E_UNSUPPORTED_AF, E_UNSUPPORTED_AF_M);

  // Set basic fields
  co_new->co_fd = new_cli_fd; 
  co_new->co_auth_status = CO_FLAG_NO_AUTH;
  co_new->co_af = new_addr.sa_family;
  memcpy((void*)&co_new->co_port, (const void*)new_addr.sa_data, sizeof(in_port_t));

  // Copy IP address
  if (new_addr.sa_family == AF_INET)
    memcpy(co_new->co_ip_addr, &((struct sockaddr_in*)&new_addr)->sin_addr, sizeof(struct in_addr));
  else if (new_addr.sa_family == AF_INET6)
    memcpy(co_new->co_ip_addr, &((struct sockaddr_in6*)&new_addr)->sin6_addr, sizeof(struct in6_addr));
  bzero((void*)co_new->co_key, crypto_secretbox_KEYBYTES);
  return __SUCCESS__;
}


/// @brief poll error handler 
/// @param __err value of errno passed as argument
/// @return __SUCCESS__--> resume process D_NET_EXIT--> cleanup and exit
static inline errcode_t net_handle_poll_err(int __err)
{
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
      sleep(MEM_WARN_INTV);
      break;
    default: return __SUCCESS__;
  }
  return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
}


/// @brief initialize pollfd structures for incoming data and fd = -1 so that they are ignored by poll
/// @param total_cli__fds all file descriptors available accross all threads
inline void net_init_clifd(pollfd_t **total_cli__fds)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
    for (size_t j = 0; j < CLIENTS_PER_THREAD; j++){
      total_cli__fds[i][j].fd = -1;
      total_cli__fds[i][j].events = 0;
      total_cli__fds[i][j].revents = 0;
    }
}


/// @brief 
/// @param thread_cli__fds 
/// @param db_connect 
/// @param new_cli_fd 
/// @param new_addr 
/// @param addr_len 
/// @return 
static inline errcode_t net_add_clifd_to_thread(pollfd_t *thread_cli__fds, MYSQL *db_connect, sockfd_t new_cli_fd, sockaddr_t new_addr, socklen_t addr_len)
{
  co_t co_new;
  for (size_t i = 0; i < CLIENTS_PER_THREAD; i++)
    if (thread_cli__fds[i].fd == -1)
    {
      thread_cli__fds[i].fd = new_cli_fd;
      thread_cli__fds[i].events = POLLIN | POLLPRI;  // we set the events to priority bcs the client did not auth yet
      // create connection instance
      if (net_co_create(&co_new, new_cli_fd, new_addr, addr_len))
        return __FAILURE__;
      // save instance to database Connection table
      pthread_mutex_lock(&mutex_connection_global); // lock the mutex for writing to db conenction object
      if (db_co_insert(db_connect, co_new)){
        pthread_mutex_unlock(&mutex_connection_global); // unlock the mutex 
        return __FAILURE__;
      }
      pthread_mutex_unlock(&mutex_connection_global); // unlock the mutex 
      return __SUCCESS__;
    }
  return MAX_FDS_IN_THREAD;
}


/// @brief 
/// @param thread_arg 
/// @param new_cli_fd 
/// @param new_addr 
/// @param addr_len 
/// @return 
static inline errcode_t net_add_clifd(thread_arg_t *thread_arg, sockfd_t new_cli_fd, sockaddr_t new_addr, socklen_t addr_len)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++)
    if (net_add_clifd_to_thread(thread_arg->total_cli__fds[i], thread_arg->db_connect, new_cli_fd, new_addr, addr_len))
      return LOG(NET_LOG_PATH, MAX_FDS_IN_PROGRAM, MAX_FDS_IN_PROGRAM_M);
  return __SUCCESS__;
}


/// @brief 
/// @param thread_arg 
/// @return 
static inline errcode_t net_accept_save_new_co(thread_arg_t *thread_arg)
{
  sockaddr_t new_addr;
  sockfd_t new_fd;
  socklen_t addr_len;
  // accept co
  if ((new_fd = accept(thread_arg->server_fd, &new_addr, &addr_len)) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));

  // add file descriptor to threads poll list
  if (net_add_clifd(thread_arg, new_fd, new_addr, addr_len))
    return __FAILURE__;
  return __SUCCESS__;
}


/// @brief event loop for handling incoming connections to the server (executed by the main thread)
/// @param thread_arg thread argument structure defined in include/threads.h
errcode_t net_connection_handler(thread_arg_t *thread_arg)
{
  pollfd_t __fds[1] = {[0].fd = thread_arg->server_fd, [0].events = POLLPRI, [0].revents = 0};
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
    net_accept_save_new_co(thread_arg);
  }
  return __SUCCESS__;
}


//==========================================================================
//              EVENT HANDLING & POLLING COMMUNICATION AND DATA IO
//==========================================================================


/// @brief disconnect client bcs recv returned 0 (close fd and put last fd in i)
/// @param __fds list of client file descriptors polled by this thread
/// @param i index of client file decriptor
static void cli_dc(MYSQL *db_connect, pollfd_t *__fds, size_t i)
{
  size_t j = i;
  while (__fds[j+1].fd != -1)
    j++;
  close(__fds[i].fd);
  __fds[i].fd = __fds[j].fd;
  __fds[j].fd = -1;
  if (db_co_up_auth_stat_by_fd(db_connect, CO_FLAG_DISCO, __fds[i].fd))
    j = LOG(DB_LOG_PATH, D_DB_EXIT, D_DB_EXIT_M);
}


/// @brief check error value in the recv() syscall
/// @param __fds list of file descriptors handled by the thread
/// @param i index of the cli fd
/// @param __err value of errno
static errcode_t net_handle_recv_err(MYSQL *db_connect, pollfd_t *__fds, size_t i, errcode_t __err)
{
  switch (__err){
    case EWOULDBLOCK || EAGAIN:
      return __SUCCESS__;
  
    case ECONNREFUSED:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __err, ECONNREFUSED_M1);
    
    case EFAULT:
      return LOG(NET_LOG_PATH, __err, EFAULT_M1);
    
    case ENOTCONN:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __err, ENOTCONN_M1);

    case EINTR: 
      return LOG(NET_LOG_PATH, __SUCCESS__, EINTR_M1);

    case ENOTSOCK:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOTSOCK_M1);
    
    case EINVAL:
      return LOG(NET_LOG_PATH, __SUCCESS__, EINVAL_M1);

    case ENOMEM: 
    #if (ATOMIC_SUPPORT)
      memory_w++;
    #else
      pthread_mutex_lock(&mutex_memory_w);
      memory_w++;
      pthread_mutex_unlock(&mutex_memory_w);  
    #endif
      sleep(MEM_WARN_INTV);
      return LOG(NET_LOG_PATH, __err, ENOMEM_M);
      break;
  }
  return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
}


/// @brief check error value in the send() syscall
/// @param __fds list of file descriptors handled by the thread
/// @param i index of the cli fd
/// @param __err value of errno
static errcode_t net_handle_send_err(MYSQL *db_connect, pollfd_t *__fds, size_t i, errcode_t __err)
{
  switch (__err){
    case EWOULDBLOCK || EAGAIN:
      return __SUCCESS__;
  
    case ECONNREFUSED:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, ECONNREFUSED_M2);
    
    case EALREADY:
      return LOG(NET_LOG_PATH, __SUCCESS__, EALREADY_M2);
    
    case EFAULT:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, EFAULT_M2);
    
    case EBADF:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, EBADF_M2);

    case ECONNRESET:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, ECONNRESET_M2);

    case ENOBUFS:
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOBUFS_M2);

    case ENOTCONN:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOTCONN_M2);

    case EINTR: 
      return LOG(NET_LOG_PATH, __SUCCESS__, EINTR_M2);

    case EMSGSIZE:
      return LOG(NET_LOG_PATH, __SUCCESS__, EMSGSIZE_M2);

    case ENOTSOCK:
      cli_dc(db_connect, __fds, i);
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOTSOCK_M2);
    
    case EINVAL:
      return LOG(NET_LOG_PATH, __SUCCESS__, EINVAL_M2);

    case ENOMEM: 
    #if (ATOMIC_SUPPORT)
      memory_w++;
    #else
      pthread_mutex_lock(&mutex_memory_w);
      memory_w++;
      pthread_mutex_unlock(&mutex_memory_w);  
    #endif
      sleep(MEM_WARN_INTV);
      return LOG(NET_LOG_PATH, __err, ENOMEM_M);
      break;
  }
  return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
}


/// @brief send all the data 
/// @param __fds list of pollfds getting polled
/// @param i index of client
/// @param buf buffer to send
/// @param n len of buffer
static inline errcode_t sendall(MYSQL *db_connect, pollfd_t *__fds, size_t i, const void *buf, size_t n)
{
  ssize_t rest = n, sent;
  int32_t attempts = 0;
  while (rest){
    if ((sent = send(__fds[i].fd, buf, n, MSG_DONTWAIT | MSG_OOB)) == -1){
      if (net_handle_send_err(db_connect, __fds, i, errno))
        pthread_exit(NULL);
      else
        return E_SEND_FAILED;
    }
    if (attempts == 4)
      return E_SEND_FAILED;
    rest = n - sent;
  }
  return __SUCCESS__;
}


/// @brief check for data availaibility coming from file descriptor
/// @param __fds list of file descriptors handled by the thread
/// @param i index of the cli fd
/// @param buf buffer to contain the stream
/// @return 1--->DATA_AVAILABLE  0--->DATA_UNAVAILABLE
static errcode_t net_data_available(MYSQL *db_connect, pollfd_t *__fds, size_t i, void *buf)
{
  
  int32_t mss, __err;
  socklen_t mss_len = sizeof mss;
  if (GET__MSS(__fds[i].fd, mss, mss_len) == -1) // minimum TP/IP segment size agreed on upon TCP's three way handshake
    return DATA_UNAVAILABLE;
  buf = malloc((size_t)mss);
  
  switch (recv(__fds[i].fd, buf, (size_t)mss, MSG_DONTWAIT | MSG_OOB))
  {
    // error
    case -1:
      free(buf);
      buf = NULL;
      __err = errno;
      if (net_handle_recv_err(db_connect, __fds, i, __err))// critical error
        pthread_exit(NULL);// terminate thread
      return DATA_UNAVAILABLE;
    // client disconnects
    case 0:
      free(buf);
      buf = NULL;
      cli_dc(db_connect, __fds[i].fd, i);
      return DATA_UNAVAILABLE;
    default:// data available
      return DATA_AVAILABLE;
  }
}


/// @brief iterate over client file descriptor to check which ones have data incoming
/// @param __fds list of file descriptors handled by the thread
static inline void net_check_clifds(MYSQL *db_connect, pollfd_t *__fds)
{
  size_t i = 0;
  void *buf = NULL;
  while (__fds[i].fd != -1 && ((__fds[i].revents & POLLIN) || (__fds[i].revents & POLLPRI))){
    if (buf)
      free(buf);
    if (net_data_available(db_connect, __fds, i, buf)){   // check if client's RCVBUFF is available
      if (__fds[i].revents & POLLPRI)
      {
        // call for request module to handle authentication
        if (req_pri_request_handle(buf, db_connect, __fds, i))
          return __FAILURE__;
      }
      else if (__fds[i].revents & POLLIN)
      {
        // call for request module to parse and handle data reception
        if (req_request_handle(buf, db_connect, __fds, i))
          return __FAILURE__;
      }
    }
    ++i;
  }
}


/// @brief handler for incoming client data (called by the additionally created threads)
/// @param args hint to the struct defined in header for threads
/// @return errcode NULL for now
void *net_communication_handler(void *args)
{
  thread_arg_t *thread_arg = (thread_arg_t *)args;
  pollfd_t *__fds = thread_arg->total_cli__fds[thread_arg->thread_id];
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_unlock(&mutex_thread_id);
    if (thread_arg->thread_id == SERVER_THREAD_NO)
      pthread_mutex_destroy(&mutex_thread_id);
  #endif
  int32_t n_events;
  for (;;)
  {
    while (!(n_events = poll(__fds, CLIENTS_PER_THREAD, COMM_POLL_TIMEOUT))) // do testings on the timeout value
      continue;
    switch (n_events)
    {
    case -1: // error occured
      if (net_handle_poll_err(errno))
        pthread_exit(NULL);
      continue;
    default:  // incoming data
      net_check_clifds(thread_arg->db_connect, __fds);
    }
  }
  pthread_exit(NULL);
}


//==========================================================================
//           COMMUNICATION PROTOCOL'S HANDSHAKES + AUTHENTICATION
//==========================================================================

/// @section    CLIENT AUTHENTICATION OVER THE NETWORK + KEY-EXCHANGE PROTOCOL 
/// @attention This section performs key exchanges over network it is not to be changed.
/// @attention only if the other end of the communication agrees on it.
/// @attention to ensure performance and valid communication cycles
/// @brief These functions in this section will mostly be called by the request handler module
/// @brief 1- send public key 
/// @brief 2- recv encrypted symmetric key + encrypted secret bytes
/// @brief 3- fetch the public and secret key from the database
/// @brief 4- decrypt the secret key + decrypt the secret bytes 
/// @brief 5- send the secret bytes encrypted by the secret key
/// @brief 6- recv the connected flag ----> REQ_VALID_SYMKEY
/// @attention You should check which functions set key memory space to 0 after usage !!


errcode_t send_pk()
{

}
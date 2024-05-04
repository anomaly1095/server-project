#include "../include/network.h"

//==========================================================================
//                        SERVER SETUP
//==========================================================================


#if (USING_HN)
/// @brief Retrieves the IP address associated with the specified host name.
/// @param server_addr Pointer to the server's sockaddr structure where the IP address will be stored
/// @return Error code indicating success or failure
static inline errcode_t net_get_ipaddr_byhost(sockaddr_t *server_addr) {
  // Retrieve host information using the specified domain name
  struct hostent *hptr;
  if (!(hptr = gethostbyname(SERVER_DOMAIN)))
    return LOG(NET_LOG_PATH, h_errno, EGET_HOSTBYNAME_M);
  // Determine the address family and convert the IP address to binary form
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
/**
 * @brief Determines the IP address either by converting the domain name to IP address or directly using the IP address.
 * 
 * This function gets the ip address to bind for the server
 * It handles ipv4 ipv6 and domain name 
 * 
 * @param server_addr Pointer to the server's sockaddr structure where the IP address will be stored
 * @return Error code indicating success or failure
 */
static inline errcode_t net_get_ipaddr(sockaddr_t *server_addr)
{
  // Check if SERVER_DOMAIN is an IP address or a domain name and handle accordingly
  #if (USING_IP)
    // Convert the IP address string to binary form
    if (inet_pton(SERVER_AF, SERVER_DOMAIN, (void*)&server_addr->sa_data[2]) != 1)
      return LOG(NET_LOG_PATH, errno, strerror(errno));
  #else
    // Perform DNS lookup to retrieve the IP address associated with the domain name
    if (net_get_ipaddr_byhost(server_addr))
      return ERR_IP_HANDLER;
  #endif
  return __SUCCESS__;
}


/**
 * @brief Fills up the server's sockaddr structure 
 *
 * This function initiate the sockaddr struct with port number and ip address (BIG ENDIAN)
 * and the address family
 *
 * @param server_addr Pointer to the server's sockaddr structure to be initialized
 * @return Error code indicating success or failure
 */
static inline errcode_t net_server_init(sockaddr_t *server_addr)
{
  // Initialize the memory block to zeros
  memset((void*)server_addr, 0x0, sizeof(*server_addr));
  // Set the address family to the specified value
  server_addr->sa_family = SERVER_AF;
  // Set the port in network byte order, taking into account endianness
  server_addr->sa_data[0] = (__BYTE_ORDER == __BIG_ENDIAN) ? (SERVER_PORT >> 8) : (SERVER_PORT & 0xFF);
  server_addr->sa_data[1] = (__BYTE_ORDER == __BIG_ENDIAN) ? (SERVER_PORT & 0xFF) : (SERVER_PORT >> 8);
  // Retrieve the IP address for the server
  if (net_get_ipaddr(server_addr))
    return ERR_IP_HANDLER;
  return __SUCCESS__;
}


/**
 * @brief Sets up the needed options for the server socket
 * 
 * This function sets up server socket options as defined in network.h
 * 
 * @param server_fd File descriptor of the server socket
 * @return Error code indicating success or failure
 */
static inline errcode_t net_set_server_opts(sockfd_t server_fd)
{
  // Set up various socket options needed for the server socket
  if (SET__KEEPALIVE(server_fd) == -1 || 
      SET__REUSEADDR(server_fd) == -1 || 
      SET__IDLETIME(server_fd)  == -1 || 
      SET__INTRLTIME(server_fd) == -1 || 
      SET__KEEPCNTR(server_fd)  == -1)
      // If any of the options setting fails, log the error
      return LOG(NET_LOG_PATH, errno, strerror(errno));
  // Return success if all options were successfully set
  return __SUCCESS__;
}

/**
 * @brief Setting up the server (socket / bind / options / listen)
 * 
 * This function sets up the server
 * 
 * @param server_addr Pointer to the server's address structure
 * @param server_fd Pointer to the server's socket file descriptor
 * @return Error code indicating success or failure
 */
errcode_t net_server_setup(sockaddr_t *server_addr, sockfd_t *server_fd)
{
  // Initialize the server address
  if (net_server_init(server_addr))
    return E_SERVER_SETUP;

  // Create a socket
  if ((*server_fd = socket(SERVER_AF, SERVER_SOCK_TYPE, SERVER_SOCK_PROTO)) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));

  // Bind the socket to the server address
  if (bind(*server_fd, (const sockaddr_t *)server_addr, sizeof(*server_addr)) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));

  // Set server socket options
  if (net_set_server_opts(*server_fd))
    return ENET_OPT_FAIL;

  // Listen for incoming connections
  if (listen(*server_fd, SERVER_BACKLOG) == -1)
    return LOG(NET_LOG_PATH, errno, strerror(errno));

  return __SUCCESS__;
}


//==========================================================================
//                  EVENT HANDLING & POLLING NEW CONNECTIONS
//==========================================================================

/**
 * @brief Creates a new connection instance.
 * 
 * This function creates a new connection instance using the provided parameters.
 * 
 * @param co_new Pointer to the new connection instance to be created.
 * @param new_cli_fd New client file descriptor.
 * @param new_addr Address of the new client.
 * @param addr_len Length of the address.
 * @return __SUCCESS__ if the connection instance is created successfully, or an error code if an error occurs.
 */
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
  
  // Clear the key
  bzero((void*)co_new->co_key, crypto_secretbox_KEYBYTES);
  
  return __SUCCESS__;
}



/**
 * @brief Handles poll errors.
 * 
 * This function handles errors that may occur during polling.
 * 
 * @param __err Value of errno passed as an argument.
 * @return __SUCCESS__ if the process can be resumed, D_NET_EXIT if cleanup and exit are required.
 */
static inline errcode_t net_handle_poll_err(int __err)
{
  LOG(NET_LOG_PATH, __err, strerror(__err)); // Log the error
  
  switch (__err)
  {
    case EFAULT:
    case EINVAL:
      // Exit if there's a fatal error related to the arguments
      return D_NET_EXIT;
      
    case EINTR:
      // Ignore interrupt signals
      break;
      
    case ENOMEM:
      // Handle out-of-memory condition by sleeping and increasing memory warning count
      memory_w++;
      sleep(MEM_WARN_INTV);
      break;
      
    default:
      // For other errors, resume the process
      return __SUCCESS__;
  }
  
  // Check if memory warning count has reached the maximum
  return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
}



/**
 * @brief Initializes pollfd structures for incoming data.
 * 
 * This function initializes the pollfd structures for incoming data. It sets the file descriptors to -1
 * so that they are ignored by poll.
 * 
 * @param total_cli__fds All file descriptors available across all threads.
 */
inline void net_init_clifd(pollfd_t **total_cli__fds)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++) {
    for (size_t j = 0; j < CLIENTS_PER_THREAD; j++) {
      // Set file descriptor to -1 so that it is ignored by poll
      total_cli__fds[i][j].fd = FD_DISCO;
      total_cli__fds[i][j].events = POLLIN | POLLPRI;
      total_cli__fds[i][j].revents = 0;
    }
  }
}




/**
 * @brief Adds a new client file descriptor to a thread's list.
 * 
 * This function adds a new client file descriptor, along with its address and length, to a specific thread's list of file descriptors.
 * 
 * @param thread_cli__fds Pointer to the list of file descriptors for the thread.
 * @param db_connect Pointer to the MySQL database connection.
 * @param new_cli_fd New client file descriptor to add.
 * @param new_addr Address of the new client.
 * @param addr_len Length of the address.
 * @return __SUCCESS__ if the client file descriptor is added successfully, __FAILURE__ if an error occurs, or MAX_FDS_IN_THREAD if the maximum number of file descriptors per thread is reached.
 */
static inline errcode_t net_add_clifd_to_thread(pollfd_t *thread_cli__fds, MYSQL *db_connect, sockfd_t new_cli_fd, sockaddr_t new_addr, socklen_t addr_len)
{
  co_t co_new;
  
  // Iterate through the thread's list of file descriptors
  for (size_t i = 0; i < CLIENTS_PER_THREAD; i++) {
    // Find an empty slot in the list of file descriptors
    if (thread_cli__fds[i].fd == FD_DISCO) {
      // Add the new client file descriptor to the list
      thread_cli__fds[i].fd = new_cli_fd;
      thread_cli__fds[i].events = POLLIN | POLLPRI; // Set events to priority because the client has not authenticated yet
      
      // Create a new connection instance
      if (net_co_create(&co_new, new_cli_fd, new_addr, addr_len) != __SUCCESS__)
        return __FAILURE__;
      
      // Save the connection instance to the database Connection table
      if (db_co_insert(db_connect, co_new) != __SUCCESS__) {
        return __FAILURE__;

      return __SUCCESS__;
    }
  }
  
  // If the maximum number of file descriptors per thread is reached
  return MAX_FDS_IN_THREAD;
}




/**
 * @brief Adds a new client file descriptor to each thread's list.
 * 
 * This function iterates through each thread and attempts to add the new client file descriptor,
 * along with its address and length, to the thread's list of file descriptors.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param new_cli_fd New client file descriptor to add.
 * @param new_addr Address of the new client.
 * @param addr_len Length of the address.
 * @return __SUCCESS__ if the client file descriptor is added successfully, MAX_FDS_IN_PROGRAM if the maximum number of file descriptors is reached, or __FAILURE__ for other errors.
 */
static inline errcode_t net_add_clifd(thread_arg_t *thread_arg, sockfd_t new_cli_fd, sockaddr_t new_addr, socklen_t addr_len)
{
  for (size_t i = 0; i < SERVER_THREAD_NO; i++) {
    if (net_add_clifd_to_thread(thread_arg->total_cli_fds[i], thread_arg->db_connect, new_cli_fd, new_addr, addr_len)) {
      // Log error if maximum number of file descriptors is reached
      return LOG(NET_LOG_PATH, MAX_FDS_IN_PROGRAM, MAX_FDS_IN_PROGRAM_M);
    }
  }
  
  return __SUCCESS__;
}



/**
 * @brief Accepts a new connection and saves it.
 * 
 * This function accepts a new connection on the server socket and saves it by adding the file descriptor
 * to the thread's poll list.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @return __SUCCESS__ if the new connection is accepted and saved successfully, __FAILURE__ otherwise.
 */
static inline errcode_t net_accept_save_new_co(thread_arg_t *thread_arg)
{
  sockaddr_t new_addr;
  sockfd_t new_fd;
  socklen_t addr_len = sizeof(new_addr); // Initialize addr_len with the size of sockaddr_t
  
  // Accept the new connection
  if ((new_fd = accept(thread_arg->server_fd, &new_addr, &addr_len)) == -1) {
    // Handle error if accept fails
    return LOG(NET_LOG_PATH, errno, strerror(errno));
  }

  // Add the file descriptor to the thread's poll list
  if (net_add_clifd(thread_arg, new_fd, new_addr, addr_len) == __FAILURE__) {
    // Handle error if adding file descriptor fails
    return __FAILURE__;
  }

  return __SUCCESS__;
}



/**
 * @brief Event loop for handling incoming connections to the server (executed by the main thread).
 * 
 * This function continuously polls for events on the server file descriptor and handles incoming connections.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure defined in include/threads.h.
 * @return __SUCCESS__ on successful execution, D_NET_EXIT if an error occurs.
 */
errcode_t net_connection_handler(thread_arg_t *thread_arg)
{
  pollfd_t __fds[1] = {[0].fd = thread_arg->server_fd, [0].events = POLLIN | POLLPRI, [0].revents = 0};
  int32_t n_events = 0;
  
  for (;;) {
    n_events = poll(__fds, 1, CONN_POLL_TIMEOUT);
    
    // Handling error
    if (n_events == -1) {
      if (net_handle_poll_err(errno))
        return D_NET_EXIT;
      continue;
    }
    
    // Accept and save new connection
    net_accept_save_new_co(thread_arg);
  }
  
  return __SUCCESS__;
}



//==========================================================================
//              EVENT HANDLING & POLLING COMMUNICATION AND DATA IO
//==========================================================================


/**
 * @brief Disconnects a client due to recv() returning 0 (indicating closed connection).
 * 
 * This function handles the disconnection of a client when the recv() syscall returns 0, indicating that the client has closed the connection.
 * It closes the file descriptor associated with the client, updates the connection authentication status and file descriptor in the database,
 * and updates the file descriptor array accordingly.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 * @param client_index Index of the client file descriptor.
 */
static void cli_dc(thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  size_t last_index = client_index; // Initialize the index of the last active client as the current client index
  
  // Find the index of the last active client file descriptor
  while (thread_arg->total_cli_fds[thread_index][last_index + 1].fd != -1)
    last_index++;
  
  // Close the client file descriptor
  close(thread_arg->total_cli_fds[thread_index][client_index].fd);
  
  // Update the connection authentication status in the database to indicate disconnection
  if (db_co_up_auth_stat_by_fd(thread_arg->db_connect, CO_FLAG_DISCO, thread_arg->total_cli_fds[thread_index][client_index].fd))
    LOG(DB_LOG_PATH, D_DB_EXIT, D_DB_EXIT_M); // Log error if database update fails

  // Update the connection file descriptor in the database to -1 to mark disconnection
  if (db_co_up_fd_by_fd(thread_arg->db_connect, FD_DISCO, thread_arg->total_cli_fds[thread_index][client_index].fd))
    LOG(DB_LOG_PATH, D_DB_EXIT, D_DB_EXIT_M); // Log error if database update fails

  // Swap the disconnected client file descriptor with the last active client file descriptor in the array and with it it's details
  thread_arg->total_cli_fds[thread_index][client_index].fd = thread_arg->total_cli_fds[thread_index][last_index].fd;
  thread_arg->total_cli_fds[thread_index][client_index].events = thread_arg->total_cli_fds[thread_index][last_index].events;
  thread_arg->total_cli_fds[thread_index][client_index].revents = thread_arg->total_cli_fds[thread_index][last_index].revents;
  thread_arg->total_cli_fds[thread_index][last_index].fd = FD_DISCO; // Set the last active client file descriptor to -1 to mark it as inactive
}




/**
 * @brief Check error value in the recv() syscall and handle accordingly.
 * 
 * This function checks the error value returned by the recv() syscall and handles it based on the error code.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 * @param client_index Index of the client file descriptor.
 * @param err Value of errno indicating the error.
 * @return __SUCCESS__ if the error is handled successfully, otherwise appropriate error code.
 */
static errcode_t net_handle_recv_err(thread_arg_t *thread_arg, size_t thread_index, size_t client_index, errcode_t err)
{
  #define CLI_DC_XX() cli_dc(thread_arg, thread_index, client_index);
  switch (err)
  {
    case EWOULDBLOCK || EAGAIN:
      return __SUCCESS__;
  
    case ECONNREFUSED:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, err, ECONNREFUSED_M1);
    
    case EFAULT:
      return LOG(NET_LOG_PATH, err, EFAULT_M1);
    
    case ENOTCONN:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, err, ENOTCONN_M1);

    case EINTR: 
      return LOG(NET_LOG_PATH, __SUCCESS__, EINTR_M1);

    case ENOTSOCK:
      CLI_DC_XX();
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
      return LOG(NET_LOG_PATH, err, ENOMEM_M);
    
    default:
      return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
  }
}



/**
 * @brief Check error value in the send() syscall and handle accordingly.
 * 
 * This function checks the error value returned by the send() syscall and handles it based on the error code.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 * @param client_index Index of the client file descriptor.
 * @param err Value of errno indicating the error.
 * @return __SUCCESS__ if the error is handled successfully, otherwise appropriate error code.
 */
static errcode_t net_handle_send_err(thread_arg_t *thread_arg, size_t thread_index, size_t client_index, errcode_t err)
{
  #define CLI_DC_XX() cli_dc(thread_arg, thread_index, client_index);
  switch (err) {
    case EWOULDBLOCK || EAGAIN:
      return __SUCCESS__;
    
    case ECONNREFUSED:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, __SUCCESS__, ECONNREFUSED_M2);
    
    case EALREADY:
      return LOG(NET_LOG_PATH, __SUCCESS__, EALREADY_M2);
    
    case EFAULT:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, __SUCCESS__, EFAULT_M2);
    
    case EBADF:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, __SUCCESS__, EBADF_M2);

    case ECONNRESET:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, __SUCCESS__, ECONNRESET_M2);

    case ENOBUFS:
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOBUFS_M2);

    case ENOTCONN:
      CLI_DC_XX();
      return LOG(NET_LOG_PATH, __SUCCESS__, ENOTCONN_M2);

    case EINTR: 
      return LOG(NET_LOG_PATH, __SUCCESS__, EINTR_M2);

    case EMSGSIZE:
      return LOG(NET_LOG_PATH, __SUCCESS__, EMSGSIZE_M2);

    case ENOTSOCK:
      CLI_DC_XX();
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
      return LOG(NET_LOG_PATH, err, ENOMEM_M);
    
    default:
      return (memory_w == MAX_MEM_WARN) ? D_NET_EXIT : __SUCCESS__;
  }
}


/**
 * @brief Send all data to a client.
 * 
 * This function attempts to send all data in the provided buffer to the specified client.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 * @param client_index Index of the client file descriptor.
 * @param buf Pointer to the buffer containing the data to send.
 * @param n Length of the data buffer.
 * @return __SUCCESS__ if all data is sent successfully, otherwise E_SEND_FAILED.
 */
static inline errcode_t sendall(thread_arg_t *thread_arg, size_t thread_index, size_t client_index, const void *buf, size_t n)
{
  ssize_t total_sent = 0;
  const char *ptr = buf;

  while (total_sent < n) {
    ssize_t sent = send(thread_arg->total_cli_fds[thread_index][client_index].fd, ptr + total_sent, n - total_sent, MSG_DONTWAIT | MSG_OOB);

    if (sent == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Socket buffer is full, try again later
        continue;
      }
      if (net_handle_send_err(thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index, errno)) {
        pthread_exit(NULL);
      } else {
        return E_SEND_FAILED;
      }
    }

    if (sent == 0) {
      // Socket closed unexpectedly
      if (net_handle_send_err(thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index, EPIPE)) {
        pthread_exit(NULL);
      } else {
        return E_SEND_FAILED;
      }
    }

    total_sent += sent;
  }

  return __SUCCESS__;
}



/**
 * @brief Check for data availability coming from a file descriptor.
 * 
 * This function checks if there is data available for reading on the specified file descriptor.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 * @param client_index Index of the client file descriptor.
 * @param buf Pointer to a buffer to contain the incoming data stream.
 * @return DATA_AVAILABLE if data is available, otherwise DATA_UNAVAILABLE.
 */
static errcode_t net_data_available(thread_arg_t *thread_arg, size_t thread_index, size_t client_index, void *buf)
{
  int32_t mss, recv_result, err;
  socklen_t mss_len = sizeof(mss);
  
  // Retrieve the Maximum Segment Size (MSS) for the TCP connection
  if (GET_MSS(thread_arg->total_cli_fds[thread_index][client_index].fd, &mss, &mss_len) == -1)
    return DATA_UNAVAILABLE; // Failed to retrieve MSS
  
  // Allocate memory for the buffer based on MSS
  buf = malloc((size_t)mss);
  
  // Attempt to receive data from the client socket
  recv_result = recv(thread_arg->total_cli_fds[thread_index][client_index].fd, buf, (size_t)mss, MSG_DONTWAIT | MSG_OOB);
  
  // Handle different cases of recv_result
  switch (recv_result)
  {
  case -1: // Error occurred
    free(buf);
    buf = NULL;
    err = errno;
    if (net_handle_recv_err(thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index, err))
      pthread_exit(NULL); // Critical error, terminate thread
    return DATA_UNAVAILABLE;
  case 0: // Client disconnected
    free(buf);
    buf = NULL;
    cli_dc(thread_arg, thread_index, client_index);
    return DATA_UNAVAILABLE;
  default: // Data available
    return DATA_AVAILABLE;
  }
}



/**
 * @brief Iterate over client file descriptors to check which ones have incoming data.
 * 
 * This function iterates over the list of client file descriptors handled by the thread
 * to check which ones have incoming data available for reading.
 * 
 * @param thread_arg Pointer to a thread_arg_t structure containing thread-specific information.
 * @param thread_index Index of the thread in the thread pool.
 */
static inline void net_check_clifds(thread_arg_t *thread_arg, size_t thread_index)
{
  size_t client_index = 0;
  void *buffer = NULL;
  
  // Iterate over client file descriptors
  while (thread_arg->total_cli_fds[thread_index][client_index].fd != -1 && 
         ((thread_arg->total_cli_fds[thread_index][client_index].revents & POLLIN) || 
          (thread_arg->total_cli_fds[thread_index][client_index].revents & POLLPRI)))
  {
    if (buffer)
      free(buffer);
    
    // Check if data is available on the client's receive buffer
    if (net_data_available(thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index, buffer))
    {
      if (thread_arg->total_cli_fds[thread_index][client_index].revents & POLLPRI) // client needs to authenticate
      {
        // Call request module to handle priority requests (e.g., authentication)
        if (req_pri_handle(buffer, thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index))
          return __FAILURE__;
      }
      else if (thread_arg->total_cli_fds[thread_index][client_index].revents & POLLIN) // client authenticated can perform I/O
      {
        // Call request module to parse and handle regular data reception
        if (req_handle(buffer, thread_arg->db_connect, thread_arg->total_cli_fds[thread_index], client_index))
          return __FAILURE__;
      }
    }
    ++client_index;
  }
}



/**
 * @brief Handler for incoming client data (called by the additionally created threads).
 * 
 * This function is responsible for handling incoming client data in a multi-threaded environment.
 * It continuously polls for events on the client file descriptors associated with the thread.
 * 
 * @param args Pointer to a thread_arg_t structure containing thread-specific information.
 * @return Always returns NULL.
 */
void *net_communication_handler(void *args)
{
  thread_arg_t *thread_arg = (thread_arg_t *)args;
  uint32_t thread_num = thread_arg->thread_id;
  
  // Destroy mutex if this thread is the server thread and atomic support is not enabled
  #if (!ATOMIC_SUPPORT)
    pthread_mutex_unlock(&mutex_thread_id);
    if (thread_arg->thread_id == SERVER_THREAD_NO)
      pthread_mutex_destroy(&mutex_thread_id);
  #endif
  
  int32_t n_events;
  for (;;)
  {
    // Poll for events on client file descriptors
    while (!(n_events = poll(thread_arg->total_cli_fds[thread_num], CLIENTS_PER_THREAD, COMM_POLL_TIMEOUT)))
      continue;
    
    // Handle poll errors
    switch (n_events)
    {
    case -1: // Error occurred
      if (net_handle_poll_err(errno))
        pthread_exit(NULL);
      continue;
    default:  // Incoming data
      net_check_clifds(thread_arg, thread_num);
    }
  }
  
  // This should never be reached, but pthread_exit is used for safety
  pthread_exit(NULL);
}



//==========================================================================
//           COMMUNICATION PROTOCOL'S HANDSHAKES + AUTHENTICATION
//==========================================================================

/**
 * @section CLIENT AUTHENTICATION OVER THE NETWORK + KEY-EXCHANGE PROTOCOL
 * 
 * @attention This section handles key exchanges over the network and should not be altered,
 *            unless both ends of the communication agree on it.
 *            Ensure performance and valid communication cycles.
 * 
 * @brief Functions in this section are primarily called by the request handler module.
 * 
 * @brief 1. Send Public Key
 *        2. Receive Encrypted Symmetric Key + Encrypted Secret Bytes
 *        3. Fetch Public and Secret Key from the database
 *        4. Decrypt the Secret Key + Decrypt the Secret Bytes
 *        5. Send the Secret Bytes Encrypted by the Secret Key
 *        6. Receive the Connected Flag (REQ_VALID_SYMKEY)
 * 
 * @attention Check which functions zero out key memory space after usage.
 */


/**
 * @brief Sends the public key to the client. (First step of authentication)
 * 
 * This function retrieves the public key from the database and sends it to the client identified by the thread and client indices.
 * and updates the client co_auth_status from the database
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the public key is sent successfully, or an error code if sending fails or retrieving the public key from the database fails.
 */
errcode_t net_send_pk(thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  
  // Retrieve the public key from the database
  if (db_get_pk(thread_arg->db_connect, pk))
    return __FAILURE__;
  
  // Send the public key to the client
  if (sendall(thread_arg, thread_index, client_index, pk, crypto_box_PUBLICKEYBYTES)){
    bzero((void*)pk, crypto_box_PUBLICKEYBYTES);
    return LOG(NET_LOG_PATH, E_SEND_PK, E_SEND_PK_M);
  }

  // Clear the public key from memory after sending
  bzero((void*)pk, crypto_box_PUBLICKEYBYTES);

  
  // Update client's connection authentication status in the database
  if (db_co_up_auth_stat_by_fd(thread_arg->db_connect, CO_FLAG_RECVD_PK, thread_arg->total_cli_fds[thread_index][client_index].fd))
    return LOG(NET_LOG_PATH, E_ALTER_CO_FLAG, E_ALTER_CO_FLAG_M);
  
  return __SUCCESS__;
}


/**
 * @brief Receive the symmetric key generated by the client and decrypt it.
 * 
 * This function:
 *  1. Retrieves the symmetric key from the client socket.
 *  2. Decrypts it with the (pk, sk) key pair retrieved from the database.
 *  3. Updates the connection authentication status flag in the database.
 *  4. Updates the key in the database.
 * 
 * @param req Binary stream of data coming from the network.
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return Error code indicating success or failure.
 */
errcode_t net_recv_key(const void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  uint32_t len_data1;
  uint8_t enc_key[ENCRYPTED_KEY_SIZE]; // size of asymmetrically encrypted symmetric key 
  uint8_t dec_key[crypto_secretbox_KEYBYTES];
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
  
  // Clear memory buffers
  bzero((void*)enc_key, ENCRYPTED_KEY_SIZE);
  bzero((void*)dec_key, crypto_secretbox_KEYBYTES);
  bzero((void*)pk, crypto_box_PUBLICKEYBYTES);
  bzero((void*)sk, crypto_box_SECRETKEYBYTES);

  // Copy the length of the data offset by 4 bytes that are used for the reqcode
  if (!memcpy((void*)&len_data1, req + 4, 4))
    return LOG(NET_LOG_PATH, EREQ_LEN, EREQ_LEN_M);
  
  // Check that the length of the data segment corresponds to the expected size
  if (len_data1 != ENCRYPTED_KEY_SIZE)
    return LOG(NET_LOG_PATH, EREQ_LEN, EREQ_LEN_M);
  
  // Move the encrypted data offset by 8 bytes that are used for the reqcode and seglen
  if (!memmove((void*)enc_key, req + 8, ENCRYPTED_KEY_SIZE))
    goto __failure;

  // Fetch asymmetric server keys from the database
  if (db_get_pk_sk(thread_arg->db_connect, pk, sk))
    goto __failure;
  
  // Decrypt the key
  if (secu_asymmetric_decrypt(pk, sk, enc_key, dec_key, ENCRYPTED_KEY_SIZE))
    goto __failure;

  // Update connection authentication status flag
  if (db_co_up_auth_stat_by_fd(thread_arg->db_connect, CO_FLAG_SENT_KEY, thread_arg->total_cli_fds[thread_index][client_index].fd))
    goto __failure;

  // Update the key in the database
  if (db_co_up_key_by_fd(thread_arg->db_connect, (const)dec_key, thread_arg->total_cli_fds[thread_index][client_index].fd))
    goto __failure;

  // Reset all security memory to 0x0
  bzero((void*)enc_key, ENCRYPTED_KEY_SIZE);
  bzero((void*)dec_key, crypto_secretbox_KEYBYTES);
  bzero((void*)pk, crypto_box_PUBLICKEYBYTES);
  bzero((void*)sk, crypto_box_SECRETKEYBYTES);
  return __SUCCESS__;

__failure:
  // Reset all security memory to 0x0
  bzero((void*)enc_key, ENCRYPTED_KEY_SIZE);
  bzero((void*)dec_key, crypto_secretbox_KEYBYTES);
  bzero((void*)pk, crypto_box_PUBLICKEYBYTES);
  bzero((void*)sk, crypto_box_SECRETKEYBYTES);
  
  return LOG(NET_LOG_PATH, E_PHASE2_AUTH, E_PHASE2_AUTH_M);
}


/**
 * @brief Sends an encrypted ping message to the client.
 * 
 * This function:
 *  1. Retrieves the connection object including the symmetric key from the database.
 *  2. Encrypts the ping message using the retrieved symmetric key.
 *  3. Sends the encrypted ping message to the client.
 *  4. Updates the connection status in the database to indicate that the ping was sent.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @param packet Pointer to the ping message data.
 * @param packet_len Length of the ping message data.
 * @return Error code indicating success or failure.
 */
errcode_t net_send_ping(thread_arg_t *thread_arg, size_t thread_index, size_t client_index, const void *packet, const size_t packet_len)
{
  uint8_t key[crypto_secretbox_KEYBYTES];
  uint8_t c[crypto_secretbox_MACBYTES + packet_len]; // Buffer for encrypted message

  // Retrieve connection object including the symmetric key from the database
  if (db_co_sel_key_by_fd(thread_arg->db_connect, key, thread_arg->total_cli_fds[thread_index][client_index].fd))
  {
    bzero(key, crypto_secretbox_KEYBYTES);
    return __FAILURE__;
  }

  // Encrypt the ping message
  if (secu_symmetric_encrypt(key, c, packet, packet_len))
  {
    bzero(key, crypto_secretbox_KEYBYTES);
    return __FAILURE__;
  }  

  bzero(key, crypto_secretbox_KEYBYTES);

  // Send the encrypted ping message
  if (sendall(thread_arg, thread_index, client_index, c, crypto_secretbox_MACBYTES))
    return LOG(NET_LOG_PATH, E_SEND_PING, E_SEND_PING_M);
  
  // Update connection status to indicate that ping was sent
  if (db_co_up_auth_stat_by_fd(thread_arg->db_connect, CO_FLAG_SENT_PING, thread_arg->total_cli_fds[thread_index][client_index].fd))
    return LOG(NET_LOG_PATH, E_SEND_PING, E_SEND_PING_M);

  return __SUCCESS__;
}


/**
 * @brief Receives and processes an encrypted ping message.
 * 
 * This function:
 *  1. Receives a ping message from the network.
 *  2. Decrypts the message using the key retrieved from the connection table in the database.
 *  3. Updates the connection authentication status flag in the database.
 *  4. Frees the data.
 * 
 * @param req Binary stream of data coming from the network.
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return Error code indicating success or failure.
 */
errcode_t net_recv_auth_ping(const void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  uint8_t key[crypto_secretbox_KEYBYTES];
  uint8_t *correct_ping = PING_HELLO; // Correct ping message
  uint8_t m[PING_HELLO_LEN]; // Buffer for decrypted message
  uint32_t seglen; // Length of data segment

  // Check length of data segment: offset by 4 for reqcode
  if (!memcpy((void*)&seglen, req + 4, 4))
    return LOG(NET_LOG_PATH, EREQ_LEN, EREQ_LEN_M);
  
  if (seglen != PING_HELLO_LEN)
    return LOG(NET_LOG_PATH, EREQ_LEN, EREQ_LEN_M);


  if (db_co_sel_key_by_fd(thread_arg->db_connect, key, thread_arg->total_cli_fds[thread_index][client_index].fd))
  {
    bzero(key, crypto_secretbox_KEYBYTES);
    return __FAILURE__;
  }
  
  // Decrypt the ping message
  if (secu_symmetric_decrypt(key, m, req + 8, PING_HELLO_LEN + crypto_secretbox_MACBYTES))
  {
    bzero(key, crypto_secretbox_KEYBYTES);
    return __FAILURE__;
  }  

  // Free  
  bzero(key, crypto_secretbox_KEYBYTES);

  // Check if the decrypted message matches the correct ping message
  if (memcmp(m, correct_ping, PING_HELLO_LEN))
    return LOG(NET_LOG_PATH, E_INVALID_PING, E_INVALID_PING_M);
  
  // Change connection authentication status in the database
  if (db_co_up_auth_stat_by_fd(thread_arg->db_connect, CO_FLAG_AUTH, thread_arg->total_cli_fds[thread_index][client_index].fd))
    return __FAILURE__;

  // change .events to pollin as the client is fully authenticated
  thread_arg->total_cli_fds[thread_index][client_index].events &= ~POLLPRI;

  return __SUCCESS__;
}


#include "../include/request.h"

//==========================================================================
//                                NORMAL REQUESTS
//==========================================================================

/**
 * @brief Sends the stream to the correct parsing function for the request code.
 * 
 * This function determines the type of request based on the request code and sends the stream to the corresponding parsing function.
 * 
 * @param req Binary stream of data coming from the network.
 * @param reqcode Code of the request.
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the request is processed successfully, or an error code if an undefined request code is encountered.
 */
static inline errcode_t req_run(void *req, uint32_t reqcode, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  switch (reqcode)
  {
    // Add cases for specific request codes and call corresponding parsing functions
    // case REQ_CODE_1:
    //   return parse_req_code_1(req, thread_arg, thread_index, client_index);
    // case REQ_CODE_2:
    //   return parse_req_code_2(req, thread_arg, thread_index, client_index);
    // Add more cases as needed
    
    default:
      // Log an error for undefined request code
      return LOG(REQ_LOG_PATH, EUNDEF_REQ_CODE, EUNDEF_REQ_CODE_M);
  }
  
  return __SUCCESS__;
}



/**
 * @brief Handles the incoming stream of data from the socket.
 * 
 * This function processes the incoming stream of data received from the network module's recv() function.
 * 
 * @param req Stream of data coming from the network module recv().
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the request is handled successfully, EREQ_FAIL if an error occurs.
 */
errcode_t req_handle(void *req, ssize_t len_req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  uint32_t reqcode;
  if (len_req < 4)
    return __FAILURE__;
  memcpy((void*)&reqcode, req, 4); // Get request code
  
  // Run the request
  if (req_run(req, reqcode, thread_arg, thread_index, client_index))
    return EREQ_FAIL;
  
  return __SUCCESS__;
}


//==========================================================================
//                            PRIORITY REQUESTS
//==========================================================================

/**
 * @brief Sends the stream to the correct parsing function for the request code.
 * 
 * This function determines the type of request based on the request code and sends the stream to the corresponding parsing function.
 * 
 * @param req Binary stream of data coming from the network.
 * @param reqcode Code of the request.
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the request is processed successfully, or an error code if an undefined request code is encountered.
 */
static inline errcode_t req_pri_run(void *req, uint32_t reqcode, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  switch (reqcode)
  {
    case REQ_SEND_ASYMKEY: 
      // Send the public key to the client as a response to REQ_SEND_ASYMKEY request
      net_send_pk(thread_arg, thread_index, client_index);
      // Free the memory allocated for the request stream
      free(req);
      break;
    case REQ_RECV_K:
      // Receive and process the symmetric key from the client as a response to REQ_RECV_K request
      net_recv_key(req, thread_arg, thread_index, client_index);
      // Free the memory allocated for the request stream
      free(req);
      break;
    case REQ_SEND_PING:
      // Send a ping message to the client as a response to REQ_SEND_PING request
      net_send_auth_ping(thread_arg, thread_index, client_index);
      // Free the memory allocated for the request stream
      free(req);
      break;
    case REQ_RECV_PING:
      // Receive and process a ping message from the client as a response to REQ_RECV_PING request
      net_recv_auth_ping(req, thread_arg, thread_index, client_index);
      // Free the memory allocated for the request stream
      free(req);
      break;
    case REQ_MODIF_SYMKEY:
      // Currently no implementation for modifying the symmetric key
      break;
    default:
      // Log an error for encountering an undefined request code
      return LOG(REQ_LOG_PATH, EUNDEF_REQ_CODE, EUNDEF_REQ_CODE_M);
  }
  
  return __SUCCESS__;
}




/**
 * @brief Handles priority data for client authentication.
 * 
 * This function processes priority data received from the network module's recv().
 * 
 * @param req Stream of data coming from the network module recv().
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the priority data is handled successfully, EREQ_FAIL if an error occurs.
 */
errcode_t req_pri_handle(void *req, ssize_t len_req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)
{
  uint32_t reqcode;
  if (len_req < 4)
    return __FAILURE__;
  memcpy((void*)&reqcode, req, 4); // Get request code
  
  // Run the request
  if (req_pri_run(req, reqcode, thread_arg, thread_index, client_index))
    return EREQ_FAIL;
  
  return __SUCCESS__;
}

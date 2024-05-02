#include "../include/request.h"

//==========================================================================
//                                NORMAL REQUESTS
//==========================================================================

/// @brief this function sends the stream to the correct parsing function for that reqcode
/// @param req binary stream of data coming from network
/// @param reqcode code of the request 
static inline errcode_t req_run_request(const void *req, MYSQL *db_connect, uint32_t reqcode, pollfd_t *__fds, size_t i)
{
  switch (reqcode)
  {
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    // case : 	break;
    default: return LOG(REQ_LOG_PATH, EUNDEF_REQ_CODE, EUNDEF_REQ_CODE_M);
  }
  return __SUCCESS__;
}




/// @brief get the incoming stream of data from the socket
/// @param req stream of data coming from network module recv()
errcode_t req_request_handle(const void *req, MYSQL *db_connect, pollfd_t *__fds, size_t i)
{
  uint32_t reqcode;
  memcpy((void*)&reqcode, req, 4); // get request code
  if (req_run_request(req, db_connect, reqcode, __fds, i))
    return EREQ_FAIL;
  return __SUCCESS__;
}

//==========================================================================
//                            PRIORITY REQUESTS
//==========================================================================

/// @brief __PRIORITY FOR AUTHENTICATION
/// @brief this function sends the stream to the correct parsing function for that reqcode
/// @param req binary stream of data coming from network
/// @param reqcode code of the request 
static inline errcode_t req_pri_run_request(const void *req, MYSQL *db_connect, uint32_t reqcode, pollfd_t *__fds, size_t i)
{
  switch (reqcode)
  {
    case REQ_SEND_ASYMKEY: 
      net_send_pk(db_connect, __fds, i);
      break;
    case REQ_RECV_K: 	      break;
    case REQ_VALID_SYMKEY: 	break;
    case REQ_MODIF_SYMKEY: 	break;
    case 4: 	break;
    case 5: 	break;
    case 6: 	break;
    default: return LOG(REQ_LOG_PATH, EUNDEF_REQ_CODE, EUNDEF_REQ_CODE_M);
  }
  return __SUCCESS__;
}


/// @brief __PRIORITY FOR AUTHENTICATION
/// @brief get priority data for client authentication
/// @param req stream of data coming from network module recv()
errcode_t req_pri_request_handle(const void *req, MYSQL *db_connect, pollfd_t *__fds, size_t i)
{
  uint32_t reqcode;
  memcpy((void*)&reqcode, req, 4); // get request code
  if (req_pri_run_request(req, db_connect, reqcode, __fds, i))
    return EREQ_FAIL;
  return __SUCCESS__;
}

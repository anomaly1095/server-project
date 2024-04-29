#include "../include/request.h"


/// @brief this function sends the stream to the correct parsing function for that reqcode
/// @param req binary stream of data coming from network
/// @param reqcode code of the request 
static inline req_run_request(const void *req, uint32_t reqcode)
{
  switch (reqcode){
    case REQ_SENT_ASYMKEY: 	break;
    case REQ_RECV_SYMKEY: 	break;
    case REQ_VALID_SYMKEY: 	break;
    case REQ_MODIF_SYMKEY: 	break;
    case 4: 	break;
    case 5: 	break;
    case 6: 	break;
    case 7: 	break;
    case 8: 	break;
    case 9: 	break;
    case 10: 	break;
    case 11: 	break;
    case 12: 	break;
    case 13: 	break;
    case 14: 	break;
    case REQ_CREATE_U: 	    break;
    case REQ_DELETE_U: 	    break;
    case REQ_MODIF_UNAME: 	break;
    case REQ_MODIF_UPASS: 	break;
    default: return LOG(REQ_LOG_PATH, EUNDEF_REQ_CODE, "Undefined request code");
  }
  return __SUCCESS__;
}


/// @brief get the incoming stream of data from the socket
/// @param req stream of data coming from network module recv()
inline errcode_t req_request_handle(const void *req)
{
  uint32_t reqcode;
  memcpy((void*)&reqcode, req, 4); // get request code
  if (req_run_request(req, reqcode))
    return EREQ_FAIL;
  return __SUCCESS__;
}


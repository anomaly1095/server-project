#include "../include/request.h"


/// @brief this function sends the stream to the correct parsing function for that reqcode
/// @param req binary stream of data coming from network
/// @param reqcode code of the request 
static inline req_run_request(const void *req, uint32_t reqcode)
{
  switch (reqcode){
    case 1: 	break; // return foo()
    case 2: 	break; // return foo()
    case 3: 	break; // return foo()
    case 4: 	break; // return foo()
    case 5: 	break; // return foo()
    case 6: 	break; // return foo()
    case 7: 	break; // return foo()
    case 8: 	break; // return foo()
    case 9: 	break; // return foo()
    case 10: 	break; // return foo()
    case 11: 	break; // return foo()
    case 12: 	break; // return foo()
    case 13: 	break; // return foo()
    case 14: 	break; // return foo()
    case 15: 	break; // return foo()
    case 16: 	break; // return foo()
    case 17: 	break; // return foo()
    case 18: 	break; // return foo()
    case 19: 	break; // return foo()
    case 20: 	break; // return foo()
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


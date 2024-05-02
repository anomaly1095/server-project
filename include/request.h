


#ifndef REQUEST_H
#define REQUEST_H     1
#include "threads.h"

/*==========================================================================================
|Requests are gona be sent from the client to the server                                    |
|we will define elssewhere messages that are going to be sent from the server to the client |
|.                                                                                          |  
|In this header we will discuss:                                                            |
|                 - the formatting of the incoming requests                                 |
|                 - the parsing                                                             |
|                 - handling all the requests and helper functions                          |
|                                                                                           |
| GENERAL FORMAT:                                                                           |
|             [req code 4 bytes][sizeseg1 4 bytes][seg1][sizedeg2 4 bytes][seg2]...         |
|  |
|  |
|  |
/*==========================================================================================*/

//===========================|
//------REQUEST NUMBERS------|
//===========================|

//---SECU REQUEST NUMBERS----|
#define REQ_SEND_ASYMKEY    0  // client received public key
#define REQ_RECV_K          1  // client sends encrypted symmetric key & salt
#define REQ_VALID_SYMKEY    2  // client confirms that the symkey is correct
#define REQ_MODIF_SYMKEY    3  // client requests to repete key exchange




errcode_t req_request_handle(const void *req, MYSQL *db_connect, pollfd_t *__fds, size_t i);

errcode_t req_pri_request_handle(const void *req, MYSQL *db_connect, pollfd_t *__fds, size_t i);

#endif
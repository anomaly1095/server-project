


#ifndef REQUEST_H
#define REQUEST_H     1
#include "base.h"
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
// request errors: 400
#define EUNDEF_REQ_CODE   400
#define EREQ_FAIL         401



extern errcode_t req_request_handle(const void *req);

#endif
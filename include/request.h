


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

//===========================|
//------REQUEST NUMBERS------|
//===========================|

//---SECU REQUEST NUMBERS----|
#define REQ_SENT_ASYMKEY    0  // client received public key
#define REQ_RECV_SYMKEY     1  // client sends encrypted symmetric key
#define REQ_VALID_SYMKEY    2  // client confirms that the symkey is correct
#define REQ_MODIF_SYMKEY    3  // client requests to repete key exchange

//---USER REQUEST NUMBERS----|
#define REQ_CREATE_USER        15
#define REQ_DELETE_USER        16
#define REQ_MODIF_UNAME     17
#define REQ_MODIF_UPASS     18




// USER 
extern errcode_t user_add(char *request);


extern errcode_t user_del(char *request);


extern errcode_t user_modif_username(char *request);


extern errcode_t user_modif_password(char *request);


extern errcode_t user_modif_sym_key(char *request);

extern void key_exchange(MYSQL *db_connect, pollfd_t *__fds, size_t i);

#endif
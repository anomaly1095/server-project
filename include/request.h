


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
|             [req code 4 bytes][seglen1 4 bytes][seg1][seglen2 4 bytes][seg2]...         |
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
errcode_t req_request_handle(const void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);

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
errcode_t req_pri_request_handle(const void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);


void net_send_pk(thread_arg_t *thread_arg, size_t thread_index, size_t client_index);

void net_recv_key(const void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index)


#endif
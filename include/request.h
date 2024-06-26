


#ifndef REQUEST_H
#define REQUEST_H     1
#include "database.h"
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
|==========================================================================================*/

#define PING_HELLO          (const char*)"Hello"
#define PING_HELLO_LEN     (const size_t)__builtin_strlen(PING_HELLO)

//===========================|
//------REQUEST NUMBERS------|
//===========================|

//---SECU REQUEST NUMBERS----|
#define REQ_SEND_ASYMKEY    0  // client received public key
#define REQ_RECV_K          1  // client sends encrypted symmetric key & salt
#define REQ_SEND_PING       2
#define REQ_RECV_PING       3
#define REQ_MODIF_SYMKEY    4  // client requests to repete key exchange


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
errcode_t req_handle(void *req, ssize_t len_req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);

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
errcode_t req_pri_handle(void *req, ssize_t len_req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);


/**
 * @brief Sends the public key to the client.
 * 
 * This function retrieves the public key from the database and sends it to the client identified by the thread and client indices.
 * 
 * @param thread_arg Pointer to the thread_arg_t structure.
 * @param thread_index Index of the thread.
 * @param client_index Index of the client.
 * @return __SUCCESS__ if the public key is sent successfully, or an error code if sending fails or retrieving the public key from the database fails.
 */
errcode_t net_send_pk(thread_arg_t *thread_arg, size_t thread_index, size_t client_index);


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
errcode_t net_recv_key(void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);



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
 * @return Error code indicating success or failure.
 */
errcode_t net_send_auth_ping(thread_arg_t *thread_arg, size_t thread_index, size_t client_index);


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
errcode_t net_recv_auth_ping(void *req, thread_arg_t *thread_arg, size_t thread_index, size_t client_index);



#endif
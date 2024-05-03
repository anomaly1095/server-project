

#ifndef __ERRORS_H
  #define __ERRORS_H      1
  
//=========================================================================

typedef int32_t errcode_t;
#define __SUCCESS__   00

// general purpose errors 1-->99
#define __FAILURE__   01
#define ELOG          02
#define E_FOPEN       03
#define E_FREAD       04
#define E_FWRITE      05
#define E_AUTH        06
#define E_PASS_LEN    07
#define E_INVAL_PASS  010
#define E_INIT        011
#define E_GETPASS     012
#define EINVALID_CHAR 013
#define EMALLOC_FAIL  014
/// @brief Danger return values (cleanup and exit)
#define D_NET_EXIT    014
#define D_SECU_EXIT   015
#define D_DB_EXIT     016
#define D_CORE_EXIT   017
// warnings
#define MAX_MEM_WARN  4 // maximum warning from the kernel before we do an emergency exit
#define MEM_WARN_INTV 1

#define E_GETPASS_M     "Error getting password)"
#define E_PASS_LEN_M    "Security invalid password length"
#define E_INVAL_PASS_M  "Security invalid password character"
#define EINVALID_CHAR_M "Invalid character found during passphrase check"


//=========================================================================
  //  security errors 100->150 
#define ESODIUM_INIT    100
#define ESECU_LOG       101
#define EKEYPAIR_GEN    102
#define EKEYPAIR_SAVE   103
#define EKEYPAIR_DEL    104
#define E_WRONG_CREDS   105
#define E_AUTHKEY       106
#define E_SHA512        107
#define E_ASYMM_ENCRYPT 108
#define E_ASYMM_DECRYPT 109
#define E_SYMM_ENCRYPT  110
#define E_SYMM_DECRYPT  111
#define E_SEND_PK       112
#define ESIZE_REQ_DATA  113

#define ESODIUM_INIT_M  "Security ctx_init failed"
#define E_FOPEN_M       "Error opening authentication private key file"
#define E_FREAD_M       "Error reading authentication private key file missing data!"
#define E_SHA512_M      "SHA512 cipher failed"
#define E_WRONG_CREDS_M "Securtiy Error wrong credentials"
#define EKEYPAIR_GEN_M  "Security keypair generation failed"
#define EKEYPAIR_DEL_M  "Security keypair deletion failed"
#define EKEYPAIR_DEL_M  "Security keypair deletion failed"
#define EKEYPAIR_SAVE_M "Security keypair saving failed"
#define E_ASYMM_ENCRYPT_M "Security Error during encryption with public key"
#define E_ASYMM_DECRYPT_M "Security Error during decryption with key pair"
#define E_SEND_PK_M     "Error occured during sending of public key to client"

//=========================================================================
// database ERRORS: 200->300
// many errnos will be defined in libmysql
#define EDB_LOG         200
#define EDB_CO_INIT     201 
    
#define EDB_GET_PKEY    205
#define EDB_FOPEN       206
#define EDB_FREAD       207
#define EDB_AUTH        208
#define EDB_W_HOST      209
#define EDB_W_USER      210
#define EDB_W_PASSWD    211
#define EDB_W_DB        212
#define EDB_W_PORT      213
#define EDB_CONNECT     214
#define WDB_NO_ROWS     215
#define DB_SIZE_HOST    256
#define DB_SIZE_USER    33
#define DB_SIZE_PASS    33
#define DB_SIZE_DB      65

#define D_DB_EXIT_M "Danger this error should be investigated file descriptor is not present id db"
#define EDB_W_HOST_M    "Error getting host for database connection"
#define EDB_W_USER_M    "Error getting username for database connection"
#define EDB_W_PASSWD_M  "Error getting password for database connection"
#define EDB_W_DB_M      "Error getting database name for database connection"
#define EDB_CO_INIT_M   "Database error during db_connect"
#define WDB_NO_ROWS_M1  "Warning: no rows found with that file descriptor"
#define WDB_NO_ROWS_M2  "Warning: no rows found with that authentication status"
#define WDB_NO_ROWS_M3  "Warning: no rows found with that ip address"
#define WDB_NO_ROWS_M4  "Warning: no rows found with that (ip address, port) pair"


#define EMALLOC_FAIL_M1 "Error: memory allocation failed for co in db_co_get_all_by_id()"
#define EMALLOC_FAIL_M2 "Error: memory allocation failed for co in db_co_get_all_by_fd()"
#define EMALLOC_FAIL_M3 "Error: memory allocation failed for co in db_co_get_all_by_auth_stat()"
#define EMALLOC_FAIL_M4 "Error: memory allocation failed for co in db_co_get_all_by_ip()"
#define EMALLOC_FAIL_M5 "Error: memory allocation failed for co in db_co_get_all_by_id()"

//=========================================================================

// request errors: 300-->400
#define EUNDEF_REQ_CODE     400
#define EREQ_FAIL           401
#define EREQ_LEN            402

#define EUNDEF_REQ_CODE_M   "Undefined request code"
#define EREQ_LEN_M          403

//=========================================================================
// network errors 400->500
// many errnos will be defined in libsodium
#define ENET_OPT_FAIL       400
#define E_SERVER_SETUP      401
#define E_INVAL_ADDRLEN     402
#define ERR_IP_HANDLER      403
#define MAX_FDS_IN_THREAD   404
#define MAX_FDS_IN_PROGRAM  405
#define E_KEY_EXCHANGE      406
#define E_SEND_FAILED       407
#define E_MISSING_DATA      408
#define E_UNSUPPORTED_AF    409
#define E_ALTER_CO_FLAG     410
#define E_PHASE2_AUTH       411

#define ENOMEM_M           "WARNING kernel out of memory"
#define EGET_HOSTBYNAME_M   "Error during server DNS lookup"
#define E_INVAL_ADDRLEN_M   "Invalid address len resulting of DNS resolving"
#define E_UNSUPPORTED_AF_M  "Warning Unsupported address family in new connection"
#define MAX_FDS_IN_PROGRAM_M"WARNING max_file descriptors reached for system"
#define ECONNREFUSED_M1     "ERROR in recv() A remote host refused to allow the network connection"
#define EFAULT_M1           "ERROR in recv() The receive buffer pointer point outside the \
process's address space."
#define ENOTCONN_M1         "ERROR in recv() The socket is associated with a connection-oriented \
protocol and has not been connected"
#define EINTR_M1            "ERROR in recv() interrupt occured"
#define ENOTSOCK_M1         "ERROR in recv() fd is not a socket"
#define EINVAL_M1           "ERROR in recv() invalid argument"
#define ECONNREFUSED_M2     "ERROR in send() A remote host refused to allow the network connection"
#define EALREADY_M2         "ERROR in send() Another Fast Open is in progress.."
#define EFAULT_M2           "ERROR in send() An invalid user space address was specified for an argument."
#define EBADF_M2            "ERROR in send() Invalid file descriptor."
#define ECONNRESET_M2       "ERROR in send() Connection was reset by peer."
#define ENOBUFS_M2          "The output queue for a network interface was full. This generally \
indicates that the interface has stopped sending, but maybe  caused  by transient congestion"
#define ENOTCONN_M2         "ERROR in send() The socket is associated with a connection-oriented \
protocol and has not been connected"
#define EINTR_M2            "ERROR in send() interrupt occured"
#define EMSGSIZE_M2         "WARNING in send() The buffer size is way too big"
#define ENOTSOCK_M2         "ERROR in send() fd is not a socket"
#define EINVAL_M2           "ERROR in send() invalid argument"
#define E_ALTER_CO_FLAG_M   "ERROR when altering client authentication status in database"
#define E_PHASE2_AUTH_M     "ERROR could be CRITICAL in net_recv_key()"


//=========================================================================

#endif

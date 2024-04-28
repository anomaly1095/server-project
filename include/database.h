

#ifndef DATABASE_H
#define DATABASE_H      1
#include "security.h"

// DB ERRORS: 200->300
// many errnos are defined in MYSQL API
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
    
#define DB_SIZE_HOST    256
#define DB_SIZE_USER    33
#define DB_SIZE_PASS    33
#define DB_SIZE_DB      65

typedef struct DBCreds{
    char host[DB_SIZE_HOST];
    char user[DB_SIZE_USER];
    char passwd[DB_SIZE_PASS];
    char db[DB_SIZE_DB];
    uint32_t port;
}db_creds_t;

errcode_t db_init(MYSQL **db_connect);

#endif
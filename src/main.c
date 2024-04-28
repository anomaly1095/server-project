#include "../include/core.h"


errcode_t main(int32_t argc, const char **argv)
{
  MYSQL *db_connect;
  if (__init__(&db_connect))
    return E_INIT;

  return __SUCCESS__;
}

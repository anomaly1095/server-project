#include <stdio.h>

#include <string.h>
#include <unistd.h>


static inline __int32_t db_get_auth_pass(char *passwd)
{
  printf("db password: ");
  char *input = getpass("");
  strncpy(passwd, input, 32);
  passwd[32] = '\0';
  return 0;
}

int main(void)
{
  char passwd[33];
  db_get_auth_pass(passwd);
  for (size_t i = 0; i < 33; i++)
    printf("%02x", passwd[i]);
  
  return 0;
}

#include <stdio.h>
#include <string.h>

#define STR "Hello %s"
#define STR_LEN __builtin_strlen(STR)
__int32_t main(__int32_t argc, const char **argv)
{
  char str[STR_LEN+20];
  sprintf(str, STR, "Youssef");
  printf("%s\n", str);
  return 0;
}
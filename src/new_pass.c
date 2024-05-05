#include "../include/base.h"

// Function to check if a character is within the valid ASCII printable range
static inline errcode_t pass_check_charx(const char c) {
  if (c < 32 || c > 126)
    return __FAILURE__;
  return __SUCCESS__;
}

// Function to check the passphrase for validity
static inline void check_passx(const char *pass) {
  size_t plen = strlen(pass);

  // Check passphrase length
  if (plen > MAX_AUTH_SIZE || plen < MIN_AUTH_SIZE) {
    fprintf(stderr, "Password should be between %u and %u characters long\n", MIN_AUTH_SIZE, MAX_AUTH_SIZE);
    exit(__FAILURE__);
  }

  // Check passphrase characters
  for (size_t i = 0; i < plen; i++) {
    if (pass_check_charx(pass[i])) {
      fprintf(stderr, "Invalid character in password\n");
      exit(__FAILURE__);
    }
  }
}

// Function to get user input for the new password
static inline void get_passx(char *pass) {
  printf("Enter new password: ");
  char *input1 = getpass("");

  if (!input1) {
    fprintf(stderr, "Failed to read password input\n");
    exit(__FAILURE__);
  }

  size_t plen1 = strlen(input1);
  
  printf("Confirm new password: ");
  char *input2 = getpass("");

  if (!input2) {
    fprintf(stderr, "Failed to read password input\n");
    exit(__FAILURE__);
  }

  size_t plen2 = strlen(input2);
  
  if (memcmp(input1, input2, plen1) != 0 || plen1 != plen2){
    bzero(input1, plen1);
    bzero(input2, plen2);
    fprintf(stderr, "Passwords entered do not match\n");
    exit(__FAILURE__);
  }

  strncpy(pass, input1, MAX_AUTH_SIZE);

  // Remove trailing newline character
  pass[strcspn(pass, "\n")] = '\0';

  // Zero out sensitive memory
  bzero(input1, plen1);
  bzero(input2, plen2);
}

// Function to initialize security library (libsodium)
static inline void secu_initx(void) {
  if (sodium_init() == -1) {
    fprintf(stderr, "Failed to initialize libsodium\n");
    exit(__FAILURE__);
  }
}

// Function to store the authentication key in a physical key file
static inline void set_auth_keyx(uint8_t *c) {
  FILE *phys_key_f = fopen(PATH_PHYSKEY, "wb");

  if (!phys_key_f) {
    bzero(c, crypto_hash_sha512_BYTES); 
    fprintf(stderr, "Failed to open file for writing\n");
    exit(__FAILURE__);
  }

  if (fwrite((void*)c, 1, crypto_hash_sha512_BYTES, phys_key_f) < crypto_hash_sha512_BYTES) {
    bzero(c, crypto_hash_sha512_BYTES); 
    fprintf(stderr, "Failed to write authentication key to file\n");
    exit(__FAILURE__);
  }

  fclose(phys_key_f);
}

int main(void) {
  char pass[MAX_AUTH_SIZE];
  uint8_t c[crypto_hash_sha512_BYTES];
  secu_initx();
  get_passx(pass);
  check_passx(pass);

  if (crypto_hash_sha512(c, pass, strlen(pass))) {
    fprintf(stderr, "Failed to encrypt password\n");
    exit(__FAILURE__);
  }

  set_auth_keyx(c);

  // Zero out buffers after success
  bzero(pass, MAX_AUTH_SIZE);
  bzero(c, crypto_hash_sha512_BYTES);

  return __SUCCESS__;
}
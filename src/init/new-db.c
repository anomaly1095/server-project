#include "../../include/database.h"

// Function to validate the database name
static inline void check_args(const char *db_name) {
  // Calculate the length of the database name
  size_t len = strlen(db_name);
  // Check if the length exceeds the maximum allowed length
  if (len > DB_SIZE_DB) {
    // Print an error message indicating the length of the database name
    fprintf(stderr, ERROR_DB_NAME_LENGTH_M, db_name);
    // Terminate the program
    _Exit(1);
  }
  // Iterate over each character in the database name
  for (size_t i = 0; i < len; i++) {
    // Check if the character is valid (a-z, A-Z, 0-9, _, or $)
    if (!((db_name[i] >= 'a' && db_name[i] <= 'z') || (db_name[i] >= 'A' && db_name[i] <= 'Z') || (db_name[i] >= '0' && db_name[i] <= '9') || db_name[i] == '_' || db_name[i] == '$')) {
      // Print an error message indicating the invalid character
      fprintf(stderr, ERROR_DB_NAME_CHAR_M, db_name[i]);
      // Terminate the program
      _Exit(__FAILURE__);
    }
  }
}

  /**
 * @brief Prompt user for the database hostname.
 * 
 * @param host Buffer to store the hostname.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
static inline errcode_t db_get_auth_host(char *host) {
    printf("Enter database hostname: ");
    if (!fgets(host, DB_SIZE_HOST, stdin))
        return __FAILURE__;
    host[strcspn(host, "\n")] = 0X0; // Remove trailing newline
    return __SUCCESS__;
}

/**
 * @brief Prompt user for the database username.
 * 
 * @param user Buffer to store the username.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
static inline errcode_t db_get_auth_user(char *user) {
    printf("Enter database username: ");
    if (!fgets(user, DB_SIZE_USER, stdin))
        return __FAILURE__;
    user[strcspn(user, "\n")] = 0x0; // Remove trailing newline
    return __SUCCESS__;
}

/**
 * @brief Prompt user for the database password.
 * 
 * @param passwd Buffer to store the password.
 * @return __SUCCESS__ on success, __FAILURE__ on failure.
 */
static inline errcode_t db_get_auth_pass(char *passwd) {
    printf("Enter database password: ");
    char *input = getpass("");
    strncpy(passwd, input, DB_SIZE_PASS - 1);
    passwd[DB_SIZE_PASS - 1] = 0x0; // Ensure null-termination
    return __SUCCESS__;
}

/**
 * @brief Perform realtime authentication from admin.
 * 
 * This function prompts the user for database credentials and populates
 * the db_creds_t structure with the provided values.
 * 
 * @param creds Pointer to db_creds_t structure to store the credentials.
 * @return __SUCCESS__ on success, appropriate error code on failure.
 */
errcode_t db_get_authx(db_creds_t *creds, MYSQL *db_connect)
{
  memset(creds, 0, sizeof(*creds));
  if (db_get_auth_host(creds->host)){
    // If connection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CONNECT_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
  if (db_get_auth_user(creds->user))
  {
    // If connection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CONNECT_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
  if (db_get_auth_pass(creds->passwd)){
    // If connection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CONNECT_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
  creds->port = DB_DEFAULT_PORT; // Assuming DEFAULT_DB_PORT is defined elsewhere
  return __SUCCESS__;
}

// Function to establish a connection to the database
static inline void connect_database(MYSQL *db_connect) {
  db_creds_t creds;
  bzero((void*)&creds, sizeof creds);
  db_get_authx(&creds, db_connect);
  
  // Attempt to establish a connection to the MySQL database
  if (!mysql_real_connect(db_connect, creds.host, creds.user, creds.passwd, NULL, creds.port, NULL, 0))
  {
    // If connection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CONNECT_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
}

// Function to create database tables
static inline void create_database_tables(MYSQL *db_connect, const char *db_name) {
  // Create a query to create a new database with the given name
  char query[MAX_QUERY_LENGTHX];
  snprintf(query, MAX_QUERY_LENGTHX, QUERY_NEW_DB, db_name);
  // Execute the query to create the new database
  if (mysql_query(db_connect, query)) {
    // If query execution fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CREATE_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
  // Select the newly created database
  if (mysql_select_db(db_connect, db_name)) {
    // If selection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_SELECT_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
  // Execute queries to create required tables within the database
  if (mysql_query(db_connect, QUERY_CREATE_CO) || mysql_query(db_connect, QUERY_CREATE_KEYPAIR)) {
    // If table creation fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_TABLES_M, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(__FAILURE__);
  }
}

// Main function
int main(int argc, const char **argv) {
  MYSQL *db_connect; // Declare a MySQL connection pointer
  // Check if the correct number of arguments is provided
  if (argc != 2) {
    // If not, print usage information and terminate the program
    fprintf(stderr, "Correct Usage: %s <new-db name>\n", argv[0]);
    _Exit(__FAILURE__);
  }
  // Validate the provided database name
  check_args(argv[1]);
  // Initialize a MySQL connection
  db_connect = mysql_init(NULL);
  // Check if initialization is successful
  if (!db_connect) {
    // If not, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_INIT_M);
    _Exit(__FAILURE__);
  }
  // Establish a connection to the MySQL database
  connect_database(db_connect);
  // Create database tables
  create_database_tables(db_connect, argv[1]);
  // Print success message
  printf(SUCCESS_DB_CREATED_M);
  // Close the MySQL connection
  mysql_close(db_connect);
  // Exit the program with success status
  return __SUCCESS__;
}

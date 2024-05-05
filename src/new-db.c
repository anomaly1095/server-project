#include "../include/database.h"

// Function to validate the database name
static inline void check_args(const char *db_name) {
  // Calculate the length of the database name
  size_t len = strlen(db_name);
  // Check if the length exceeds the maximum allowed length
  if (len > DB_SIZE_DB) {
    // Print an error message indicating the length of the database name
    fprintf(stderr, ERROR_DB_NAME_LENGTH, db_name);
    // Terminate the program
    _Exit(1);
  }
  // Iterate over each character in the database name
  for (size_t i = 0; i < len; i++) {
    // Check if the character is valid (a-z, A-Z, 0-9, _, or $)
    if (!((db_name[i] >= 'a' && db_name[i] <= 'z') || (db_name[i] >= 'A' && db_name[i] <= 'Z') || (db_name[i] >= '0' && db_name[i] <= '9') || db_name[i] == '_' || db_name[i] == '$')) {
      // Print an error message indicating the invalid character
      fprintf(stderr, ERROR_DB_NAME_CHAR, db_name[i]);
      // Terminate the program
      _Exit(1);
    }
  }
}

// Function to get user input for the new password
static inline void get_passx(char *pass) {
  // Prompt the user to enter a new password
  printf("Enter new password: ");
  // Get the password input from the user (without echoing)
  char *input = getpass("");
  // Check if input is NULL
  if (!input) {
    // Print an error message
    fprintf(stderr, "Failed to read password input\n");
    // Terminate the program
    exit(__FAILURE__);
  }
  // Calculate the length of the input password
  size_t plen = strlen(input);
  // Copy the input password to the pass buffer
  memcpy(pass, input, plen);
  // Remove the trailing newline character, if present
  pass[strcspn(pass, "\n")] = '\0';
  // Zero out sensitive memory (clearing the input password)
  memset(input, 0, plen);
}

// Function to establish a connection to the database
static inline void connect_database(MYSQL *db_connect) {
  // Set the host, user, password, and port for the MySQL connection
  const char *host = DB_DEFAULT_HOST;
  const char *user = "admin";
  char password[DB_SIZE_PASS]; // Replace with your password
  const unsigned int port = DB_DEFAULT_PORT; // Default MySQL port
  // Get the password from the user
  get_passx(password);
  // Attempt to establish a connection to the MySQL database
  if (!mysql_real_connect(db_connect, host, user, password, NULL, port, NULL, 0)) {
    // If connection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_CONNECT, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(1);
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
    fprintf(stderr, ERROR_DB_CREATE, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(1);
  }
  // Select the newly created database
  if (mysql_select_db(db_connect, db_name)) {
    // If selection fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_SELECT, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(1);
  }
  // Execute queries to create required tables within the database
  if (mysql_query(db_connect, QUERY_CREATE_CO) || mysql_query(db_connect, QUERY_CREATE_KEYPAIR)) {
    // If table creation fails, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_TABLES, mysql_error(db_connect));
    mysql_close(db_connect);
    _Exit(1);
  }
}

// Main function
int main(int argc, const char **argv) {
  MYSQL *db_connect; // Declare a MySQL connection pointer
  // Check if the correct number of arguments is provided
  if (argc != 2) {
    // If not, print usage information and terminate the program
    fprintf(stderr, "Correct Usage: %s <new-db name>\n", argv[0]);
    _Exit(1);
  }
  // Validate the provided database name
  check_args(argv[1]);
  // Initialize a MySQL connection
  db_connect = mysql_init(NULL);
  // Check if initialization is successful
  if (!db_connect) {
    // If not, print an error message and terminate the program
    fprintf(stderr, ERROR_DB_INIT);
    _Exit(1);
  }
  // Establish a connection to the MySQL database
  connect_database(db_connect);
  // Create database tables
  create_database_tables(db_connect, argv[1]);
  // Print success message
  printf(SUCCESS_DB_CREATED);
  // Close the MySQL connection
  mysql_close(db_connect);
  // Exit the program with success status
  return 0;
}

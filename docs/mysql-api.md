# API Reference

## MySQL C API

**Description:** The MySQL C API allows C programs to interact with MySQL databases.

### Prepared Statements

**Description:** Prepared statements are SQL statements that are precompiled by the database server, which improves efficiency and security.

**Functions:**
- `mysql_stmt_init()`: Initialize a prepared statement handle.
- `mysql_stmt_prepare()`: Prepare an SQL statement for execution.
- `mysql_stmt_bind_param()`: Bind parameters to a prepared statement.
- `mysql_stmt_execute()`: Execute a prepared statement.
- `mysql_stmt_bind_result()`: Bind result set columns to variables.
- `mysql_stmt_store_result()`: Store the result set on the client side.

### Result Handling

**Description:** After executing a query, the MySQL C API provides functions to retrieve and process the result set.

**Functions:**
- `mysql_stmt_bind_result()`: Bind result set columns to variables.
- `mysql_stmt_store_result()`: Store the result set on the client side.
- `mysql_stmt_fetch()`: Fetch the next row of data from the result set.
- `mysql_stmt_free_result()`: Free the memory associated with the result set.
- `mysql_fetch_row()`: Fetch the next row of data from a result set as an array.
- `mysql_fetch_lengths()`: Get the lengths of the values in the current row of a result set.

### Example Function

**Description:** Example function demonstrating the usage of prepared statements and result handling.

```c
/**
 * @brief Get all columns by ID from the database.
 * 
 * This function retrieves all columns of a connection identified by the given ID from the database.
 * Memory will be allocated internally for the `co` object to store the retrieved data.
 * 
 * @param db_connect The MYSQL database connection.
 * @param co Pointer to a pointer to a connection object. Memory will be allocated internally for this object.
 * @param co_id The ID of the connection.
 * @return An error code indicating the status of the operation.
 */
errcode_t db_co_sel_all_by_id(MYSQL *db_connect, co_t **co, const id64_t co_id)
{
  // Function implementation...
}

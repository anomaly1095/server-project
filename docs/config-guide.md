## Server Configuration (.config.h)

The `include/.config.h` file provides a central location to manage your server application's configuration. This guide details the various settings you can adjust, emphasizing the importance of using environment-specific values (development, testing, production).

### Configuration Modes

The server operates in one of three mutually exclusive modes: development, testing, or production. Flags in `.config.h` control this behavior (e.g., `DEV_MODE`, `TEST_MODE`, `PROD_MODE`). Only one flag should be active at a time.

### General Configuration Options

* **Authentication Sizes:** Define minimum and maximum allowed lengths for authentication data (usernames, passwords).
* **Physical Key Path (Placeholder):** A commented-out line might provide an example path to a physical key file. Replace this with the actual path to your mounted USB key for production use.

### Server Configuration (Mode-Specific)

Specific configuration details vary depending on the active mode. Here's a breakdown of the general categories you can configure:

#### Server Connection

* **Server Address:**
    * `SERVER_DOMAIN`: Hostname or IP address where the server listens for connections.
    * `SERVER_PORT`: Port number used by the server.
* **Socket and Protocol:**
    * `SERVER_SOCKET_TYPE`: Socket type (likely `SOCK_STREAM` for TCP connections).
    * `SERVER_PROTOCOL`: Protocol (likely `IPPROTO_TCP`).

#### Server Threads

* **Worker Threads:**
    * `SERVER_THREAD_NO`: Number of worker threads to handle concurrent client requests (adjust based on system resources and expected traffic).
* **Connection Queue:**
    * `SERVER_BACKLOG`: Maximum number of pending connections allowed in the server's queue.

#### Database Configuration (Development Placeholders)

**Important:** The following options are placeholders used specifically for development mode:

* `DB_DEFAULT_HOST`
* `DB_DEFAULT_USER`
* `DB_DEFAULT_PASS`
* `DB_DEFAULT_DB`
* `DB_DEFAULT_PORT`

In production environments, configure your actual database credentials securely outside of `.config.h` (e.g., environment variables).

### Recommendations

* Activate only one mode (DEV_MODE, TEST_MODE, or PROD_MODE) at a time.
* Replace placeholder values with your specific configurations for production use.
* Consult system documentation for adjusting server thread and backlog values based on your hardware resources.
* Configure your actual database credentials securely outside of `.config.h`.

By understanding these configurable options and referring to the specific values in your `.config.h` file, you can effectively tailor your server application for the desired operational mode.

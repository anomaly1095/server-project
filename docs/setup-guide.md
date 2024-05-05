## Setting Up the Server Application

This guide walks you through the steps required to set up and run the server application for your project.

**Prerequisites**

* Git installed on your system (https://git-scm.com/downloads)

**Steps**

1. **Clone the Repository:**

   Open a terminal window and navigate to the directory where you want to install the project. Then, run the following command to clone the repository from GitHub:

     ```bash
     git clone [https://github.com/anomaly1095/server-project.git](https://github.com/anomaly1095/server-project.git)
     ```

2. **Change Directory:**

   Navigate into the newly cloned project directory:

     ```bash
     cd server-project
     ```

3. **Grant Execution Permission:**

   The `install.sh` script is used to set up dependencies. Make it executable with this command:

     ```bash
     chmod 544 install.sh
     ```

4. **Install Dependencies:**

   Run the `install.sh` script to install the necessary dependencies for your project:

     ```bash
     ./install.sh
     ```

5. **Configure Server Settings (`include/.config.h`):**

   Open the `include/.config.h` file in a text editor. Here, you can modify the following configuration options to suit your environment:

     * **Host Address:** Specify the IP address or hostname where the server will listen for incoming connections.
     * **Threads:** Define the number of worker threads for handling concurrent requests.
     * **Number of Connections:** Set the maximum number of connections allowed for clients.
     * **Path to USB Key:** If using USB key authentication, enter the path to the mounted USB key here.

6. **View Build Options:**

   Use the `make help` command to see a list of available build options for the project:

     ```bash
     make help
     ```

7. **Project Components:**

   This project includes three applications:

     * **Main Server Application:** This is the core server application that serves requests and manages connections.
     * **Database Initialization:** This tool initializes a new database for your project.
     * **Passkey Initialization:** This tool allows you to set up a secure passkey stored on a mounted USB key.

8. **Build Executables:**

   Run the following command to build all three executables in production mode:

     ```bash
     make all-prod
     ```

9. **Initialize a New Database:**

   To create a new database for your project, run:

     ```bash
     ./bin/init/new-db
     ```

10. **Initialize a New Passkey (USB Key Required):**

   **Important:**

     * You'll need a mounted USB key for this step.
     * Ensure the USB key is securely stored as it will hold your passkey.

   Mount your USB key and then run:

     ```bash
     ./bin/init/new-pass
     ```

   Follow the prompts to enter a password, confirm it, and specify the mounted USB key path within `include/.config.h`. The passkey will be stored securely on the USB key as a SHA512 64-bit cipher.

   **Note:** Remember the password you set for the passkey. You'll need this password to run the main server application.

11. **Run the Server:**

   To start the server application, execute:

     ```bash
     ./bin/server
     ```

12. **Server Usage Guide:**

   For detailed instructions on using the server application after setup, refer to the user guide located in the `/docs/user-guide` directory.

**Additional Notes**

* This guide assumes you have a basic understanding of working with the command line. If you encounter any issues, refer to the project's documentation or seek help from the project's maintainers.
* Ensure proper security measures are taken when managing passkeys and database access.

By following these steps, you should be able to successfully set up and run the server application for your project.

# Secure Network Communication System

This project implements a robust and secure network communication protocol system with extensive features such as two-step authentication, physical authentication using USB flash drives, encryption using libsodium, multithreading, multiplexing, and a dedicated module for error handling and logging.

## Features

- **Secure Communication**: Utilizes asymmetric and symmetric encryption to ensure secure communication over the network.
- **Two-Step Authentication**: Implements a two-step authentication system to enhance security.
- **Physical Authentication**: Offers the option for physical authentication using USB flash drives with SHA-512 encryption.
- **Multithreading**: Utilizes multithreading to handle concurrent connections efficiently.
- **Multiplexing**: Implements multiplexing to handle multiple network connections concurrently.
- **Extensive Documentation**: Provides detailed documentation covering all aspects of the project, including setup, usage, and architecture.
- **Error Handling and Logging**: Incorporates a dedicated module for error handling and logging, ensuring robustness and ease of debugging.
- **Communication protocol**: Incorporates a dedicated module for request definition and handling, ensuring robustness and performant communication.
- **MySQL C API Integration**: Integrates the MySQL C API for database interaction, enabling seamless integration with MySQL databases.
- **Libsodium Encryption**: Utilizes libsodium for encryption, providing strong cryptographic security.
- **Low-Level Network API Interface**: Implements a low-level network API interface for efficient network communication.

## Installation

1. Clone the repository: `git clone https://github.com/anomaly1095/server-project.git`
2. Install dependencies: `cd network-server && chmod 544 install.sh && ./install.sh`
3. Configure the project settings: Modify the configuration file /include/.config.h to fit you needs.
4. Build the project: `make all-prod` | `make help` for more details.

## Usage

1. Start the server: `./bin/final`
2. Follow the authentication process as per the two-step authentication system.
3. Start communicating securely over the network.

## Documentation

- **Setup Guide**: Provides detailed instructions on setting up the project environment.
- **User Guide**: Offers comprehensive documentation on how to use the system effectively.
- **API Reference**: Provides detailed documentation of the project's APIs and interfaces.
- **Overview**: Explains the architecture and design principles of the system.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the [MIT License](LICENSE).

## Credits

- Youssef Azaiez - Project Lead
- Youssef Azaiez - Lead Developer
- Contributors - [Imen ben Ghanem](CONTRIBUTORS.md)

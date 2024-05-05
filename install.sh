#!/bin/bash

#######################works with archlinux and debian#######################

#######################################
# Function to detect package manager
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
detect_package_manager() {
    if [ -x "$(command -v apt-get)" ]; then
        PACKAGE_MANAGER="apt"
    elif [ -x "$(command -v pacman)" ]; then
        PACKAGE_MANAGER="pacman"
    else
        echo "Error: Unsupported package manager. Please install either apt or pacman."
        exit 1
    fi
}

#######################################
# Function to update package manager repositories
# Globals:
#   PACKAGE_MANAGER
# Arguments:
#   None
# Returns:
#   None
#######################################
update_repositories() {
    if [ "$PACKAGE_MANAGER" == "apt" ]; then
        sudo apt-get update
    elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
        sudo pacman -Sy
    fi
    echo "Updated package manager repos"
}

#######################################
# Function to install libsodium
# Globals:
#   PACKAGE_MANAGER
# Arguments:
#   None
# Returns:
#   None
#######################################
install_libsodium() {
    if [ "$PACKAGE_MANAGER" == "apt" ]; then
        sudo apt-get install -y libsodium-dev
    elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
        sudo pacman -S --noconfirm libsodium
    fi
    echo "Installed libsodium needed by the security module"
}

#######################################
# Function to install MySQL or MariaDB
# Globals:
#   PACKAGE_MANAGER
# Arguments:
#   None
# Returns:
#   None
#######################################
install_mysql() {
    if [ "$PACKAGE_MANAGER" == "apt" ]; then
        sudo apt-get install -y libmysqlclient-dev
        sudo apt-get install -y mysql-server
    elif [ "$PACKAGE_MANAGER" == "pacman" ]; then
        sudo pacman -S --noconfirm mariadb
        sudo mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
        sudo systemctl enable --now mariadb.service
    fi
    echo "Installed MySQL/MariaDB server locally"
}

#######################################
# Function to prompt for MySQL installation
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
prompt_mysql_installation() {
    while true; do
        read -p "Do you want to install MySQL/MariaDB server locally? (y/n): " choice
        case "$choice" in
            y|Y ) install_mysql; break ;;
            n|N ) echo "Skipping MySQL/MariaDB server installation"; break ;;
            * ) echo "Invalid input. Please enter 'y' or 'n'." ;;
        esac
    done
}

#######################################
# Main function
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
#######################################
main() {
    detect_package_manager
    update_repositories
    install_libsodium
    prompt_mysql_installation
    echo "Dependencies installed successfully."
    echo "Installation complete."
}

# Run the main function
main

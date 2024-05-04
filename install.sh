#!/bin/bash

# Install libsodium
sudo apt-get update
echo "Updated package manager repos"

sudo apt-get install -y libsodium-dev
echo "Installed libsodium needed by the security module"

# Prompt for MySQL server installation
while true; do
  read -p "Do you want to install MySQL server locally? (y/n): " choice
  case "$choice" in
    y|Y ) sudo apt-get install -y libmysqlclient-dev
          echo "Installed libmysql developer dependencies"
          sudo apt-get install -y mysql-server
          echo "Installed mysql server locally"
          break ;;
    n|N )
          echo "Skipping MySQL server installation"
          break ;;
    * )
          echo "Invalid input. Please enter 'y' or 'n'." ;;
  esac
done

echo "Dependencies installed successfully."
echo "Installation complete."

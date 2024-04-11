#!/bin/bash

# Function to perform port scan using hping3
perform_hping3_scan() {
    read -p "Enter target IP address: " target_ip
    hping3 --scan 1-2048 -S "$target_ip"
}

# Function to perform port scan using nmap
perform_nmap_scan() {
    read -p "Enter target IP address: " target_ip
    nmap -Pn "$target_ip"
}

# Main menu
echo "Choose a port scanning tool:"
echo "1. hping3"
echo "2. nmap"
read -p "Enter your choice (1 or 2): " choice

case $choice in
    1)
        perform_hping3_scan
        ;;
    2)
        perform_nmap_scan
        ;;
    *)
        echo "Invalid choice. Please choose 1 or 2."
        ;;
esac

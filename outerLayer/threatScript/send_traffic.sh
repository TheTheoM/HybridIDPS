#!/bin/bash

send_traffic() {
    if [[ $1 == "1" ]]; then
        send_tcp
    elif [[ $1 == "2" ]]; then
        send_udp
    elif [[ $1 == "3" ]]; then
        send_icmp
    fi
}

send_tcp() {
    read -p "Enter target IP: " target_ip
    read -p "Enter target port: " target_port
    read -p "Enter number of packets to send: " num_packets
    read -p "Enter source IP to spoof (leave blank for default): " source_ip

    # Send TCP packets using hping3
    echo "Sending $num_packets TCP packets to $target_ip:$target_port"
    if [[ -z $source_ip ]]; then
        hping3 -c $num_packets --syn -p $target_port $target_ip
    else
        hping3 -c $num_packets --syn -a $source_ip -p $target_port $target_ip
    fi
}

send_udp() {
    read -p "Enter target IP: " target_ip
    read -p "Enter target port: " target_port
    read -p "Enter number of packets to send: " num_packets
    read -p "Enter source IP to spoof (leave blank for default): " source_ip

    # Send UDP packets using hping3
    echo "Sending $num_packets UDP packets to $target_ip:$target_port"
    if [[ -z $source_ip ]]; then
        hping3 -c $num_packets -2 -p $target_port $target_ip
    else
        hping3 -c $num_packets -2 -a $source_ip -p $target_port $target_ip
    fi
}

send_icmp() {
    read -p "Enter target IP: " target_ip
    read -p "Enter number of packets to send: " num_packets
    read -p "Enter source IP to spoof (leave blank for default): " source_ip

    # Send ICMP packets using hping3
    echo "Sending $num_packets ICMP packets to $target_ip"
    if [[ -z $source_ip ]]; then
        hping3 -c $num_packets --icmp $target_ip
    else
        hping3 -c $num_packets --icmp --spoof $source_ip $target_ip
    fi
}

echo "Select Traffic Type:"
echo "1. TCP"
echo "2. UDP"
echo "3. ICMP"

read -p "Enter your choice (1/2/3): " traffic_type

send_traffic "$traffic_type"

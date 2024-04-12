ip_ranges = {
    "192.168.1.0-42":    "Australia",
    "192.168.1.43-85":   "New Zealand",
    "192.168.1.85-100":  "USA",
    "192.168.1.101-128":  "Minsk",
    "192.168.1.129-171": "Prague",
    "192.168.1.172-214": "Finland",
    "192.168.1.215-235": "North Korea",
    "192.168.1.235-255": "Romania",
}


def subdivide_ip_range(ip_range):
    start_ip, end_ip = ip_range.split('-')

    start_byte = int(start_ip.split('.')[-1])
    end_byte = int(end_ip.split('.')[-1])

    # Calculate the step size based on the range of the last octet
    step = (end_byte - start_byte + 1) // 6

    locations = []
    for i in range(6):
        byte_value = start_byte + i * step
        # Construct the IP address using the last octet
        locations.append("{}.{}.{}.{}".format(start_ip.split('.')[0], start_ip.split('.')[1], start_ip.split('.')[2], byte_value))

    return locations

def find_location(ip):
    try:
        if ip.count(':') == 7:
            ip = ip.replace(':', '')
            ip = ip.upper()
            hex_sum = sum(int(digit, 16) for digit in ip)
            return list(ip_ranges.values())[hex_sum % len(ip_ranges)]    

        ip_int = int(ip.split('.')[-1])

        for ip_range, location in ip_ranges.items():
            start_ip, end_ip = ip_range.split('-')
            start_ip_int = int(start_ip.split('.')[-1])
            end_ip_int = int(end_ip.split('.')[-1])
            if start_ip_int <= ip_int <= end_ip_int:
                return location
            
    except Exception as E:
        print(f"[Warning]: find_location() failed with ip: {ip}")
        
    return 'Unknown Geolocation'


if __name__ == "__main__":
    # print(find_location("192.168.1.2"))
    print(find_location("172.91.2.129"))
    
    # print(find_location("fe80:0000:0000:0000:76da:88ff:fe6b:a560"))
    
    
    #This exists to map private-ip addresses to mock different locations.

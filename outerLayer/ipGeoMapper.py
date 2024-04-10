
ip_ranges = {
    "192.168.1.0-192.168.1.42":    "Australia",
    "192.168.1.43-192.168.1.85":   "New Zealand",
    "192.168.1.86-192.168.1.128":  "Minsk",
    "192.168.1.129-192.168.1.171": "Prague",
    "192.168.1.172-192.168.1.214": "Finland",
    "192.168.1.215-192.168.1.255": "Mars",
}


def subdivide_ip_range(ip_range):
    start_ip, end_ip = ip_range.split('-')

    start_bytes = start_ip.split('.')
    end_bytes = end_ip.split('.')

    start_byte = int(start_bytes[-1])
    end_byte = int(end_bytes[-1])

    step = (end_byte - start_byte + 1) // 6

    locations = []
    for i in range(6):
        byte_value = start_byte + i * step
        locations.append("{}.{}.{}.{}".format(start_bytes[0], start_bytes[1], start_bytes[2], byte_value))

    return locations

def find_location(ip):
    try:
        if ip.count(':') == 7:
            ip = ip.replace(':', '')
            ip = ip.upper()
            hex_sum = sum(int(digit, 16) for digit in ip)
            return list(ip_ranges.values())[hex_sum % len(ip_ranges)]    

        ip_int = int(''.join([f'{int(x):08b}' for x in ip.split('.')]), 2)

        for ip_range, location in ip_ranges.items():
            start_ip, end_ip = ip_range.split('-')
            start_ip_int = int(''.join([f'{int(x):08b}' for x in start_ip.split('.')]), 2)
            end_ip_int = int(''.join([f'{int(x):08b}' for x in end_ip.split('.')]), 2)
            if start_ip_int <= ip_int <= end_ip_int:
                return location
            
    except Exception as E:
        print(f"[Warning]: find_location() failed with ip: {ip}")
        
    return 'Unknown Geolocation'


if __name__ == "__main__":
    print(subdivide_ip_range("192.168.1.0-192.168.1.255"))
    print(find_location("192.168.1.35"))
    
    print(find_location("fe80:0000:0000:0000:76da:88ff:fe6b:a560"))
    
    
    #This exists to map private-ip addresses to mock different locations.

function findLocation(ip) {
  if (ip.includes(':')) {
      // Extract the IPv4 part from the IPv6 address
      const ipv4Part = ip.split(':').pop();
      // Remove the prefix '::ffff:' if present
      const ipv4 = ipv4Part.includes('::ffff:') ? ipv4Part.replace('::ffff:', '') : ipv4Part;
      // Continue with IPv4 logic for the converted address
      ip = ipv4;
  }
  const ip_ranges = {
      "0-42":    "Australia",
      "43-85":   "New Zealand",
      "86-128":  "Minsk",
      "129-171": "Prague",
      "172-214": "Finland",
      "215-255": "Mars",
  };
  const ipInt = parseInt(ip.split('.').pop(), 10);

  for (const [ipRange, location] of Object.entries(ip_ranges)) {
      const [startIp, endIp] = ipRange.split('-');
      const startIpInt = parseInt(startIp.split('.').pop(), 10);
      const endIpInt = parseInt(endIp.split('.').pop(), 10);
      if (startIpInt <= ipInt && ipInt <= endIpInt) {
          return location;
      }
  }
  return "Unknown Location";
}

// Example usage:
console.log(findLocation("172.168.18.129"));  // Example IPv4 address
// console.log(findLocation("fe80:0000:0000:0000:76da:88ff:fe6b:a560"));  // Example IPv6 address

// This function is intended to map private IP addresses to mock different locations.

const ip_ranges = {
  "192.168.1.0-192.168.1.42":    "Australia",
  "192.168.1.43-192.168.1.85":   "New Zealand",
  "192.168.1.86-192.168.1.128":  "Minsk",
  "192.168.1.129-192.168.1.171": "Prague",
  "192.168.1.172-192.168.1.214": "Finland",
  "192.168.1.215-192.168.1.255": "Mars",
};

function subdivideIpRange(ipRange) {
  const [startIp, endIp] = ipRange.split('-');

  const startBytes = startIp.split('.');
  const endBytes = endIp.split('.');

  const startByte = parseInt(startBytes[3]);
  const endByte = parseInt(endBytes[3]);

  const step = Math.floor((endByte - startByte + 1) / 6);

  const locations = [];
  for (let i = 0; i < 6; i++) {
      const byteValue = startByte + i * step;
      locations.push(`${startBytes[0]}.${startBytes[1]}.${startBytes[2]}.${byteValue}`);
  }

  return locations;
}

function findLocation(ip) {
  const ip_ranges = {
    "192.168.1.0-192.168.1.42":    "Australia",
    "192.168.1.43-192.168.1.85":   "New Zealand",
    "192.168.1.86-192.168.1.128":  "Minsk",
    "192.168.1.129-192.168.1.171": "Prague",
    "192.168.1.172-192.168.1.214": "Finland",
    "192.168.1.215-192.168.1.255": "Mars",
  };
  const ipInt = ip.split('.').reduce((acc, val) => (acc << 8) + parseInt(val, 10), 0);

  for (const [ipRange, location] of Object.entries(ip_ranges)) {
      const [startIp, endIp] = ipRange.split('-');
      const startIpInt = startIp.split('.').reduce((acc, val) => (acc << 8) + parseInt(val, 10), 0);
      const endIpInt = endIp.split('.').reduce((acc, val) => (acc << 8) + parseInt(val, 10), 0);
      if (startIpInt <= ipInt && ipInt <= endIpInt) {
          return location;
      }
  }
  return null;
}

console.log(subdivideIpRange("192.168.1.0-192.168.1.255"));
console.log(findLocation("192.168.1.35"));
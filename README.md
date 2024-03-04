# HybridIDPS
In progress HybridIDPS. Do NOT run on production systems. This is a proof of concept.

## Installation of Snort

### 1. Install Npcap https://npcap.com/#download  
- Its called 'Npcap 1.79 installer'. This is a packet-sniffer and driver library.

### 2. Install Snort 2. https://www.snort.org/downloads
- Its under Snort 2, under binaries. File is called Snort_2_9_20_Installer.x64.exe
- This is a open-source intrusion detection and prevention system for network security monitoring.
- This should make a Directory in C:\Snort with a folder bin at C:\Snort\bin.
- CD to C:\Snort\bin and type .\snort  . This should result in alot of text-output, ending
- with 'Commencing packet processing' and potentially some network activity. If it does, snort has been installed correctly. Exit with ctrl-c





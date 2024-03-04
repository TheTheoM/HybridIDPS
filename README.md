# HybridIDPS
In progress HybridIDPS. Do NOT run on production systems. This is a proof of concept.

## Installation of Snort

### 1. Install Npcap https://npcap.com/#download  
- Its called 'Npcap 1.79 installer'. This is a packet-sniffer and driver library.

### 2. Install Snort 2. https://www.snort.org/downloads
- Its under Snort 2, under binaries. File is called Snort_2_9_20_Installer.x64.exe . This is a open-source intrusion detection and prevention system for network security monitoring.
- This should make a Directory in C:\Snort with a folder bin at C:\Snort\bin.
- cd to C:\Snort\bin and type .\snort  . This should result in alot of text-output, ending with 'Commencing packet processing' and potentially some network activity. If it does, snort has been installed correctly. Exit with ctrl-c.
- If it fails, reinstall npcap with compatability mode in the installer, and reinstall snort. 

### 3. Fix the broken Snort config file and create missing files. 
  - This will go over alot of the same as this youtube, but I will shorten it to steps. https://www.youtube.com/watch?v=naLbhKW62nY
#### 3.1 Download the rules folder and snort.conf from this github.
  - Replace the rules folder at C:\Snort\rules with the downloaded folder. If the rules-folder doesn't exist, paste it in anyway.
  - Replace the snort.conf at C:\Snort\etc\snort.conf with the downloaded file. 

#### 3.2 Check if the alert.ids file exists
- Check if the alert.ids file exists in C:\Snort\log\alert.ids. If it doesn't exist, or the log-folder itself doesn't exist. Create both, with the alert.ids file *must* be empty with no whitespace with no whitespace.

## With snort installed and fixed, download and run the snortRunner.py
- This file will:
    * Check if critical files and directories exist for Snort. 'checkDirectories()'
    * Display network interfaces. You must select your interface. This is explained below. 'list_interfaces()'
    * Display the Snort Rules in the local.rules file. You will edit the file to add/remove/modify files to Snort. 'displayRules()'
    * Run snort itself with the correct command which output its alerts to alerts.id. 'runSnort()' This will be ran as admin. So you will need to input your password into the cmd window that pops up. Your password is not stored or touched by the code at all, it is entered directly into windows cmd.
    * Will monitor the changes to alerts.id 'check_file_changes()', and print the alerts sorted by source ip. 
- To make this program work, you must select the correct interface, to do so:
  * Run the program, it may crash, but in the output you will see a list of interfaces under 'Interfaces:', find your correct one. Incorrect ones may be named VM-ware adapters or Loopback.
  * Say your interface is called 'Asus(R) Ethernet Controller (3) I612-FA23', you will extract a suitable substring such as 'Ethernet Controller' and write it into the code like this:
      - Change:
         * interface_Number = list_interfaces(find_Interface_subString = None)
      - To:
         * interface_Number = list_interfaces(find_Interface_subString = 'Ethernet Controller')
* This step is necessary as your interface number *will* change over time, so this way the computer will select the correct one. 
  

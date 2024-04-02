# HybridIDPS
In progress HybridIDPS. Do NOT run on production systems. This is a proof of concept.

# InnerLayer

## 1. Install Node.js: https://nodejs.org/en
- Download Node.js (LTS), and follow the instructions to install. 
- This allows you to run the javascript files.

## 2. Download/ Clone Github Repo
- Navigate to the green button labeled "Code" on the GitHub repository.
- Download the ZIP file containing the repository.
- Move the downloaded ZIP file to your designated folder and extract its contents.
- Open the "HybridIDPS-main" folder in VSCode for easier navigation and access to project files.

## 3. Install needed Packages for instaKilo.js and React
- Check to see if node is properly installed, ```node```.
- Navigate to the "userinterface" folder within the project directory and create a new file named ".env".
- Inside the ".env" file, copy and paste the following line, replacing "your_ip" with your actual IPV4 address:
    * ```REACT_APP_WEBSOCKET_SERVER_IP=your_ip:8100```
- After creating the ".env" file, right-click on the "innerLayer" folder in VSCode and open the integrated terminal.
- Navigate to the terminal section and open PowerShell (basically a linux terminal).
- ```cd innerLayer```
- ```npm install .``` this installs the necessary packages for the inner layer.
     * This may come up with warnings just ignore those.
- ```cd userinterface```
- ```npm install .``` this installs the necessary packages for the user interface.
   * This may come up with warnings just ignore those.

## 4. Run instaKilo.js and React Interface
- ```cd innerLayer```, run the javascript file ```node instaKilo.js```.
- Confirm that the message "WebSocket server is running on port 8100" appears. Ignore the message about being unable to connect to the MySQL database for now.
- ```cd userinterface```, run the command ```npm start```.
- If all set, the web app window will open in your default browser shortly.
- In VSCode, open "innerLayer.py" and run it. If it errors out, install MySQL Connector Python by ```pip install mysql-connector-python``` in terminal.

## 5. Install MySQL: https://dev.mysql.com/downloads/installer/ 
- Download the “Windows (x86, 32-bit), MSI Installer” with the larger file size.
- Then run the installer (The key ones are noted below, just next other ones and execute them):
   * Setup type: Full
   * Development Computer
   * MySQL Root password (don’t lose it): whatever you want (admin)
   * Add user (this is obtain through the innerLayer.py): 
      - Username - Hybrid_IDPS
      - Password - css2
   * Connect to server: 
      - Username - root
      - Password - what you set it (admin)
## 6. Import the SQL scripts to make a database
- Open MySQL Workbench and connect to the local instance using root as username and admin as password, then click "Remember Login".
- Navigate to the "File" tab and select "Open SQL Script".
- Locate the "HybridIDPS-main\outerLayer\sqlScripts" folder and open the desired scripts individually.

## 7. Run the project
- Terminate all running programs to ensure a clean restart.
- Execute the "getInnerLayer" and "wipes_and_Creates_Database_and_Tables" script in MySQL by clicking the lightning bolt icon.
- ```cd innerLayer``` and run ```node instaKilo.js```.
- ```cd userinterface``` and run ```npm start```.
- Run the "innerLayer.py".
- The "wipes_and_Creates_Database_and_Tables" is used to clear the tables.
- With these steps completed, you're now set up to test the project, including the web application and threat levels functionality.

# OuterLayer

## Installation of Snort

### 1. Install Npcap https://npcap.com/#download  
- Its called 'Npcap 1.79 installer'. This is a packet-sniffer and driver library.

### 2. Install Snort 2. https://www.snort.org/downloads
- Its under Snort 2, under binaries. File is called Snort_2_9_20_Installer.x64.exe . This is a open-source intrusion detection and prevention system for network security monitoring.
- This should make a Directory in C:\Snort with a folder bin at C:\Snort\bin.
- cd to C:\Snort\bin and type .\snort  . This should result in alot of text-output, ending with 'Commencing packet processing' and potentially some network activity. If it does, snort has been installed correctly. Exit with ctrl-c.
- If it fails, reinstall npcap with compatability mode in the installer, and reinstall snort. 

### 3. Fix the broken Snort config file and create missing files. 
  - This will go over alot of the same as this youtube, but I will shorten it to steps shown below to save you time. https://www.youtube.com/watch?v=naLbhKW62nY
#### 3.1 Download the rules folder and snort.conf from this github.
  - Replace the rules folder at C:\Snort\rules with the downloaded folder. If the rules-folder doesn't exist, paste it in anyway.
  - Replace the snort.conf at C:\Snort\etc\snort.conf with the downloaded file. 

#### 3.2 Check if the alert.ids file exists
- Check if the alert.ids file exists in C:\Snort\log\alert.ids. If it doesn't exist, or the log-folder itself doesn't exist. Create both, with the alert.ids file *must* be empty with no whitespace with no whitespace.

## With snort installed and fixed, download and run the snortRunner.py
### This file will
  - Check if critical files and directories exist for Snort. 'checkDirectories()'
  - Display network interfaces. You must select your interface. This is explained below. 'list_interfaces()'
  - Display the Snort Rules in the local.rules file. You will edit the file to add/remove/modify files to Snort. 'displayRules()'
  - Run snort itself with the correct command which output its alerts to alerts.id. 'runSnort()' This will be ran as admin. So you will need to input your password into the cmd window that pops up. Your password is not stored or touched by the code at all, it is entered directly into windows cmd.
  - Will monitor the changes to alerts.id 'check_file_changes()', and print the alerts sorted by source ip. 
    
### To make this program work, you must select the correct interface, to do so:
  - Run the program, it may crash, but in the output you will see a list of interfaces under 'Interfaces:', find your correct one. Incorrect ones may be named VM-ware adapters or Loopback.
  - Say your interface is called 'Asus(R) Ethernet Controller (3) I612-FA23', you will extract a suitable substring such as 'Ethernet Controller' and write it into the code like this:
      * Change: Approximately line 231
         - interface_Number = list_interfaces(find_Interface_subString = None)
      * To:
         - interface_Number = list_interfaces(find_Interface_subString = 'Ethernet Controller')
- This step is necessary as your interface number *will* change over time, so this way the computer will select the correct one. 
  

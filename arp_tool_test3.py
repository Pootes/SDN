# Description: Detect ARP poisoning in a captured packet trace.
import time
import subprocess
from scapy.all import rdpcap
from collections import defaultdict
from scapy.layers.l2 import ARP


def detect_arp_poisoning(pcap_file):
    """
    Detect ARP poisoning by analyzing repeated ARP replies and conflicting mappings.
    Provide detailed information about detected attacks.
    """
    print(f"Analyzing {pcap_file} for ARP poisoning...\n")

    packets = rdpcap(pcap_file)  # Load the PCAP file
    ip_to_mac = defaultdict(set)  # Map of IP to MAC addresses
    mac_to_ip = defaultdict(set)  # Map of MAC to IP addresses
    arp_reply_count = defaultdict(int)  # Count ARP replies per MAC
    arp_reply_details = defaultdict(list)  # Details of ARP replies per MAC
    suspicious_arp_packets = []  # List of suspicious ARP packets for reporting

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply (is-at)
            ip_src = packet[ARP].psrc
            mac_src = packet[ARP].hwsrc
            timestamp = packet.time

            # Update mappings
            ip_to_mac[ip_src].add(mac_src)
            mac_to_ip[mac_src].add(ip_src)
            arp_reply_count[mac_src] += 1
            arp_reply_details[mac_src].append({
                "ip_src": ip_src,
                "mac_src": mac_src,
                "timestamp": timestamp,
                "target_ip": packet[ARP].pdst,
                "target_mac": packet[ARP].hwdst
            })

            # Track packets with conflicting mappings
            if len(ip_to_mac[ip_src]) > 1 or len(mac_to_ip[mac_src]) > 1:
                suspicious_arp_packets.append({
                    "timestamp": timestamp,
                    "source_ip": ip_src,
                    "source_mac": mac_src,
                    "target_ip": packet[ARP].pdst,
                    "target_mac": packet[ARP].hwdst,
                })

    # Detect and report conflicts
    conflicts_found = False
    for ip, macs in ip_to_mac.items():
        if len(macs) > 1:  # Multiple MACs for the same IP
            if not conflicts_found:
                print("[!] Conflicting ARP Mappings Detected:\n")
                conflicts_found = True
            print(f"  [!] IP {ip} resolves to conflicting MACs: {', '.join(macs)}")

    for mac, ips in mac_to_ip.items():
        if len(ips) > 1:  # Multiple IPs for the same MAC
            if not conflicts_found:
                print("[!] Conflicting ARP Mappings Detected:\n")
                conflicts_found = True
            print(f"  [!] MAC {mac} resolves to conflicting IPs: {', '.join(ips)}")

    if conflicts_found:
        print()

    # Report high ARP traffic rates
    high_traffic_found = False
    for mac, count in arp_reply_count.items():
        if count > 5:  # Threshold for high traffic
            if not high_traffic_found:
                print("[!] High ARP Reply Rates Detected:\n")
                high_traffic_found = True
            print(f"  [!] MAC {mac} sent {count} ARP replies.")
            print("  Details of ARP replies:")
            for reply in arp_reply_details[mac]:
                print(f"    - [Time: {reply['timestamp']}] "
                      f"Source: {reply['ip_src']} ({reply['mac_src']}) -> "
                      f"Target: {reply['target_ip']} ({reply['target_mac']})")
            print()

    if high_traffic_found:
        print()

    # Report suspicious ARP packets
    if suspicious_arp_packets:
        print("[!] Suspicious ARP Packets:\n")
        for arp_packet in suspicious_arp_packets:
            print(f"  [Timestamp: {arp_packet['timestamp']}] "
                  f"Source: {arp_packet['source_ip']} ({arp_packet['source_mac']}) -> "
                  f"Target: {arp_packet['target_ip']} ({arp_packet['target_mac']})")
        print()

    # If no issues were detected
    if not (conflicts_found or high_traffic_found or suspicious_arp_packets):
        print("No suspicious ARP activity detected.\n")

    print("Analysis complete.")

def main():
    target_ip = "192.168.1.3"  # Target IP address
    spoof_ip = "192.168.1.1"   # IP to spoof (typically the gateway)
    target_mac = "00:11:22:33:44:55"  # Target MAC address (you should get it from the target device)
    iface = "h1-eth0"  # Network interface (change as needed)
    capture_iface = "any"  # Interface to capture packets from (switch port)
    attack_duration = 10  # Duration of the attack and capture in seconds
    
    # Start ARP poisoning in a separate thread/process
    poison_process = subprocess.Popen(
        ['python3', 'scapy_arp_poison.py', target_ip, spoof_ip, target_mac, iface]
    )
    
    # Start packet capture using tshark
    capture_process = subprocess.Popen(
        ['sudo', 'tshark', '-i', capture_iface, '-a', f'duration:{attack_duration}', '-w', '/tmp/arp_pcap.pcap']
    )
    
    # Wait for the ARP poisoning and capture to finish
    time.sleep(attack_duration)
    
    # Terminate both processes after the specified duration
    poison_process.terminate()
    capture_process.terminate()

    print("[+] ARP poisoning and packet capture completed.\n")

    # Detect ARP poisoning in captured packets
    detect_arp_poisoning('/tmp/arp_pcap.pcap')

if __name__ == "__main__":
    main()

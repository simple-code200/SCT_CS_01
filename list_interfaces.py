from scapy.all import get_if_list

def list_interfaces():
    """List available network interfaces for scapy"""
    interfaces = get_if_list()
    print("Available network interfaces (use these names in scapy):")
    for iface in interfaces:
        print(f"- {iface}")

if __name__ == "__main__":
    list_interfaces()

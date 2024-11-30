from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def process_packet(packet):
    """Process and display information about a captured packet."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        protocol_name = {
            1: "ICMP",
            6: "TCP",
            17: "UDP"
        }.get(protocol, "Other")

        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol_name}")

        # Check for payload
        if TCP in packet or UDP in packet:
            payload = bytes(packet[TCP].payload if TCP in packet else packet[UDP].payload).decode('utf-8', errors='ignore')
            print(f"Payload: {payload}")
        print("-" * 50)

def main():
    """Main function to start sniffing packets."""
    try:
        print("Starting packet sniffer...")
        print("Press Ctrl+C to stop.")
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
        sys.exit()

if __name__ == "__main__":
    main()

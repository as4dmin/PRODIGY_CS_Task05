
# Packet Sniffer Tool

A lightweight Python-based packet sniffer that captures and analyzes live network traffic. This tool extracts key information such as source and destination IP addresses, protocols, and payload data.

## Features
- **Packet Capture**: Intercepts live network traffic.
- **Protocol Analysis**: Identifies protocols (TCP, UDP, ICMP).
- **Payload Inspection**: Displays packet payload for deeper inspection.
- **Simple & Extendable**: Easy to customize and extend for specific use cases.

## Requirements
- Python 3.x
- `scapy` library

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/as4dmin/packet-sniffer.git
   cd packet-sniffer
   ```
2. Install the required library:
   ```bash
   pip install scapy
   ```

## Usage
1. Run the script with administrator/root privileges:
   ```bash
   sudo python packet_sniffer.py
   ```
2. Press `Ctrl+C` to stop capturing packets.

### Example Output
```plaintext
Starting packet sniffer...
Press Ctrl+C to stop.
Source: 192.168.1.2 -> Destination: 192.168.1.3 | Protocol: TCP
Payload: GET /index.html HTTP/1.1
--------------------------------------------------
Source: 10.0.0.5 -> Destination: 8.8.8.8 | Protocol: ICMP
Payload: 
--------------------------------------------------
```

## How It Works
- **Packet Interception**: Uses the `sniff()` function from the `scapy` library to capture live packets.
- **Protocol Identification**: Recognizes TCP, UDP, ICMP, and other protocols.
- **Payload Analysis**: Extracts and prints payloads for TCP and UDP packets.

## Customization
Modify the `process_packet` function in the script to:
- Filter specific types of traffic (e.g., HTTP, DNS).
- Save packets to a file (e.g., in PCAP format for Wireshark analysis).
- Integrate with visualization or alerting systems.

## Legal Disclaimer
This tool is intended for **educational purposes only**. Use it responsibly and only on networks you own or have explicit permission to analyze. Unauthorized use on networks you do not own is illegal and unethical.

## Contributions
Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


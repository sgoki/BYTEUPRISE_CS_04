from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = None

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        
        print(f"\n[+] New Packet: {protocol}")
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Payload: {bytes(packet.payload)}")

def main():
    # Start sniffing (requires root/admin privileges)
    print("Starting packet sniffing...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

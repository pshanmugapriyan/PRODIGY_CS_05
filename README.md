
from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")

        if proto == 6 and TCP in packet:  # TCP protocol
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"Protocol: TCP, Source Port: {tcp_sport}, Destination Port: {tcp_dport}")
            if packet[TCP].payload:
                print(f"Payload: {packet[TCP].payload}")

        elif proto == 17 and UDP in packet:  # UDP protocol
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            print(f"Protocol: UDP, Source Port: {udp_sport}, Destination Port: {udp_dport}")
            if packet[UDP].payload:
                print(f"Payload: {packet[UDP].payload}")

        print("-" * 40)

# Start sniffing packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, count=10)  # Capture 10 packets
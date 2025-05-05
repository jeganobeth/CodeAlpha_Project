# CodeAlpha_Project
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to process each captured packet
def process_packet(packet):
    print("\n=== Packet Captured ===")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"From: {ip_layer.src} --> To: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")
    
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Segment | Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Segment | Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        
        elif ICMP in packet:
            print("ICMP Packet")
    else:
        print("Non-IP Packet")

#

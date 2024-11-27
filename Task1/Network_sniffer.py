from scapy.all import sniff, Ether, IP, TCP, UDP

def analyze_packet(packet):

    
    """The network sniffer is working ..."""
    
    print("\n" + "="*60)
    print(f"Packet Captured: {packet.summary()}")
    
    # Ethernet Layer
    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        print("Ethernet Layer:")
        print(f"  Source MAC: {ether_layer.src}")
        print(f"  Destination MAC: {ether_layer.dst}")
        print(f"  EtherType: {hex(ether_layer.type)}")
    
    # IP Layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("\nIP Layer:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Version: {ip_layer.version}")
        print(f"  Header Length: {ip_layer.ihl * 4} bytes")
        print(f"  Total Length: {ip_layer.len} bytes")
        print(f"  TTL: {ip_layer.ttl}")
        print(f"  Protocol: {ip_layer.proto}")
    
    # TCP Layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("\nTCP Layer:")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print(f"  Sequence Number: {tcp_layer.seq}")
        print(f"  Acknowledgment Number: {tcp_layer.ack}")
        print(f"  Flags: {tcp_layer.flags}")
        print(f"  Window Size: {tcp_layer.window}")
    
    # UDP Layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("\nUDP Layer:")
        print(f"  Source Port: {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")
        print(f"  Length: {udp_layer.len}")

def start_sniffer(interface=None, packet_count=10):

    print("\n"+f"Starting sniffer on {interface or 'default interface'}...")
    sniff(iface=interface, prn=analyze_packet, count=packet_count, store=False, filter="ip")

if __name__ == "__main__":
    interface_name = None 
    packet_limit = 1  
    start_sniffer(interface=interface_name, packet_count=packet_limit)

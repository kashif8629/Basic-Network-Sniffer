from scapy.all import sniff

def packet_callback(packet):
    # Print the summary of the packet
    print(packet.summary())
    
    # If the packet has IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

    # If the packet has TCP layer
    if packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        print(f"Source Port: {tcp_layer.sport}")
        print(f"Destination Port: {tcp_layer.dport}")
        
    print("\n")  # Add a newline for readability

# Start sniffing the network
print("Starting the network sniffer...")
sniff(prn=packet_callback, store=0)

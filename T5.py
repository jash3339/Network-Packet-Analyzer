from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            protocol_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            protocol_name = "Other"
            sport = None
            dport = None

        print(f"IP src: {ip_src} | IP dst: {ip_dst} | Protocol: {protocol_name}", end='')
        if sport and dport:
            print(f" | Src port: {sport} | Dst port: {dport}")
        else:
            print()
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")

# Capture packets
sniff(prn=packet_callback, store=0)
import scapy.all as scapy

class ArpGuard:
    def __init__(self):
        self.known_macs = {}

    def monitor(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            if ip in self.known_macs and self.known_macs[ip] != mac:
                print(f"[ALERT] ARP spoofing detected: {ip} changed from {self.known_macs[ip]} to {mac}")
            self.known_macs[ip] = mac

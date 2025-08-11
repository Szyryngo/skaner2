import scapy.all as scapy

class LanScanner:
    def __init__(self, ip_range="192.168.1.0/24"):
        self.ip_range = ip_range

    def scan(self):
        arp_request = scapy.ARP(pdst=self.ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        return [{"ip": pkt[1].psrc, "mac": pkt[1].hwsrc} for pkt in answered]

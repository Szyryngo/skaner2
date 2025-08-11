import scapy.all as scapy

class Sniffer:
    def __init__(self, iface="eth0"):
        self.iface = iface

    def start(self, packet_callback):
        scapy.sniff(iface=self.iface, store=False, prn=packet_callback)

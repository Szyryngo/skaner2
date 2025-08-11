from scapy.utils import wrpcap

class PacketStorage:
    def __init__(self, path="data/capture.pcap"):
        self.path = path
        self.packets = []

    def add(self, packet):
        self.packets.append(packet)

    def save(self):
        wrpcap(self.path, self.packets)

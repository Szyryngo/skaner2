from scapy.all import sniff, wrpcap
from datetime import datetime

class PacketSniffer:
    def __init__(self, iface):
        self.iface = iface
        self.packets = []
        self.index = 0
        self.running = False

    def start(self, callback):
        self.running = True
        sniff(iface=self.iface, prn=lambda pkt: self._handle(pkt, callback), store=False)

    def _handle(self, packet, callback):
        self.index += 1
        self.packets.insert(0, (self.index, packet))  # najnowszy na górze
        callback(self.index, packet)

    def stop(self):
        self.running = False

    def save_to_pcap(self, filename=None):
        if not filename:
            filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(filename, [pkt for _, pkt in self.packets])
        return filename

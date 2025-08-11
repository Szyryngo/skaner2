from scapy.all import sniff
from core.ai import ThreatDetector
from PyQt5.QtCore import pyqtSignal, QObject

class PacketSignal(QObject):
    packet_received = pyqtSignal(object, str)

class Sniffer:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.detector = ThreatDetector()
        self.signal = PacketSignal()

    def start(self):
        self.running = True
        sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=self.should_stop)

    def stop(self):
        self.running = False

    def should_stop(self, packet):
        return not self.running

    def process_packet(self, packet):
        classification = self.detector.classify(packet)
        self.signal.packet_received.emit(packet, classification)

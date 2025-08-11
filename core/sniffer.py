from PyQt5.QtCore import QObject, pyqtSignal
from scapy.all import sniff
from threading import Thread

class Sniffer(QObject):
    packet_received = pyqtSignal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = False
        self.thread = None

    def start(self):
        if not self.running:
            self.running = True
            self.thread = Thread(target=self._sniff)
            self.thread.start()

    def stop(self):
        self.running = False

    def _sniff(self):
        sniff(iface=self.iface, prn=self._handle_packet, store=False)

    def _handle_packet(self, packet):
        if self.running:
            self.packet_received.emit(packet)

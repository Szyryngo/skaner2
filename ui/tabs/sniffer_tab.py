from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit
import threading

class SnifferTab(QWidget):
    def __init__(self, sniffer, arp_guard, anomaly_detector):
        super().__init__()
        self.sniffer = sniffer
        self.arp_guard = arp_guard
        self.anomaly_detector = anomaly_detector

        self.layout = QVBoxLayout()
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.start_btn = QPushButton("Start Sniffer")
        self.start_btn.clicked.connect(self.start_sniffing)

        self.layout.addWidget(self.start_btn)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def start_sniffing(self):
        thread = threading.Thread(target=self.sniffer.start, args=(self.packet_callback,))
        thread.daemon = True
        thread.start()

    def packet_callback(self, packet):
        self.arp_guard.monitor(packet)
        self.anomaly_detector.analyze(packet)
        self.output.append(packet.summary())

import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox, QLabel,
    QHBoxLayout, QCheckBox, QListWidget
)
from PyQt5.QtCore import Qt
from scapy.all import get_if_list
from core.sniffer import Sniffer
from core.ai import ThreatDetector
from core.firewall import FirewallManager

class ActiveSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Sniffer — Tryb aktywny")
        self.setGeometry(100, 100, 900, 700)

        self.detector = ThreatDetector()
        self.firewall = FirewallManager()
        self.sniffer = None
        self.active_mode = False

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Interfejs + przyciski
        top_layout = QHBoxLayout()
        self.interface_box = QComboBox()
        self.interface_box.addItems(get_if_list())
        top_layout.addWidget(self.interface_box)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_sniffing)
        top_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_sniffing)
        top_layout.addWidget(self.stop_button)

        self.active_checkbox = QCheckBox("Tryb aktywny (blokuj IP)")
        self.active_checkbox.stateChanged.connect(self.toggle_active_mode)
        top_layout.addWidget(self.active_checkbox)

        layout.addLayout(top_layout)

        # Tabela pakietów
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Classification"])
        layout.addWidget(self.packet_table)

        # Podgląd pakietu
        self.packet_view = QTextEdit()
        self.packet_view.setReadOnly(True)
        layout.addWidget(self.packet_view)

        # Lista zablokowanych IP
        self.blocked_label = QLabel("Zablokowane IP:")
        layout.addWidget(self.blocked_label)

        self.blocked_list = QListWidget()
        layout.addWidget(self.blocked_list)

        self.setLayout(layout)

    def start_sniffing(self):
        interface = self.interface_box.currentText()
        self.sniffer = Sniffer(interface)
        self.sniffer.signal.packet_received.connect(self.handle_packet)
        self.sniffer.start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()

    def toggle_active_mode(self, state):
        self.active_mode = state == Qt.Checked

    def handle_packet(self, packet, classification):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        time_item = QTableWidgetItem(str(packet.time))
        src_item = QTableWidgetItem(packet.src if hasattr(packet, "src") else "N/A")
        dst_item = QTableWidgetItem(packet.dst if hasattr(packet, "dst") else "N/A")
        class_item = QTableWidgetItem(classification)

        color = self.detector.get_color(classification)
        for item in [time_item, src_item, dst_item, class_item]:
            item.setBackground(Qt.GlobalColor.__dict__.get(color.capitalize(), Qt.white))

        self.packet_table.setItem(row, 0, time_item)
        self.packet_table.setItem(row, 1, src_item)
        self.packet_table.setItem(row, 2, dst_item)
        self.packet_table.setItem(row, 3, class_item)

        if self.detector.should_alert(classification):
            QMessageBox.warning(self, "Zagrożenie wykryte", f"Wykryto: {classification}")

        if self.active_mode and classification in ["malware", "flood", "scan"]:
            ip = packet.src if hasattr(packet, "src") else None
            if ip:
                self.firewall.block_ip(ip)
                self.blocked_list.addItem(ip)

        # Podgląd pakietu
        hex_data = bytes(packet).hex()
        ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes(packet))
        self.packet_view.setPlainText(f"HEX:\n{hex_data}\n\nASCII:\n{ascii_data}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ActiveSnifferGUI()
    window.show()
    sys.exit(app.exec_())

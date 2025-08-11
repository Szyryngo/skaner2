import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt
from scapy.all import get_windows_if_list
from network_guard.core.sniffer import Sniffer
from network_guard.core.ai import ThreatDetector

class PacketSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Guard")
        self.setGeometry(100, 100, 800, 600)

        self.detector = ThreatDetector()
        self.sniffer = None
        self.interface_map = {}

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.interface_box = QComboBox()
        self.load_interfaces()
        layout.addWidget(self.interface_box)

        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Classification"])
        self.packet_table.cellClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table)

        self.packet_view = QTextEdit()
        self.packet_view.setReadOnly(True)
        layout.addWidget(self.packet_view)

        self.setLayout(layout)

    def load_interfaces(self):
        interfaces = get_windows_if_list()
        for iface in interfaces:
            npf_name = iface['name']
            user_name = iface['description']
            self.interface_map[user_name] = npf_name
            self.interface_box.addItem(user_name)

    def start_sniffing(self):
        user_selected = self.interface_box.currentText()
        npf_name = self.interface_map.get(user_selected)
        if npf_name:
            self.sniffer = Sniffer(npf_name)
            self.sniffer.signal.packet_received.connect(self.handle_packet)
            self.sniffer.start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()

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

    def show_packet_details(self, row, column):
        packet = self.sniffer.signal.packet_received.receivers()[0][0].__self__.last_packet
        hex_data = bytes(packet).hex()
        ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes(packet))
        self.packet_view.setPlainText(f"HEX:\n{hex_data}\n\nASCII:\n{ascii_data}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec_())

import sys
import wmi
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt
from scapy.all import get_if_list
from core.sniffer import Sniffer
from core.ai import ThreatDetector

class MainWindow(QWidget):
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

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Classification"])
        layout.addWidget(self.packet_table)

        self.packet_view = QTextEdit()
        self.packet_view.setReadOnly(True)
        layout.addWidget(self.packet_view)

        self.setLayout(layout)

    def load_interfaces(self):
        scapy_ifaces = get_if_list()
        w = wmi.WMI()
        guid_map = {}

        for nic in w.Win32_NetworkAdapter():
            guid = nic.GUID
            name = nic.NetConnectionID or nic.Name
            if guid and name:
                npf_name = f"NPF_{{{guid}}}"
                guid_map[npf_name] = name

        for iface in scapy_ifaces:
            label = guid_map.get(iface, iface)
            self.interface_map[label] = iface
            self.interface_box.addItem(label)

    def start_sniffing(self):
        selected_label = self.interface_box.currentText()
        iface = self.interface_map.get(selected_label)
        if iface:
            self.sniffer = Sniffer(iface)
            self.sniffer.packet_received.connect(self.handle_packet)
            self.sniffer.start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()

    def handle_packet(self, packet):
        classification = self.detector.classify(packet)

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        time_item = QTableWidgetItem(str(packet.time))
        src_item = QTableWidgetItem(getattr(packet, "src", "N/A"))
        dst_item = QTableWidgetItem(getattr(packet, "dst", "N/A"))
        class_item = QTableWidgetItem(classification)

        color = self.detector.get_color(classification)
        for item in [time_item, src_item, dst_item, class_item]:
            item.setBackground(Qt.GlobalColor.__dict__.get(color.capitalize(), Qt.white))

        self.packet_table.setItem(row, 0, time_item)
        self.packet_table.setItem(row, 1, src_item)
        self.packet_table.setItem(row, 2, dst_item)
        self.packet_table.setItem(row, 3, class_item)

        hex_data = bytes(packet).hex()
        ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes(packet))
        self.packet_view.setPlainText(f"HEX:\n{hex_data}\n\nASCII:\n{ascii_data}")

        if self.detector.should_alert(classification):
            QMessageBox.warning(self, "Zagrożenie wykryte", f"Wykryto: {classification}")

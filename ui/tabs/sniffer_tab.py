from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QTextEdit, QHeaderView
)
from core.packet_sniffer import sniff_packets

class SnifferTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.packet_table = QTableWidget(0, 6)
        self.packet_table.setHorizontalHeaderLabels(["Index", "Czas", "Źródło", "Cel", "Protokół", "Rozmiar"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.cellClicked.connect(self.show_packet_details)
        layout.addWidget(self.packet_table)

        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        layout.addWidget(QLabel("HEX / ASCII:"))
        layout.addWidget(self.hex_view)

        self.setLayout(layout)
        self.load_packets()

    def load_packets(self):
        packets = sniff_packets(limit=50)
        for i, pkt in enumerate(packets):
            self.packet_table.insertRow(i)
            self.packet_table.setItem(i, 0, QTableWidgetItem(str(i)))
            self.packet_table.setItem(i, 1, QTableWidgetItem(str(pkt.time)))
            self.packet_table.setItem(i, 2, QTableWidgetItem(pkt.src))
            self.packet_table.setItem(i, 3, QTableWidgetItem(pkt.dst))
            self.packet_table.setItem(i, 4, QTableWidgetItem(pkt.proto))
            self.packet_table.setItem(i, 5, QTableWidgetItem(str(len(pkt))))

    def show_packet_details(self, row, _):
        pkt = sniff_packets(limit=50)[row]
        raw = bytes(pkt)
        hex_str = ' '.join(f"{b:02x}" for b in raw)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw)
        self.hex_view.setText(f"HEX:\n{hex_str}\n\nASCII:\n{ascii_str}")

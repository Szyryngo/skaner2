import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox, QLabel,
    QHBoxLayout
)
from PyQt5.QtCore import Qt
from scapy.all import get_if_list
from core.sniffer import Sniffer
from core.ai import ThreatDetector
from core.stats import ThreatStats
from core.logger import EventLogger
from core.exporter import StatsExporter

class LoggingSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Sniffer — Statystyki i logi")
        self.setGeometry(100, 100, 900, 700)

        self.detector = ThreatDetector()
        self.stats = ThreatStats()
        self.logger = EventLogger()
        self.exporter = StatsExporter()
        self.sniffer = None

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

        self.export_button = QPushButton("Eksportuj statystyki")
        self.export_button.clicked.connect(self.export_stats)
        top_layout.addWidget(self.export_button)

        layout.addLayout(top_layout)

        # Statystyki
        self.stats_label = QLabel("Statystyki: brak")
        layout.addWidget(self.stats_label)

        # Tabela pakietów
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Classification"])
        layout.addWidget(self.packet_table)

        # Podgląd pakietu
        self.packet_view = QTextEdit()
        self.packet_view.setReadOnly(True)
        layout.addWidget(self.packet_view)

        self.setLayout(layout)

    def start_sniffing(self):
        interface = self.interface_box.currentText()
        self.sniffer = Sniffer(interface)
        self.sniffer.signal.packet_received.connect(self.handle_packet)
        self.sniffer.start()
        self.logger.log_event(f"Sniffer uruchomiony na interfejsie: {interface}")

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.logger.log_event("Sniffer zatrzymany")

    def export_stats(self):
        stats = self.stats.get_stats()
        self.exporter.export(stats)
        QMessageBox.information(self, "Eksport", "Statystyki zapisane do stats.csv")
        self.logger.log_event("Statystyki wyeksportowane")

    def handle_packet(self, packet, classification):
        self.stats.update(classification)
        self.update_stats_label()

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
            self.logger.log_event(f"ALERT: {classification} od {packet.src if hasattr(packet, 'src') else 'N/A'}")

        # Podgląd pakietu
        hex_data = bytes(packet).hex()
        ascii_data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes(packet))
        self.packet_view.setPlainText(f"HEX:\n{hex_data}\n\nASCII:\n{ascii_data}")

    def update_stats_label(self):
        stats = self.stats.get_stats()
        text = "Statystyki: " + ", ".join(f"{k}: {v}" for k, v in stats.items())
        self.stats_label.setText(text)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoggingSnifferGUI()
    window.show()
    sys.exit(app.exec_())

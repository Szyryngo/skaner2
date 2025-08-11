import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QLabel, QMessageBox
)
from PyQt5.QtCore import Qt
from scapy.all import get_if_list
from core.sniffer import Sniffer
from core.ai import ThreatDetector
from core.training import TrainingManager

class TrainingGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Trenowanie modelu AI")
        self.setGeometry(100, 100, 800, 600)

        self.detector = ThreatDetector()
        self.trainer = TrainingManager()
        self.sniffer = None
        self.packets = []

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        self.interface_box = QComboBox()
        self.interface_box.addItems(get_if_list())
        layout.addWidget(self.interface_box)

        self.start_button = QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        layout.addWidget(self.stop_button)

        self.train_button = QPushButton("Trenuj model")
        self.train_button.clicked.connect(self.train_model)
        layout.addWidget(self.train_button)

        self.status_label = QLabel("Zebranych próbek: 0")
        layout.addWidget(self.status_label)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Length", "Label"])
        layout.addWidget(self.packet_table)

        self.label_box = QComboBox()
        self.label_box.addItems(["normal", "scan", "malware", "flood"])
        layout.addWidget(self.label_box)

        self.setLayout(layout)

    def start_sniffing(self):
        interface = self.interface_box.currentText()
        self.sniffer = Sniffer(interface)
        self.sniffer.signal.packet_received.connect(self.handle_packet)
        self.sniffer.start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()

    def handle_packet(self, packet, classification):
        self.packets.append(packet)
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        time_item = QTableWidgetItem(str(packet.time))
        src_item = QTableWidgetItem(packet.src if hasattr(packet, "src") else "N/A")
        dst_item = QTableWidgetItem(packet.dst if hasattr(packet, "dst") else "N/A")
        len_item = QTableWidgetItem(str(len(packet)))
        label_item = QTableWidgetItem(self.label_box.currentText())

        self.packet_table.setItem(row, 0, time_item)
        self.packet_table.setItem(row, 1, src_item)
        self.packet_table.setItem(row, 2, dst_item)
        self.packet_table.setItem(row, 3, len_item)
        self.packet_table.setItem(row, 4, label_item)

        features = self.detector.extract_features(packet)
        label = self.label_box.currentText()
        self.trainer.add_sample(features, label)
        self.status_label.setText(f"Zebranych próbek: {self.trainer.get_dataset_size()}")

    def train_model(self):
        success = self.trainer.train_model()
        if success:
            QMessageBox.information(self, "Sukces", "Model został wytrenowany i zapisany.")
        else:
            QMessageBox.warning(self, "Błąd", "Brak danych do treningu.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TrainingGUI()
    window.show()
    sys.exit(app.exec_())

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QPushButton, QVBoxLayout,
    QWidget, QHBoxLayout, QLabel
)
from ui.lan_tab import LanTab
from ui.sniffer_tab import SnifferTab
from ui.threats_tab import ThreatsTab
from ui.geo_tab import GeoTab
from ui.reputation_tab import ReputationTab
from ui.settings_tab import SettingsTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Guard — Interfejs")
        self.setGeometry(100, 100, 1200, 800)

        self.tabs = QTabWidget()
        self.tabs.addTab(LanTab(), "Skaner LAN")
        self.tabs.addTab(SnifferTab(), "Sniffer")
        self.tabs.addTab(ThreatsTab(), "Zagrożenia")
        self.tabs.addTab(GeoTab(), "Geolokalizacja")
        self.tabs.addTab(ReputationTab(), "Reputacja IP")
        self.tabs.addTab(SettingsTab(), "Ustawienia")

        control_layout = QHBoxLayout()
        control_layout.addWidget(QPushButton("▶️ Start"))
        control_layout.addWidget(QPushButton("⏸️ Pauza"))
        control_layout.addWidget(QPushButton("⏹️ Stop"))

        system_info = QLabel("RAM: 45% | CPU: 23% | Pakiety: 128")
        control_layout.addWidget(system_info)

        main_layout = QVBoxLayout()
        main_layout.addLayout(control_layout)
        main_layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

def run_gui():
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()

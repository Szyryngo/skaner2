from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from ui.tabs.lan_tab import LanTab
from ui.tabs.threats_tab import ThreatsTab
from ui.tabs.geo_tab import GeoTab
from ui.tabs.reputation_tab import ReputationTab
from ui.tabs.settings_tab import SettingsTab
from ui.tabs.sniffer.sniffer_tab import SnifferTab


def run_gui():
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Guard")
        self.setGeometry(100, 100, 1000, 600)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.tabs.addTab(LanTab(), "LAN")
        self.tabs.addTab(SnifferTab(), "Sniffer")
        self.tabs.addTab(ThreatsTab(), "Threats")
        self.tabs.addTab(GeoTab(), "Geolocation")
        self.tabs.addTab(ReputationTab(), "Reputation")
        self.tabs.addTab(SettingsTab(), "Settings")

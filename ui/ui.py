from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from ui.tabs.lan_tab import LanTab
from ui.tabs.sniffer_tab import SnifferTab
from ui.tabs.threat_tab import ThreatTab
from ui.tabs.ai_tab import AiTab
from ui.tabs.map_tab import MapTab

def start_gui(sniffer, lan_scanner, arp_guard, threat_intel, anomaly_detector, ai_detector):
    app = QApplication([])
    window = QMainWindow()
    tabs = QTabWidget()

    tabs.addTab(LanTab(lan_scanner), "LAN")
    tabs.addTab(SnifferTab(sniffer, arp_guard, anomaly_detector), "Sniffer")
    tabs.addTab(ThreatTab(threat_intel), "Threat Intel")
    tabs.addTab(AiTab(ai_detector), "AI")
    tabs.addTab(MapTab(), "Mapa")

    window.setCentralWidget(tabs)
    window.setWindowTitle("Network Guard")
    window.resize(800, 600)
    window.show()
    app.exec_()

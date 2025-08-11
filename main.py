from ui.ui import start_gui
from core.sniffer import Sniffer
from core.lan import LanScanner
from core.arp_guard import ArpGuard
from core.threat_intel import ThreatIntel
from core.anomalies import AnomalyDetector
from core.ai import ThreatDetector

def main():
    sniffer = Sniffer()
    lan_scanner = LanScanner()
    arp_guard = ArpGuard()
    threat_intel = ThreatIntel()
    anomaly_detector = AnomalyDetector()
    ai_detector = ThreatDetector()

    start_gui(sniffer, lan_scanner, arp_guard, threat_intel, anomaly_detector, ai_detector)

if __name__ == "__main__":
    main()

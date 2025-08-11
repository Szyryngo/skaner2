class AnomalyDetector:
    def __init__(self):
        self.packet_count = 0

    def analyze(self, packet):
        self.packet_count += 1
        if self.packet_count > 1000:
            print("[WARNING] High traffic volume detected")

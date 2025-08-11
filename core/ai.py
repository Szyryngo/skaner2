import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.packet import Raw

MODEL_PATH = "data/models/threat_model.pkl"

class ThreatDetector:
    def __init__(self):
        self.model = None
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)

    def extract_features(self, packet):
        features = [
            int(packet.haslayer(TCP)),
            int(packet.haslayer(UDP)),
            int(packet.haslayer(ICMP)),
            len(packet),
            int(packet.haslayer(Raw)),
            packet.time % 60  # czas jako cecha
        ]
        return features

    def classify(self, packet):
        features = self.extract_features(packet)
        if self.model:
            prediction = self.model.predict([features])[0]
            return prediction
        else:
            return self.heuristic(packet)

    def heuristic(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            return "scan"
        elif packet.haslayer(Raw) and b"malware" in bytes(packet[Raw]):
            return "malware"
        elif packet.haslayer(ICMP):
            return "flood"
        else:
            return "normal"

    def train(self, X, y):
        self.model = RandomForestClassifier()
        self.model.fit(X, y)
        joblib.dump(self.model, MODEL_PATH)

    def should_alert(self, classification):
        return classification in ["malware", "flood", "scan"]

    def get_color(self, classification):
        return {
            "normal": "white",
            "scan": "orange",
            "malware": "red",
            "flood": "purple"
        }.get(classification, "gray")

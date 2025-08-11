import joblib
from sklearn.ensemble import RandomForestClassifier
import os

class ThreatDetector:
    def __init__(self):
        self.model_path = "data/models/threat_model.pkl"
        self.model = None
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)

    def train(self, X, y):
        self.model = RandomForestClassifier()
        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)

    def predict(self, features):
        if self.model:
            return self.model.predict([features])[0]
        return "Unknown"

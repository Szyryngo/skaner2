import joblib
from sklearn.ensemble import RandomForestClassifier

class TrainingManager:
    def __init__(self):
        self.X = []
        self.y = []
        self.model_path = "data/models/custom_model.pkl"

    def add_sample(self, features, label):
        self.X.append(features)
        self.y.append(label)

    def train_model(self):
        if not self.X or not self.y:
            return False
        model = RandomForestClassifier()
        model.fit(self.X, self.y)
        joblib.dump(model, self.model_path)
        return True

    def get_dataset_size(self):
        return len(self.X)

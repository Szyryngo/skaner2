from collections import Counter

class ThreatStats:
    def __init__(self):
        self.counter = Counter()

    def update(self, classification):
        self.counter[classification] += 1

    def get_stats(self):
        return dict(self.counter)

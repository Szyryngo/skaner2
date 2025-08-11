import csv

class StatsExporter:
    def __init__(self, path="data/stats.csv"):
        self.path = path

    def export(self, stats_dict):
        with open(self.path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Typ zagrożenia", "Liczba"])
            for key, value in stats_dict.items():
                writer.writerow([key, value])

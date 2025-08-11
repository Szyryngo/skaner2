from datetime import datetime

class EventLogger:
    def __init__(self, log_path="data/logs/events.log"):
        self.log_path = log_path

    def log_event(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_path, "a") as f:
            f.write(f"[{timestamp}] {message}\n")

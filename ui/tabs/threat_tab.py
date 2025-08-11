from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit

class ThreatTab(QWidget):
    def __init__(self, threat_intel):
        super().__init__()
        self.threat_intel = threat_intel
        self.layout = QVBoxLayout()

        self.input = QLineEdit()
        self.input.setPlaceholderText("Wprowadź IP")
        self.check_btn = QPushButton("Sprawdź reputację IP")
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.check_btn.clicked.connect(self.check_ip)

        self.layout.addWidget(self.input)
        self.layout.addWidget(self.check_btn)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def check_ip(self):
        ip = self.input.text()
        result = self.threat_intel.check_ip(ip)
        self.output.clear()
        for k, v in result.items():
            self.output.append(f"{k}: {v}")

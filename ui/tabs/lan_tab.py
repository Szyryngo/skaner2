from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit

class LanTab(QWidget):
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        self.layout = QVBoxLayout()
        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.scan_btn = QPushButton("Skanuj LAN")
        self.scan_btn.clicked.connect(self.scan)

        self.layout.addWidget(self.scan_btn)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def scan(self):
        results = self.scanner.scan()
        self.output.clear()
        for device in results:
            self.output.append(f"IP: {device['ip']} | MAC: {device['mac']}")

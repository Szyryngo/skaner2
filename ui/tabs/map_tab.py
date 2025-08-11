from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel
import webbrowser

class MapTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()
        self.label = QLabel("Kliknij, aby otworzyć mapę zagrożeń")
        self.open_btn = QPushButton("Otwórz mapę")
        self.open_btn.clicked.connect(self.open_map)

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.open_btn)
        self.setLayout(self.layout)

    def open_map(self):
        webbrowser.open("map.html")

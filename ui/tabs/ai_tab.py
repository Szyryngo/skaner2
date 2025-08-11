from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QTextEdit

class AiTab(QWidget):
    def __init__(self, ai_detector):
        super().__init__()
        self.ai_detector = ai_detector
        self.layout = QVBoxLayout()

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        self.test_btn = QPushButton("Testuj AI (przykładowe dane)")
        self.test_btn.clicked.connect(self.test_ai)

        self.layout.addWidget(self.test_btn)
        self.layout.addWidget(self.output)
        self.setLayout(self.layout)

    def test_ai(self):
        sample_features = [0.5, 0.2, 0.1, 0.9]  # przykładowe dane
        prediction = self.ai_detector.predict(sample_features)
        self.output.setText(f"AI klasyfikacja: {prediction}")

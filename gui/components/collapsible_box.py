from PyQt5.QtWidgets import QWidget, QPushButton, QFrame, QVBoxLayout
from PyQt5.QtCore import Qt

class CollapsibleBox(QWidget):
    def __init__(self, title="", parent=None):
        super(CollapsibleBox, self).__init__(parent)
        
        self.toggle_button = QPushButton(f"▼ {title}")
        self.toggle_button.setCheckable(True)
        self.toggle_button.setChecked(False)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                border: none;
                text-align: left;
                padding: 5px;
                font-weight: bold;
            }
            QPushButton:checked {
                background-color: #e0e0e0;
            }
        """)
        self.toggle_button.clicked.connect(self.on_clicked)
        
        self.content_area = QFrame()
        self.content_area.setVisible(False)
        self.content_area.setFrameStyle(QFrame.StyledPanel)
        
        lay = QVBoxLayout(self)
        lay.setSpacing(2)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.toggle_button)
        lay.addWidget(self.content_area)
        
    def on_clicked(self):
        checked = self.toggle_button.isChecked()
        self.content_area.setVisible(checked)
        self.toggle_button.setText(f"{'▲' if checked else '▼'} {self.toggle_button.text()[2:]}")
        
    def setContentLayout(self, layout):
        self.content_area.setLayout(layout)

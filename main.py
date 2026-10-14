"""PyQt5 AES/RSA desktop demonstration. Run with: python main.py."""

import sys
from pathlib import Path

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QButtonGroup, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit,
    QPushButton, QRadioButton, QStackedWidget, QVBoxLayout, QWidget,
)

from crypto_utils import aes_decrypt, aes_encrypt, rsa_decrypt, rsa_encrypt, rsa_generate


class RSAWorker(QThread):
    completed = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, message, bits, parent=None):
        super().__init__(parent)
        self.message, self.bits = message, bits

    def run(self):
        try:
            keys = rsa_generate(self.bits)
            self.completed.emit({"n": str(keys.n), "e": str(keys.e),
                                 "d": str(keys.d),
                                 "ciphertext": rsa_encrypt(self.message, keys.e, keys.n)})
        except Exception as exc:
            self.failed.emit(str(exc))


class EncryptionWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setWindowTitle("AES & RSA Encryption - EE305")
        self.resize(1100, 690)
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self.stack.addWidget(self.make_home())
        self.stack.addWidget(self.make_aes_page())
        self.stack.addWidget(self.make_rsa_page())
        self.statusBar().showMessage("Choose AES or RSA to begin.")

    def button(self, text, action, layout):
        button = QPushButton(text)
        button.clicked.connect(action)
        layout.addWidget(button)
        return button

    def editor(self, placeholder="", readonly=False):
        edit = QPlainTextEdit()
        edit.setPlaceholderText(placeholder)
        edit.setReadOnly(readonly)
        return edit

    def page(self, title, description):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        heading = QLabel(title)
        heading.setStyleSheet("font-size: 22px; font-weight: bold;")
        layout.addWidget(heading)
        explanation = QLabel(description)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        return widget, layout

    def make_home(self):
        page, layout = self.page("Encryption System", "EE305 Discrete Mathematics - AES and RSA demonstrations")
        layout.addStretch()
        row = QHBoxLayout()
        self.button("AES Encryption", lambda: self.stack.setCurrentIndex(1), row)
        self.button("RSA Encryption", lambda: self.stack.setCurrentIndex(2), row)
        layout.addLayout(row)
        layout.addStretch()
        return page

    def panels(self, layout):
        row = QHBoxLayout()
        groups = []
        for title in ("Encrypt", "Decrypt"):
            group = QGroupBox(title)
            column = QVBoxLayout(group)
            row.addWidget(group)
            groups.append(column)
        layout.addLayout(row)
        return groups

    def io_buttons(self, layout, editor, save=False):
        self.button("Save result..." if save else "Load text file...",
                    lambda: self.save_text(editor) if save else self.load_text(editor), layout)

    def make_aes_page(self):
        page, layout = self.page("AES Encryption System", "AES-256-CBC | 32-byte key | 16-byte IV | Base64 results")
        left, right = self.panels(layout)
        self.aes_message = self.editor("Type the message to encrypt")
        left.addWidget(self.aes_message)
        self.io_buttons(left, self.aes_message)
        self.button("Encrypt", self.encrypt_aes, left)
        self.aes_ciphertext = self.editor("Encrypted message", True)
        left.addWidget(self.aes_ciphertext)
        self.aes_key_out, self.aes_iv_out = QLineEdit(), QLineEdit()
        form = QFormLayout()
        for label, field in (("Key (Base64)", self.aes_key_out), ("IV (Base64)", self.aes_iv_out)):
            field.setReadOnly(True)
            form.addRow(label, field)
        left.addLayout(form)
        self.io_buttons(left, self.aes_ciphertext, True)
        self.aes_input = self.editor("Paste Base64 ciphertext")
        right.addWidget(self.aes_input)
        self.io_buttons(right, self.aes_input)
        self.aes_key_in, self.aes_iv_in = QLineEdit(), QLineEdit()
        form = QFormLayout()
        form.addRow("Key (Base64)", self.aes_key_in)
        form.addRow("IV (Base64)", self.aes_iv_in)
        right.addLayout(form)
        self.button("Use encryption result", self.copy_aes, right)
        self.button("Decrypt", self.decrypt_aes, right)
        self.aes_plaintext = self.editor("Decrypted message", True)
        right.addWidget(self.aes_plaintext)
        self.io_buttons(right, self.aes_plaintext, True)
        self.button("Home", lambda: self.stack.setCurrentIndex(0), layout)
        return page

    def make_rsa_page(self):
        page, layout = self.page("RSA Encryption System", "Textbook RSA demonstration - decimal key values and ciphertext blocks")
        choices = QHBoxLayout()
        self.key_sizes = QButtonGroup(self)
        for bits in (2048, 1024, 512):
            radio = QRadioButton(f"{bits} bits" + (" (educational)" if bits < 2048 else ""))
            self.key_sizes.addButton(radio, bits)
            radio.setChecked(bits == 2048)
            choices.addWidget(radio)
        layout.addLayout(choices)
        left, right = self.panels(layout)
        self.rsa_message = self.editor("Type the message to encrypt")
        left.addWidget(self.rsa_message)
        self.io_buttons(left, self.rsa_message)
        self.rsa_encrypt_button = self.button("Generate keys and encrypt", self.encrypt_rsa, left)
        self.rsa_ciphertext = self.editor("JSON list of encrypted blocks", True)
        left.addWidget(self.rsa_ciphertext)
        self.rsa_e_out, self.rsa_d_out, self.rsa_n_out = QLineEdit(), QLineEdit(), QLineEdit()
        form = QFormLayout()
        for label, field in (("Public exponent e", self.rsa_e_out), ("Private exponent d", self.rsa_d_out), ("Modulus n", self.rsa_n_out)):
            field.setReadOnly(True)
            form.addRow(label, field)
        left.addLayout(form)
        self.io_buttons(left, self.rsa_ciphertext, True)
        self.rsa_input = self.editor("Paste the JSON list of encrypted blocks")
        right.addWidget(self.rsa_input)
        self.io_buttons(right, self.rsa_input)
        self.rsa_d_in, self.rsa_n_in = QLineEdit(), QLineEdit()
        form = QFormLayout()
        form.addRow("Private exponent d", self.rsa_d_in)
        form.addRow("Modulus n", self.rsa_n_in)
        right.addLayout(form)
        self.button("Use encryption result", self.copy_rsa, right)
        self.button("Decrypt", self.decrypt_rsa, right)
        self.rsa_plaintext = self.editor("Decrypted message", True)
        right.addWidget(self.rsa_plaintext)
        self.io_buttons(right, self.rsa_plaintext, True)
        self.button("Home", lambda: self.stack.setCurrentIndex(0), layout)
        return page

    def show_error(self, message):
        QMessageBox.warning(self, "Check your input", str(message))

    def encrypt_aes(self):
        try:
            result = aes_encrypt(self.aes_message.toPlainText())
            self.aes_ciphertext.setPlainText(result["ciphertext"])
            self.aes_key_out.setText(result["key"])
            self.aes_iv_out.setText(result["iv"])
            self.aes_plaintext.clear()
            self.statusBar().showMessage("AES encryption complete. Keep the key and IV for decryption.")
        except Exception as exc:
            self.show_error(exc)

    def copy_aes(self):
        self.aes_input.setPlainText(self.aes_ciphertext.toPlainText())
        self.aes_key_in.setText(self.aes_key_out.text())
        self.aes_iv_in.setText(self.aes_iv_out.text())

    def decrypt_aes(self):
        self.aes_plaintext.clear()
        try:
            result = aes_decrypt(self.aes_input.toPlainText(), self.aes_key_in.text(), self.aes_iv_in.text())
            self.aes_plaintext.setPlainText(result)
            self.statusBar().showMessage("AES decryption complete.")
        except ValueError as exc:
            self.show_error(exc)

    def encrypt_rsa(self):
        if self.worker is not None:
            return
        self.rsa_encrypt_button.setEnabled(False)
        self.rsa_plaintext.clear()
        self.statusBar().showMessage("Generating RSA keys and encrypting...")
        self.worker = RSAWorker(self.rsa_message.toPlainText(), self.key_sizes.checkedId(), self)
        self.worker.completed.connect(self.rsa_complete)
        self.worker.failed.connect(self.show_error)
        self.worker.finished.connect(self.rsa_finished)
        self.worker.start()

    def rsa_complete(self, result):
        self.rsa_ciphertext.setPlainText(result["ciphertext"])
        self.rsa_e_out.setText(result["e"])
        self.rsa_d_out.setText(result["d"])
        self.rsa_n_out.setText(result["n"])
        self.statusBar().showMessage("RSA encryption complete.")

    def rsa_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.rsa_encrypt_button.setEnabled(True)

    def copy_rsa(self):
        self.rsa_input.setPlainText(self.rsa_ciphertext.toPlainText())
        self.rsa_d_in.setText(self.rsa_d_out.text())
        self.rsa_n_in.setText(self.rsa_n_out.text())

    def decrypt_rsa(self):
        self.rsa_plaintext.clear()
        try:
            result = rsa_decrypt(self.rsa_input.toPlainText(), int(self.rsa_d_in.text()), int(self.rsa_n_in.text()))
            self.rsa_plaintext.setPlainText(result)
            self.statusBar().showMessage("RSA decryption complete.")
        except ValueError as exc:
            self.show_error(exc)

    def load_text(self, editor):
        name, _ = QFileDialog.getOpenFileName(self, "Load UTF-8 text", "", "Text files (*.txt *.json);;All files (*)")
        if name:
            try:
                with Path(name).open("rb") as stream:
                    data = stream.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ValueError("Choose a text file up to 1 MB for this demonstration.")
                editor.setPlainText(data.decode("utf-8"))
            except (OSError, UnicodeError, ValueError) as exc:
                self.show_error(exc)

    def save_text(self, editor):
        name, _ = QFileDialog.getSaveFileName(self, "Save result", "result.txt", "Text files (*.txt);;All files (*)")
        if name:
            try:
                Path(name).write_text(editor.toPlainText(), encoding="utf-8")
            except OSError as exc:
                self.show_error(exc)

    def closeEvent(self, event):
        if self.worker is not None:
            self.statusBar().showMessage("Wait for the RSA operation to finish before closing.")
            event.ignore()
        else:
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = EncryptionWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())

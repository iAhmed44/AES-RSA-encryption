import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication
from main import EncryptionWindow


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.window = EncryptionWindow()

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()

    def test_home_navigation_and_aes_workflow(self):
        w = self.window
        self.assertEqual(w.stack.count(), 3)
        w.stack.setCurrentIndex(1)
        w.aes_message.setPlainText("مرحبا / Hello 🔐")
        w.encrypt_aes()
        w.copy_aes()
        w.decrypt_aes()
        self.assertEqual(w.aes_plaintext.toPlainText(), "مرحبا / Hello 🔐")
        w.stack.setCurrentIndex(0)
        w.stack.setCurrentIndex(1)
        self.assertEqual(w.aes_message.toPlainText(), "مرحبا / Hello 🔐")

    def test_background_rsa_workflow(self):
        w = self.window
        self.assertEqual(w.key_sizes.checkedId(), 2048)
        w.key_sizes.button(512).setChecked(True)
        w.rsa_message.setPlainText("Discrete Mathematics / العربية")
        w.encrypt_rsa()
        self.assertFalse(w.rsa_encrypt_button.isEnabled())
        deadline = time.monotonic() + 20
        while w.worker is not None and time.monotonic() < deadline:
            QTest.qWait(20)
        self.assertIsNone(w.worker)
        self.assertTrue(w.rsa_encrypt_button.isEnabled())
        self.assertEqual(int(w.rsa_n_out.text()).bit_length(), 512)
        w.copy_rsa()
        w.decrypt_rsa()
        self.assertEqual(w.rsa_plaintext.toPlainText(), "Discrete Mathematics / العربية")

    def test_invalid_input_clears_stale_plaintext_and_reports_error(self):
        w = self.window
        w.aes_plaintext.setPlainText("old result")
        with patch("main.QMessageBox.warning") as warning:
            w.decrypt_aes()
            warning.assert_called_once()
        self.assertEqual(w.aes_plaintext.toPlainText(), "")
        with patch("main.QMessageBox.warning") as warning:
            w.decrypt_rsa()
            warning.assert_called_once()

    def test_load_and_save_text(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.txt"
            target = Path(directory) / "output.txt"
            source.write_text("العربية / English", encoding="utf-8")
            with patch("main.QFileDialog.getOpenFileName", return_value=(str(source), "")):
                self.window.load_text(self.window.aes_message)
            self.assertEqual(self.window.aes_message.toPlainText(), "العربية / English")
            with patch("main.QFileDialog.getSaveFileName", return_value=(str(target), "")):
                self.window.save_text(self.window.aes_message)
            self.assertEqual(target.read_text(encoding="utf-8"), "العربية / English")


if __name__ == "__main__":
    unittest.main()

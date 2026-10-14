import base64
import json
import unittest

from crypto_utils import aes_decrypt, aes_encrypt, rsa_decrypt, rsa_encrypt, rsa_generate


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = rsa_generate(512)

    def test_aes_round_trips_unicode_long_and_empty_messages(self):
        for message in ("", "Discrete Mathematics", "مرحبا بالعالم 🔐\x00", "a" * 10000):
            with self.subTest(message=message[:30]):
                encrypted = aes_encrypt(message)
                self.assertEqual(len(base64.b64decode(encrypted["key"])), 32)
                self.assertEqual(len(base64.b64decode(encrypted["iv"])), 16)
                self.assertEqual(aes_decrypt(**encrypted), message)

    def test_aes_uses_fresh_key_and_iv(self):
        first, second = aes_encrypt("repeat"), aes_encrypt("repeat")
        self.assertNotEqual(first["key"], second["key"])
        self.assertNotEqual(first["iv"], second["iv"])
        self.assertNotEqual(first["ciphertext"], second["ciphertext"])

    def test_aes_rejects_invalid_base64_and_lengths(self):
        original = aes_encrypt("message")
        cases = [("key", "?"), ("iv", "?"), ("ciphertext", "?"),
                 ("key", base64.b64encode(b"short").decode()),
                 ("iv", base64.b64encode(b"short").decode()),
                 ("ciphertext", base64.b64encode(b"short").decode()),
                 ("ciphertext", "")]
        for name, value in cases:
            with self.subTest(field=name, value=value):
                bad = dict(original, **{name: value})
                with self.assertRaises(ValueError):
                    aes_decrypt(**bad)

    def test_aes_rejects_invalid_padding(self):
        from Crypto.Cipher import AES
        key, iv = bytes(32), bytes(16)
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(bytes(16))
        with self.assertRaisesRegex(ValueError, "Decryption failed"):
            aes_decrypt(base64.b64encode(ciphertext).decode(),
                        base64.b64encode(key).decode(), base64.b64encode(iv).decode())

    def test_rsa_round_trips_unicode_crossing_block_boundaries(self):
        k = self.keys
        for message in ("", "Discrete Mathematics", "\x00" * 130,
                        "a" * 61 + "🔐" + "مرحبا" * 80):
            with self.subTest(message=message[:30]):
                encrypted = rsa_encrypt(message, k.e, k.n)
                self.assertEqual(rsa_decrypt(encrypted, k.d, k.n), message)
                self.assertTrue(all(0 <= c < k.n for c in json.loads(encrypted)))

    def test_all_rsa_key_sizes_and_round_trips(self):
        for bits in (512, 1024, 2048):
            with self.subTest(bits=bits):
                k = self.keys if bits == 512 else rsa_generate(bits)
                self.assertEqual(k.n.bit_length(), bits)
                self.assertEqual(k.e, 65537)
                self.assertEqual(rsa_decrypt(rsa_encrypt("test", k.e, k.n), k.d, k.n), "test")

    def test_rsa_rejects_malformed_ciphertext(self):
        k = self.keys
        for bad in ("not JSON", "{}", "[true]", "[1.5]", "[-1]", str([k.n]), "[0]"):
            with self.subTest(ciphertext=bad), self.assertRaises(ValueError):
                rsa_decrypt(bad, k.d, k.n)

    def test_rsa_rejects_invalid_keys_and_sizes(self):
        for bits in (0, 256, 4096):
            with self.assertRaises(ValueError):
                rsa_generate(bits)
        for e, n in ((0, self.keys.n), (self.keys.n, self.keys.n), (65537, 7)):
            with self.assertRaises(ValueError):
                rsa_encrypt("text", e, n)


if __name__ == "__main__":
    unittest.main()

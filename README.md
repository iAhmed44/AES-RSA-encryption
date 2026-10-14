# AES and RSA Encryption

Python/PyQt5 desktop application recreated from the EE305 Discrete Mathematics project report at King Abdulaziz University. It follows the report's home menu and separate AES/RSA encryption and decryption screens. This is a reconstruction, not the recovered original source.

## Features

- AES-256-CBC encryption with a random 32-byte key and 16-byte IV; Base64 ciphertext, key, and IV.
- Textbook RSA demonstration with 512-, 1024-, and 2048-bit modulus options; displays public exponent, private exponent, and modulus.
- Arabic and English UTF-8 text, long messages, text-file loading, and result saving.
- Copy encryption results into the decryption form, with input validation and readable error messages.
- RSA key generation runs in a background thread so the window remains responsive.

## Run

Use Python 3.10 or newer:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

On Windows, activate with `.venv\Scripts\activate` instead. On macOS, use a Python distribution supported by the available PyQt5 wheels; if installation fails on Apple Silicon, use a compatible Python/Qt installation or an x86_64 environment under Rosetta.

Choose AES or RSA, enter text (or load a UTF-8 text file), and encrypt. Click **Use encryption result**, then **Decrypt**. To decrypt later, keep the displayed key/IV for AES or private exponent/modulus for RSA. Saving a result saves only that text, not the keys. Text-file loading is limited to 1 MB.

## Educational scope

The report's examples are reproduced as separate demonstrations, not a hybrid AES/RSA system. AES-CBC does not authenticate ciphertext. The RSA demonstration uses raw modular exponentiation without OAEP padding; the 512- and 1024-bit options are retained for coursework comparison. Do not use these demonstrations to protect real sensitive data.

Differences from the screenshots: the selected RSA size describes the modulus size; the public exponent is 65537; a byte encoding supports Unicode and zero bytes; the UI is built in Python without the missing `.ui` file. Its ciphertext format is not compatible with the original screenshot code.

## Tests

```bash
python -m unittest discover -s tests -v
QT_QPA_PLATFORM=offscreen python -m unittest discover -s tests -v
```

The offscreen setting is useful for testing the GUI on Linux without a display. Tests require the same dependencies as the application.

## Files

- `main.py` - desktop interface.
- `crypto_utils.py` - AES and educational RSA implementation.
- `tests/` - cryptographic and GUI workflow tests.

API references: [PyCryptodome CBC](https://www.pycryptodome.org/src/cipher/classic), [PyCryptodome utilities](https://www.pycryptodome.org/src/util/util), and [PyQt5](https://www.riverbankcomputing.com/static/Docs/PyQt5/).

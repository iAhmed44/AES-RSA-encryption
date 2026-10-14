"""Cryptographic demonstrations recreated from the EE305 project report.

AES-CBC and textbook RSA reproduce the educational examples. They are not
authenticated encryption and are not intended for protecting real secrets.
"""

import base64
import binascii
import json
import math
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad, unpad


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode(value: str, name: str) -> bytes:
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"{name} must be valid Base64.") from exc


def aes_encrypt(message: str) -> dict:
    """Return AES-256-CBC ciphertext, random key and IV as Base64 strings."""
    key, iv = get_random_bytes(32), get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
    return {"ciphertext": _encode(encrypted), "key": _encode(key), "iv": _encode(iv)}


def aes_decrypt(ciphertext: str, key: str, iv: str) -> str:
    key_bytes = _decode(key, "Key")
    iv_bytes = _decode(iv, "IV")
    data = _decode(ciphertext, "Ciphertext")
    if len(key_bytes) != 32:
        raise ValueError("AES-256 requires a 32-byte key (Base64 encoded).")
    if len(iv_bytes) != 16:
        raise ValueError("AES-CBC requires a 16-byte IV (Base64 encoded).")
    if not data or len(data) % AES.block_size:
        raise ValueError("Ciphertext must contain complete 16-byte AES blocks.")
    try:
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        return unpad(cipher.decrypt(data), AES.block_size).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Decryption failed. Check the key, IV, and ciphertext.") from exc


@dataclass(frozen=True)
class RSAKeys:
    n: int
    e: int
    d: int


def rsa_generate(bits: int = 2048) -> RSAKeys:
    """Generate an exact-size modulus for the textbook RSA demonstration."""
    if bits not in (512, 1024, 2048):
        raise ValueError("Choose a demonstration key size of 512, 1024, or 2048 bits.")
    e = 65537
    while True:
        p, q = getPrime(bits // 2), getPrime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        if p != q and n.bit_length() == bits and math.gcd(e, phi) == 1:
            return RSAKeys(n=n, e=e, d=pow(e, -1, phi))


def _check_rsa(exponent: int, n: int) -> None:
    if type(exponent) is not int or type(n) is not int:
        raise ValueError("RSA key values must be integers.")
    if not 512 <= n.bit_length() <= 4096 or not 1 < exponent < n:
        raise ValueError("Invalid RSA key values; provide the generated exponent and modulus.")


def rsa_encrypt(message: str, e: int, n: int) -> str:
    """Return a JSON list of decimal textbook RSA ciphertext blocks.

    A leading byte preserves zero bytes and the block length. This is an
    encoding marker, not cryptographic padding such as OAEP.
    """
    _check_rsa(e, n)
    data = message.encode("utf-8")
    width = (n.bit_length() - 1) // 8 - 1
    blocks = [pow(int.from_bytes(b"\x01" + data[i:i + width], "big"), e, n)
              for i in range(0, len(data), width)]
    return json.dumps(blocks)


def rsa_decrypt(ciphertext: str, d: int, n: int) -> str:
    _check_rsa(d, n)
    try:
        blocks = json.loads(ciphertext)
    except (ValueError, TypeError) as exc:
        raise ValueError("RSA ciphertext must be a JSON list of integers.") from exc
    if not isinstance(blocks, list):
        raise ValueError("RSA ciphertext must be a JSON list of integers.")
    if any(type(c) is not int or not 0 <= c < n for c in blocks):
        raise ValueError("Each RSA ciphertext block must be an integer below the modulus.")
    width = (n.bit_length() - 1) // 8 - 1
    output = bytearray()
    for c in blocks:
        value = pow(c, d, n)
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if len(raw) < 2 or len(raw) > width + 1 or raw[0] != 1:
            raise ValueError("Decryption failed. Check the private key and ciphertext.")
        output.extend(raw[1:])
    try:
        return output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted message is not valid UTF-8. Check the key.") from exc

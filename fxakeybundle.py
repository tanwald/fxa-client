#!/usr/bin/env python3

import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CRYPTO_BACKEND = default_backend()


class FxaKeyBundle:

    def __init__(self, enc_key, mac_key):
        self.enc_key = enc_key
        self.mac_key = mac_key

    def decrypt(self, data):
        payload = json.loads(data['payload'])

        mac = hmac.new(self.mac_key, payload['ciphertext'].encode('utf-8'), hashlib.sha256)
        if mac.hexdigest() != payload['hmac']:
            raise ValueError('hmac mismatch: {} != {}'.format(mac.hexdigest(), payload['hmac']))

        iv = base64.b64decode(payload['IV'])
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND
        )

        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(payload['ciphertext']))
        plaintext += decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return json.loads(plaintext)

    def encrypt(self, data):
        plaintext = json.dumps(data).encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        plaintext = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.enc_key),
            modes.CBC(iv),
            backend=CRYPTO_BACKEND
        )

        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(plaintext)
        cipher_text += encryptor.finalize()

        b64_cipher_text = base64.b64encode(cipher_text)
        mac = hmac.new(self.mac_key, b64_cipher_text, hashlib.sha256).hexdigest()

        return {
            'id': data['id'],
            'payload': json.dumps({
                'ciphertext': b64_cipher_text.decode(),
                'IV': base64.b64encode(iv).decode(),
                'hmac': mac,
            })
        }

#!/usr/bin/env python3

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from binascii import hexlify
from getpass import getpass

import fxa.core
import fxa.crypto
import syncclient.client
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TOKEN_SERVICE = 'https://token.services.mozilla.com/'
CRYPTO_BACKEND = default_backend()


class Lockwise(object):

    def __init__(self, fxa_email, fxa_password):
        assertion, key_bundle = self.login(fxa_email, fxa_password)

        self.fxa_client = syncclient.client.SyncClient(
            assertion,
            hexlify(hashlib.sha256(key_bundle).digest()[:16])
        )

        self.fxa_key_bundle = self.create_fxa_key_bundle(key_bundle)

    def login(self, fxa_email, fxa_password):
        client = fxa.core.Client()
        assertion = None
        key_bundle = None
        session = None

        try:
            session = client.login(fxa_email, fxa_password, keys=True)
            status = session.get_email_status()

            while not status['verified']:
                if input('please verify your email! press enter when done or type resend: ').strip() == 'resend':
                    session.resend_email_code()
                status = session.get_email_status()

            assertion = session.get_identity_assertion(TOKEN_SERVICE)
            _, key_bundle = session.fetch_keys()

        except Exception as e:
            print(str(e).lower())
        finally:
            if session is not None:
                session.destroy_session()
            else:
                print('aborting...')
                exit(1)

        return assertion, key_bundle

    def create_fxa_key_bundle(self, key_bundle):
        raw_sync_key = fxa.crypto.derive_key(key_bundle, 'oldsync', 64)
        root_key_bundle = KeyBundle(
            raw_sync_key[:32],
            raw_sync_key[32:],
        )

        keys_bso = self.fxa_client.get_record('crypto', 'keys')
        keys = root_key_bundle.decrypt(keys_bso)

        return KeyBundle(
            base64.b64decode(keys['default'][0]),
            base64.b64decode(keys['default'][1]),
        )

    def prepare_record(self, username, password, hostname, username_field, password_field):
        now = int(time.time() * 1000)

        return {
            'id': str(uuid.uuid4()),
            'username': username,
            'password': password,
            'hostname': hostname,
            'formSubmitURL': hostname,
            'usernameField': username_field,
            'passwordField': password_field,
            'timeCreated': now,
            'timePasswordChanged': now,
            'httpRealm': None,
        }

    def create_records(self):
        record = self.prepare_record('username', 'password', 'https://serenditree.io', 'username', 'password')
        encrypted_record = self.fxa_key_bundle.encrypt(record)
        assert self.fxa_key_bundle.decrypt(encrypted_record) == record

        self.fxa_client.put_record('passwords', encrypted_record)

    def retrieve_records(self):
        records = []

        for encrypted_record in self.fxa_client.get_records('passwords'):
            record = self.fxa_key_bundle.decrypt(encrypted_record)
            if 'deleted' not in record:
                records.append(record)

        print(json.dumps(records, indent=2))


class KeyBundle:

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

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()

        return json.loads(plaintext)

    def encrypt(self, data):
        plaintext = json.dumps(data)

        padder = padding.PKCS7(128).padder()
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

        return {
            'id': data['id'],
            'payload': json.dumps({
                'ciphertext': b64_cipher_text,
                'IV': base64.b64encode(iv),
                'hmac': hmac.new(self.mac_key, b64_cipher_text, hashlib.sha256).hexdigest(),
            })
        }


if __name__ == '__main__':
    email = input('email: ')
    password = getpass('password: ')

    lockwise = Lockwise(email, password)
    lockwise.retrieve_records()

#!/usr/bin/env python3

import base64
import hashlib
import json
import time
import uuid
from argparse import ArgumentParser

from binascii import hexlify
from getpass import getpass

import fxa.core
import fxa.crypto
import syncclient.client

from imports import JsonImport
from keybundle import KeyBundle


class Lockwise(object):
    TOKEN_SERVICE_ENDPOINT = 'https://token.services.mozilla.com/'
    BOOKMARKS_COLLECTION = 'bookmarks'
    PASSWORDS_COLLECTION = 'passwords'

    importer = None

    def __init__(self, fxa_email, fxa_password, dryrun=False):
        self.importer = JsonImport()

        if not dryrun:
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

            assertion = session.get_identity_assertion(self.TOKEN_SERVICE_ENDPOINT)
            _, key_bundle = session.fetch_keys()

        except Exception as e:
            print(str(e).lower())
        finally:
            if session is not None:
                session.destroy_session()
            else:
                print('could not login. aborting...')
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

    def finalize_record(self, record):
        now = int(time.time() * 1000)

        return {
            'id': str(uuid.uuid4()),
            'username': record['username'],
            'password': record['password'],
            'hostname': record['hostname'],
            'formSubmitURL': record['hostname'],
            'usernameField': '',
            'passwordField': '',
            'timeCreated': now,
            'timePasswordChanged': now,
            'httpRealm': None,
        }

    def create_records(self, dryrun=False):
        records = [self.finalize_record(r) for r in self.importer.load('data.json')]
        encrypted_records = []

        if not dryrun:
            for record in records:
                encrypted_record = self.fxa_key_bundle.encrypt(record)
                assert self.fxa_key_bundle.decrypt(encrypted_record) == record
                encrypted_records.append(encrypted_record)

        if len(encrypted_records) > 0:
            for index, record in enumerate(encrypted_records):
                print('\ncreating record {} of {}...'.format(index + 1, len(encrypted_records)))
                print(json.dumps(records[index], indent=2))
                print(json.dumps(record, indent=2))
                print(self.fxa_client.put_record('passwords', record))
                time.sleep(1)

    def retrieve_records(self):
        records = []

        for encrypted_record in self.fxa_client.get_records(self.BOOKMARKS_COLLECTION):
            record = self.fxa_key_bundle.decrypt(encrypted_record)
            if 'deleted' not in record:
                records.append(record)

        print(json.dumps(records, indent=2))

        return records

    def delete_record(self, record_id):
        print('deleting record {}...'.format(record_id))
        self.fxa_client.delete_record('passwords', record_id)

    def delete_all_records(self):
        records = self.retrieve_records()
        for index, record in enumerate(records):
            print('deleting record {} of {}...'.format(index + 1, len(records)))
            self.delete_record(record['id'])


if __name__ == '__main__':
    arg_parser = ArgumentParser(description='lockwise cli')
    arg_parser.add_argument('command', nargs=1, type=str, metavar='CMD',
                            help='command')
    arg_parser.add_argument('-d', '--dryrun', action='store_true',
                            help='dry run')
    arg_parser.add_argument('-a', '--all', action='store_true',
                            help='dry run')
    arg_parser.add_argument('-u', '--user', nargs='+', type=str, metavar='USER',
                            help='firefox account username')
    arg_parser.add_argument('-p', '--password', nargs='+', type=str, metavar='PASS',
                            help='firefox account password')

    args = arg_parser.parse_args()

    if args.user:
        email = args.user[0]
    else:
        email = input('email: ')

    if args.password:
        password = args.password[0]
    else:
        password = getpass('password: ')

    lockwise = Lockwise(email, password, dryrun=args.dryrun)

    if args.command[0] == 'list':
        lockwise.retrieve_records()
    elif args.command[0] == 'import':
        lockwise.create_records(dryrun=args.dryrun)
    elif args.command[0] == 'delete':
        if args.all:
            lockwise.delete_all_records()
        else:
            lockwise.delete_record('todo')

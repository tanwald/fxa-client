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

from fxaimport import FxaJsonImport
from fxakeybundle import FxaKeyBundle


class FxaClient(object):
    TOKEN_SERVICE_ENDPOINT = 'https://token.services.mozilla.com/'

    fxa_client = None
    importer = None

    def __init__(self, fxa_email, fxa_password, collection, dryrun=False):
        self.collection = collection
        self.importer = FxaJsonImport()
        self.dryrun = dryrun

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
        root_key_bundle = FxaKeyBundle(
            raw_sync_key[:32],
            raw_sync_key[32:],
        )

        keys_bso = self.fxa_client.get_record('crypto', 'keys')
        keys = root_key_bundle.decrypt(keys_bso)

        return FxaKeyBundle(
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

    def create_records(self):
        records = [self.finalize_record(r) for r in self.importer.load('data.json', dryrun=self.dryrun)]
        encrypted_records = []

        if not self.dryrun:
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

        for encrypted_record in self.fxa_client.get_records(self.collection):
            record = self.fxa_key_bundle.decrypt(encrypted_record)
            if 'deleted' not in record:
                records.append(record)

        print(json.dumps(records, indent=2))

        return records

    def delete_records(self, record_ids):
        for index, record_id in enumerate(record_ids):
            print('deleting record {} ({}/{})...'.format(record_id, index + 1, len(record_ids)))
            if not self.dryrun:
                self.fxa_client.delete_record(self.collection, record_id)

    def delete_all_records(self):
        records = self.retrieve_records()
        self.delete_records([r['id'] for r in records])


if __name__ == '__main__':
    arg_parser = ArgumentParser(description='lockwise cli')
    arg_parser.add_argument('command', nargs=1, metavar='CMD',
                            help='command {list|import|delete}')
    arg_parser.add_argument('args', nargs='*', metavar='ARGS',
                            help='optional arguments')
    arg_parser.add_argument('-B', '--bookmarks', action='store_const', const='bookmarks',
                            help='target bookmarks')
    arg_parser.add_argument('-P', '--passwords', action='store_const', const='passwords',
                            help='target passwords')
    arg_parser.add_argument('-d', '--dryrun', action='store_true',
                            help='dry run')
    arg_parser.add_argument('-a', '--all', action='store_true',
                            help='crud all')
    arg_parser.add_argument('-u', '--user', nargs=1, type=str, metavar='USER',
                            help='firefox account username')
    arg_parser.add_argument('-p', '--password', nargs=1, type=str, metavar='PASS',
                            help='firefox account password')

    args = arg_parser.parse_args()

    collection = None

    if args.bookmarks:
        collection = args.bookmarks
    elif args.passwords:
        collection = args.passwords
    else:
        arg_parser.print_help()
        print('\nerror: no target collection set')
        exit(1)

    if args.user:
        email = args.user[0]
    else:
        email = input('email: ')

    if args.password:
        password = args.password[0]
    else:
        password = getpass('password: ')

    fxa_client = FxaClient(email, password, collection, dryrun=args.dryrun)

    if args.command[0] == 'list':
        print('retrieving {}...'.format(collection))
        fxa_client.retrieve_records()
    elif args.command[0] == 'import':
        fxa_client.create_records()
    elif args.command[0] == 'delete':
        if args.all and input('delete all records [N/y]: ') == 'y':
            fxa_client.delete_all_records()
        elif args.args:
            if input('delete provided records [N/y]: ') == 'y':
                fxa_client.delete_records(args.args)
        else:
            arg_parser.print_help()
            print('\nerror: no record ids provided')
            exit(1)

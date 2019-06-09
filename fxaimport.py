#!/usr/bin/env python3

import json


class FxaJsonImport(object):

    def load(self, data, dryrun=False):
        converted_records = []
        with open(data, mode='r') as records_file:
            records = json.load(records_file)
            for record in records['items']:
                if record['folderId'] == '0f7b6962-94ac-4006-9a13-a86a00f828c2' and 'login' in record:
                    original = record
                    record = self.convert(record)
                    if None not in record.values():
                        converted_records.append(record)
                    else:
                        print('\ninvalid record:')
                        print(json.dumps(original, indent=2))

        if dryrun:
            print(json.dumps(converted_records, indent=2))

        return converted_records

    def convert(self, record):
        hostname = None
        if 'uris' in record['login']:
            hostname = record['login']['uris'][0]['uri'].split('/')
            if (len(hostname)) > 1:
                hostname = hostname[2]
            else:
                hostname = hostname[0]

        return {
            'username': record['login']['username'],
            'password': record['login']['password'],
            'hostname': 'https://' + hostname if hostname else None,
        }


if __name__ == '__main__':
    importer = FxaJsonImport()
    importer.load('data.json')

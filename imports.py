#!/usr/bin/env python3

import json


class JsonImport(object):

    def load(self, data):
        converted_records = []
        with open(data, mode='r') as records_file:
            records = json.load(records_file)
            for record in records['items']:
                if record['folderId'] == 'fe2cdde2-beac-4f5d-a42a-a7d90160935f':
                    original = record
                    record = self.convert(record)
                    if None not in record.values():
                        converted_records.append(record)
                    else:
                        print('\ninvalid record:')
                        print(json.dumps(original, indent=2))

        return converted_records

    def convert(self, record):
        hostname = record['login']['uris'][0]['uri'].split('/')
        if (len(hostname)) > 1:
            hostname = hostname[2]
        else:
            hostname = hostname[0]

        return {
            'username': record['login']['username'],
            'password': record['login']['password'],
            'hostname': 'https://' + hostname,
        }


if __name__ == '__main__':
    importer = JsonImport()
    importer.load('data.json')

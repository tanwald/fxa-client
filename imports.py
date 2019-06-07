#!/usr/bin/env python3

import json


class JsonImport(object):

    def yield_records(self, data):
        with open(data, 'r') as records_file:
            records = json.load(records_file)
            for record in records['folders']:
                print(json.dumps(record, indent=2))


if __name__ == '__main__':
    importer = JsonImport()
    importer.yield_records('records.json')

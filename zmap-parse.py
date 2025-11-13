#!/usr/bin/env python3
import json, argparse
from collections import defaultdict

def process_zmap(input_file):
    files = defaultdict(lambda: [open(f'zmap-{sport}.jsonl', 'w'), open(f'ips-zmap-{sport}.txt', 'w')])

    try:
        with open(input_file) as f:
            for line in f:
                try:
                    data = json.loads(line)
                    sport = data['sport']
                    jsonl, txt = files[sport]
                    jsonl.write(line)
                    txt.write(f"{data['saddr']}\n")
                except: pass
    finally:
        for jsonl, txt in files.values():
            jsonl.close()
            txt.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Split zmap JSONL by source port')
    parser.add_argument('-f', '--file', required=True, help='Input JSONL from zmap')
    args = parser.parse_args()
    process_zmap(args.file)
    print(f"Processing complete. Files split by sport from: {args.file}")

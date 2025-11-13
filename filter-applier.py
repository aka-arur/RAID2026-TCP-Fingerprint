#!/usr/bin/env python3
"""Usage: python3 filter.py -P <protocol> <input.jsonl>"""
import json, sys
from datetime import datetime
from collections import Counter

STANDARDS = {
    'modbus': {'windows': {14600, 16384, 29200, 32768}, 'threshold': 8192, 'scale_max': 16},
    's7comm': {'windows': {8192, 8760, 16384}, 'threshold': 5840, 'scale_max': 4},
    'veeder-root': {'windows': {14600, 16384, 29200}, 'threshold': 8192, 'scale_max': 2},
    'dnp3': {'windows': {14600, 16384, 29200, 32768}, 'threshold': 8192, 'scale_max': 8},
    'iec104': {'windows': {14600, 16384, 29200, 32768}, 'threshold': 8192, 'scale_max': 8},
}

class Filter:
    __slots__ = ('s', 'hp', 'lg', 'protocol', 'hp_w', 'hp_s', 'hp_t', 'lg_w', 'lg_s', 'lg_t')

    def __init__(self, p):
        self.protocol = p
        self.s = STANDARDS.get(p, STANDARDS['modbus'])
        self.hp = self.lg = 0
        self.hp_w, self.hp_s, self.hp_t = [], [], []
        self.lg_w, self.lg_s, self.lg_t = [], [], []

    def __call__(self, e):
        w, sc = e.get('window', 0), e.get('tcpopt_wscale', 0)
        t = (w, sc)

        if (w == 65535 and sc > 0) or (w not in self.s['windows'] and w > self.s['threshold']) or sc > self.s['scale_max']:
            self.hp += 1
            self.hp_w.append(w)
            self.hp_s.append(sc)
            self.hp_t.append(t)
            return True

        self.lg += 1
        self.lg_w.append(w)
        self.lg_s.append(sc)
        self.lg_t.append(t)
        return False

    def stats(self):
        hp_wc, hp_sc, hp_tc = Counter(self.hp_w), Counter(self.hp_s), Counter(self.hp_t)
        lg_wc, lg_sc, lg_tc = Counter(self.lg_w), Counter(self.lg_s), Counter(self.lg_t)

        print(f"\n{'='*60}\nOVERALL STATISTICS\n{'='*60}")
        print(f"  Honeypots: {self.hp}\n  Legitimate: {self.lg}\n  Total: {self.hp + self.lg}")

        print(f"\n{'='*60}\nHONEYPOT-ONLY STATISTICS\n{'='*60}\n\n=== HONEYPOT WINDOW SIZES ===")
        for w, n in hp_wc.most_common(): print(f"  {w}: {n}")
        print("\n=== HONEYPOT SCALING FACTORS ===")
        for s, n in sorted(hp_sc.items()): print(f"  {s}: {n}")
        print("\n=== HONEYPOT TUPLES (window size, scaling factor) ===")
        for (w, s), n in hp_tc.most_common(): print(f"  window size: {w}, scaling factor: {s}: {n}")

        print(f"\n{'='*60}\nLEGITIMATE-ONLY STATISTICS\n{'='*60}\n\n=== LEGITIMATE WINDOW SIZES ===")
        for w, n in lg_wc.most_common(): print(f"  {w}: {n}")
        print("\n=== LEGITIMATE SCALING FACTORS ===")
        for s, n in sorted(lg_sc.items()): print(f"  {s}: {n}")
        print("\n=== LEGITIMATE TUPLES (window size, scaling factor) ===")
        for (w, s), n in lg_tc.most_common(): print(f"  window size: {w}, scaling factor: {s}: {n}")

        meta = {
            "protocol": self.protocol,
            "timestamp": datetime.now().isoformat(),
            "counts": {"honeypots": self.hp, "legitimate": self.lg, "total": self.hp + self.lg},
            "overall": {
                "window_sizes": dict((w, hp_wc[w] + lg_wc[w]) for w in set(hp_wc) | set(lg_wc)),
                "scaling_factors": dict((s, hp_sc[s] + lg_sc[s]) for s in set(hp_sc) | set(lg_sc)),
                "tuples": [{"window_size": w, "scaling_factor": s, "count": n} for (w, s), n in
                          Counter(self.hp_t + self.lg_t).most_common()]
            },
            "honeypots": {
                "window_sizes": dict(hp_wc.most_common()),
                "scaling_factors": dict(sorted(hp_sc.items())),
                "tuples": [{"window_size": w, "scaling_factor": s, "count": n} for (w, s), n in hp_tc.most_common()]
            },
            "legitimate": {
                "window_sizes": dict(lg_wc.most_common()),
                "scaling_factors": dict(sorted(lg_sc.items())),
                "tuples": [{"window_size": w, "scaling_factor": s, "count": n} for (w, s), n in lg_tc.most_common()]
            }
        }

        meta_file = f"honeypot-{self.protocol}-metaanalysis.json"
        with open(meta_file, 'w') as f:
            json.dump(meta, f, indent=2)
        print(f"\n{'='*60}\nMeta-analysis saved to: {meta_file}\n{'='*60}\n")

if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] != '-P': sys.exit('Usage: python3 filter.py -P <protocol> <input.jsonl>')
    f = Filter(sys.argv[2])
    honeypot_out = f"suspicious-ips-{datetime.now():%Y-%m-%d}.jsonl"
    legit_out = f"legitimate-ips-{datetime.now():%Y-%m-%d}.jsonl"

    with open(sys.argv[3]) as i, open(honeypot_out, 'w') as h, open(legit_out, 'w') as l:
        for line in i:
            if line.strip():
                if f(json.loads(line)):
                    h.write(line)
                else:
                    l.write(line)

    print(f'{sys.argv[2].upper()} → Honeypots: {honeypot_out} | Legitimate: {legit_out}')
    f.stats()

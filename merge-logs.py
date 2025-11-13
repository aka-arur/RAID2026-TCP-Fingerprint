#!/usr/bin/env python3
"""Multi-protocol network log analyzer with atomic filtering
Usage: python3 merge-logs.py -P {modbus|s7comm|veeder-root|dnp3|iec104} window-ttl.jsonl zgrab_data.jsonl 5840 --pcap"""
import argparse, json, sys
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import IP, TCP, Raw, wrpcap
    SCAPY = True
except ImportError:
    SCAPY = False


class ProtocolClassifier:
    __slots__ = ()

    def classify(self, d): pass
    def response_types(self): pass
    def get_data_key(self): pass
    def get_default_port(self): pass


class ModbusClassifier(ProtocolClassifier):
    __slots__ = ()
    FILTER = "modbus: could not get response: EOF"

    def classify(self, d):
        if not d: return None
        s = d.get("status")
        if s == "unknown-error":
            return None if d.get("error") == self.FILTER else "unknown-error"
        return s if s in ("application-error", "success") and ("result" in d or s == "success") else None

    def response_types(self): return {"unknown-error", "application-error", "success"}
    def get_data_key(self): return "modbus"
    def get_default_port(self): return 502


class S7commClassifier(ProtocolClassifier):
    __slots__ = ()
    FILTER = frozenset({"HTTP", "SSH", "Got packets out of order", "login", "MaxStartups", "FTP", "SUCCESS",
                        "socket", "xml", "EMAIL", "VMware", "smtp", "mail", "Server", "ESMTP", "Unable", "authorized",
                        "proxy", "<HTML>", "<html>", "Content-Type", "server", "Login", "RFB", "RFJS", "connection",
                        "RTSP", "Request", "<body>", "MySQL", "Welcome", "Network", "Kerbero", "Cookie", "Website"
                        "JSON", "json", "java", "DNS", "whitelist", "IMAP", "HELO", "Hello", "nickname", "RTP"})

    def classify(self, d):
        if not d or d.get("status") != "success": return None
        r = d.get("result", {})
        b = r.get("banner", "")
        return "success" if r and b and not any(x in b for x in self.FILTER) else None

    def response_types(self): return {"success"}
    def get_data_key(self): return "banner"
    def get_default_port(self): return 102


class VeederRootClassifier(ProtocolClassifier):
    __slots__ = ()
    INCLUDE = frozenset({"TANK", "PRODUCT", "VOLUME", "ADBLUE", "DIESEL", "PREMIUM", "SUPER", "WATER", "TEMP", "GAS"})

    def classify(self, d):
        if not d or d.get("status") != "success": return None
        r = d.get("result", {})
        b = r.get("banner", "")
        return "success" if r and b and any(x in b for x in self.INCLUDE) else None

    def response_types(self): return {"success"}
    def get_data_key(self): return "banner"
    def get_default_port(self): return 10001


class DNP3Classifier(ProtocolClassifier):
    __slots__ = ()

    def classify(self, d):
        return "success" if d and d.get("status") == "success" else None

    def response_types(self): return {"success"}
    def get_data_key(self): return "dnp3"
    def get_default_port(self): return 20000


class IEC104commClassifier(ProtocolClassifier):
    __slots__ = ()
    FILTER = frozenset({"HTTP", "SSH", "Got packets out of order", "login", "MaxStartups", "FTP", "SUCCESS",
                        "socket", "xml", "EMAIL", "VMware", "smtp", "mail", "Server", "ESMTP", "Unable", "authorized",
                        "proxy", "<HTML>", "<html>", "Content-Type", "server", "Login", "RFB", "RFJS", "connection",
                        "RTSP", "Request", "<body>", "MySQL", "Welcome", "Network", "Kerbero", "Cookie", "Website"
                        "JSON", "json", "java", "DNS", "whitelist", "IMAP", "HELO", "Hello", "nickname", "RTP", "success",
                        "Authentication", "log", "CLIENT", "HELP", "\n", "http", "msg", "~djb"})

    def classify(self, d):
        if not d or d.get("status") != "success": return None
        r = d.get("result", {})
        b = r.get("banner", "")
        return "success" if r and b and not any(x in b for x in self.FILTER) else None

    def response_types(self): return {"success"}
    def get_data_key(self): return "banner"
    def get_default_port(self): return 2404


CLASSIFIERS = {
    "modbus": ModbusClassifier(),
    "s7comm": S7commClassifier(),
    "veeder-root": VeederRootClassifier(),
    "dnp3": DNP3Classifier(),
    "iec104": IEC104commClassifier(),
}


class NetworkDataAnalyzer:
    __slots__ = ('window_thr', 'protocol', 'classifier', 'gen_pcap')

    def __init__(self, window_thr, protocol, gen_pcap=False):
        if protocol not in CLASSIFIERS:
            raise ValueError(f"Unsupported protocol: {protocol}. Available: {list(CLASSIFIERS.keys())}")
        self.window_thr = window_thr
        self.protocol = protocol
        self.classifier = CLASSIFIERS[protocol]
        self.gen_pcap = gen_pcap
        if gen_pcap and not SCAPY:
            raise ImportError("Scapy required for pcap. Install: pip install scapy")

    def _load_zmap(self, path):
        zmap = {}
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if r.get("window", 0) > self.window_thr:
                        zmap[r["saddr"]] = r
                except: pass
        return zmap

    def _gen_filename(self):
        return f"{self.protocol}_{datetime.now():%Y%m%d_%H%M%S}_{self.window_thr}"

    def _get_freq(self, data, key):
        freq = Counter(r[key] for r in data.values() if key in r)
        return dict(freq.most_common())

    def _extract_payload(self, zgrab_rec):
        pdata = zgrab_rec.get("data", {}).get(self.classifier.get_data_key(), {})
        r = pdata.get("result", {})
        payload = r.get("banner") or pdata.get("error") or json.dumps(r or pdata, separators=(',', ':'))
        return payload.encode('utf-8', errors='ignore') if isinstance(payload, str) else payload

    def _create_packet(self, ip, zgrab_rec, port):
        return IP(src="10.0.0.1", dst=ip) / TCP(sport=12345, dport=port, flags='PA') / Raw(load=self._extract_payload(zgrab_rec))

    def process(self, zmap_file, zgrab_file):
        base = self._gen_filename()
        out_file = f"{base}.jsonl"
        pcap_file = f"{base}.pcap" if self.gen_pcap else None

        zmap = self._load_zmap(zmap_file)
        data_by_type = {rt: Counter() for rt in self.classifier.response_types()}
        pattern_ips = defaultdict(set)
        counts = {"total": 0, "by_type": {t: 0 for t in self.classifier.response_types()}}
        default_port = self.classifier.get_default_port()
        pkt_cnt = 0

        with open(zgrab_file, encoding="utf-8") as inf, open(out_file, 'w', encoding="utf-8") as outf:
            for line in inf:
                try:
                    zg = json.loads(line)
                    ip = zg.get("ip")
                    if ip not in zmap: continue

                    pdata = zg.get("data", {}).get(self.classifier.get_data_key())
                    rtype = self.classifier.classify(pdata)
                    if not rtype: continue

                    merged = {**zmap[ip], **zg}
                    data_str = json.dumps(zg["data"], sort_keys=True)
                    data_by_type[rtype][data_str] += 1
                    pattern_ips[data_str].add(ip)

                    outf.write(json.dumps(merged, separators=(",", ":")) + "\n")
                    counts["total"] += 1
                    counts["by_type"][rtype] += 1

                    if self.gen_pcap:
                        try:
                            wrpcap(pcap_file, self._create_packet(ip, zg, zg.get("port", default_port)), append=True)
                            pkt_cnt += 1
                        except Exception as e:
                            print(f"Warning: Packet creation failed for {ip}: {e}", file=sys.stderr)
                except: pass

        summary = self._write_meta(len(zmap), counts, data_by_type, pattern_ips, zmap, base)
        if self.gen_pcap:
            summary["pcap_file"] = pcap_file
            summary["pcap_packet_count"] = pkt_cnt
        return out_file, summary

    def _get_window_stats(self, ips, zmap):
        windows = [zmap[ip]["window"] for ip in ips if ip in zmap]
        if not windows:
            return {"window_sizes": [], "most_common_window": None, "window_count": 0}
        wc = Counter(windows)
        return {"window_sizes": sorted(set(windows)), "most_common_window": wc.most_common(1)[0][0], "window_count": len(windows)}

    def _write_meta(self, zmap_cnt, counts, data_by_type, pattern_ips, zmap, base):
        meta_file = f"{base}.meta.jsonl"
        tcp_freq = self._get_freq(zmap, "window")
        ttl_freq = self._get_freq(zmap, "ttl")

        summary = {
            "type": "summary",
            "protocol": self.protocol,
            "zmap_ips_count": zmap_cnt,
            "total_processed_entries": counts["total"],
            "response_type_distribution": counts["by_type"],
            "window_threshold": self.window_thr,
            "tcp_window_frequencies": tcp_freq,
            "ttl_frequencies": ttl_freq
        }

        with open(meta_file, 'w', encoding="utf-8") as mf:
            mf.write(json.dumps(summary, separators=(",", ":")) + "\n")
            for rtype, counter in data_by_type.items():
                for data_str, cnt in sorted(counter.items()):
                    ips = pattern_ips[data_str]
                    ws = self._get_window_stats(ips, zmap)
                    mf.write(json.dumps({
                        "type": rtype,
                        "data": json.loads(data_str),
                        "count": cnt,
                        "window_sizes": ws["window_sizes"],
                        "most_common_window": ws["most_common_window"],
                        "affected_ips": ws["window_count"]
                    }, separators=(",", ":")) + "\n")
        return summary


def main():
    p = argparse.ArgumentParser(description="Multi-protocol network analyzer")
    p.add_argument("zmap_file")
    p.add_argument("zgrab_file")
    p.add_argument("window_size", type=int)
    p.add_argument("-P", "--protocol", choices=["modbus", "s7comm", "veeder-root", "dnp3", "iec104"], default="modbus")
    p.add_argument("--pcap", action="store_true", help="Generate pcap for tshark analysis")
    args = p.parse_args()

    for path in [args.zmap_file, args.zgrab_file]:
        if not Path(path).is_file():
            print(f"Missing: {path}")
            sys.exit(1)

    analyzer = NetworkDataAnalyzer(args.window_size, args.protocol, args.pcap)
    out_file, meta = analyzer.process(args.zmap_file, args.zgrab_file)

    print(f"Generated: {out_file}")
    print(f"Processed: {meta['total_processed_entries']} entries")
    print(f"Metadata: {out_file.replace('.jsonl', '.meta.jsonl')}")
    print(f"TCP Windows: {len(meta['tcp_window_frequencies'])} unique")
    print(f"TTL Values: {len(meta['ttl_frequencies'])} unique")

    if args.pcap:
        print(f"PCAP File: {meta.get('pcap_file', 'N/A')}")
        print(f"PCAP Packets: {meta.get('pcap_packet_count', 0)}")

    for rt, cnt in meta["response_type_distribution"].items():
        if cnt: print(f"   {rt}: {cnt}")


if __name__ == "__main__":
    main()

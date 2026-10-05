"""PCAP parsing with pyshark (needs tshark installed). Pulls out the parts that
matter for crypto triage: TLS versions, cipher suites and SNI, DNS, conversations."""

from collections import Counter

MAX_PACKETS = 50_000


def parse(pcap):
    try:
        import pyshark
    except ImportError:
        return {"skipped": "pyshark not installed"}
    try:
        cap = pyshark.FileCapture(str(pcap), keep_packets=False)
    except Exception as e:
        return {"skipped": f"cannot open pcap: {e}"}

    convs, dns, sni, tls_versions, suites = Counter(), set(), set(), Counter(), Counter()
    try:
        for i, pkt in enumerate(cap):
            if i >= MAX_PACKETS:
                break
            if hasattr(pkt, "ip"):
                proto = pkt.transport_layer or pkt.highest_layer
                port = getattr(pkt[pkt.transport_layer], "dstport", "") if pkt.transport_layer else ""
                convs[(pkt.ip.src, pkt.ip.dst, proto, port)] += 1
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                dns.add(pkt.dns.qry_name)
            if hasattr(pkt, "tls"):
                t = pkt.tls
                if hasattr(t, "handshake_extensions_server_name"):
                    sni.add(t.handshake_extensions_server_name)
                if hasattr(t, "handshake_version"):
                    tls_versions[t.handshake_version] += 1
                if hasattr(t, "handshake_ciphersuite"):  # server's chosen suite
                    suites[t.handshake_ciphersuite.showname_value] += 1
    finally:
        cap.close()

    weak = [s for s in suites if any(w in s for w in ("RC4", "DES", "NULL", "EXPORT", "MD5"))]
    return {
        "conversations": [{"src": s, "dst": d, "proto": p, "dport": port, "packets": n}
                          for (s, d, p, port), n in convs.most_common(50)],
        "dns_queries": sorted(dns)[:200],
        "tls_sni": sorted(sni),
        "tls_versions": dict(tls_versions),
        "cipher_suites": dict(suites),
        "weak_cipher_suites": weak,
    }

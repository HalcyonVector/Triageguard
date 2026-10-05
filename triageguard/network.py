"""PCAP parsing with pyshark (needs tshark installed). Pulls out the parts that
matter for crypto triage: TLS versions, cipher suites and SNI, DNS, conversations."""

import asyncio
from collections import Counter

MAX_PACKETS = 50_000
TLS_NAMES = {"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3"}


def weak_tls(suites, versions):
    weak = {}
    for s in suites:
        if any(w in s for w in ("RC4", "_DES", "3DES", "NULL", "EXPORT", "MD5")):
            weak[s] = "broken or deprecated cipher"
        elif s.startswith("TLS_RSA_"):
            weak[s] = "static RSA key exchange, no forward secrecy (server RSA key in memory decrypts the traffic)"
        elif "_CBC_" in s:
            weak[s] = "CBC mode (padding oracle history), prefer AEAD"
    for v in versions:
        if v in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
            weak[v] = "deprecated protocol version"
    return weak


def parse(pcap):
    try:
        import pyshark
    except ImportError:
        return {"skipped": "pyshark not installed"}
    # pyshark 0.6 calls asyncio.get_event_loop(), which raises on Python 3.14+
    # when no loop is set, so give it one
    asyncio.set_event_loop(asyncio.new_event_loop())
    try:
        cap = pyshark.FileCapture(str(pcap), keep_packets=False)
    except Exception as e:
        return {"skipped": f"cannot open pcap: {e}"}

    convs, dns, sni, tls_versions, suites = Counter(), set(), set(), Counter(), Counter()
    try:
        for i, pkt in enumerate(cap):
            if i >= MAX_PACKETS:
                break
            if hasattr(pkt, "ip") and pkt.transport_layer in ("TCP", "UDP"):
                tl = pkt[pkt.transport_layer]
                sport, dport = int(tl.srcport), int(tl.dstport)
                # one row per conversation: client -> server on the lower (service) port
                if sport < dport:
                    convs[(pkt.ip.dst, pkt.ip.src, pkt.transport_layer, sport)] += 1
                else:
                    convs[(pkt.ip.src, pkt.ip.dst, pkt.transport_layer, dport)] += 1
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                dns.add(pkt.dns.qry_name)
            if hasattr(pkt, "tls"):
                t = pkt.tls
                if hasattr(t, "handshake_extensions_server_name"):
                    sni.add(t.handshake_extensions_server_name)
                types = t.get_field("handshake_type")
                # only the ServerHello says what was actually negotiated
                if types and any(f.show == "2" for f in types.all_fields):
                    # TLS 1.3 keeps 0x0303 in the legacy field; the real version is in an extension
                    ver = t.get_field_value("handshake_extensions_supported_version") or t.get_field_value("handshake_version")
                    tls_versions[TLS_NAMES.get(ver, ver)] += 1
                    suites[t.get_field("handshake_ciphersuite").showname_value] += 1
    finally:
        cap.close()

    return {
        "conversations": [{"client": c, "server": s, "proto": p, "port": port, "packets": n}
                          for (c, s, p, port), n in convs.most_common(50)],
        "dns_queries": sorted(dns)[:200],
        "tls_sni": sorted(sni),
        "tls_versions": dict(tls_versions),
        "cipher_suites": dict(suites),
        "weak_tls": weak_tls(suites, tls_versions),
    }

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

# Prüfen auf dnspython
try:
    import dns.message
    import dns.query
    import dns.flags
    import dns.rdatatype
except ImportError:
    print("⚠️ Das Modul ‚dnspython‘ fehlt.")
    print("   Bitte installieren Sie es mit:")
    print("     pip install dnspython")
    sys.exit(1)

import argparse
import hashlib
import re

def compute_sha256(iban: str) -> str:
    clean = re.sub(r'\s+', '', iban)
    return hashlib.sha256(clean.encode('utf-8')).hexdigest()

def query_txt(name: str, server: str = "8.8.8.8", timeout: float = 3.0):
    import dns.message, dns.query, dns.flags, dns.rdatatype
    q = dns.message.make_query(name, dns.rdatatype.TXT, want_dnssec=True)
    q.flags |= dns.flags.RD
    r = dns.query.udp(q, server, timeout=timeout)
    answers = []
    for rrset in r.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for item in rrset.items:
                txt = b''.join(item.strings).decode('utf-8')
                answers.append(txt)
    dnssec_ok = bool(r.flags & dns.flags.AD)
    return answers, dnssec_ok

def parse_record(txt: str) -> dict:
    parts = [p.strip() for p in txt.split(';')]
    return {k.strip().lower(): v.strip() for k,v in 
            (p.split('=',1) for p in parts if '=' in p)}

def main():
    parser = argparse.ArgumentParser(
        description="IBAN ⇄ DNS-Hash Checker mit DNSSEC-Prüfung"
    )
    parser.add_argument('-i', '--iban',   required=True, help="IBAN zum Prüfen")
    parser.add_argument('-d', '--domain', required=True, help="Domain mit den TXT-Records")
    parser.add_argument('-s', '--server', default="8.8.8.8",
                        help="DNS-Server (default: 8.8.8.8)")
    args = parser.parse_args()

    iban_hash = compute_sha256(args.iban)
    dnssec_flag = False
    match = None

    for idx in range(1, 11):
        label = "_iban" if idx == 1 else f"_iban{idx}"
        name  = f"{label}.{args.domain}"
        try:
            txts, ok = query_txt(name, args.server)
        except Exception as e:
            print(f"Fehler beim DNS-Lookup {name}: {e}", file=sys.stderr)
            continue
        dnssec_flag |= ok

        for txt in txts:
            rec = parse_record(txt)
            if rec.get('v') == '1' and rec.get('k') == 'sha256' \
               and rec.get('hash', '').lower() == iban_hash:
                match = rec
                break
        if match:
            break

    if match:
        if dnssec_flag:
            print("✅ Übertragung sicher und Hash vorhanden")
            code = 0
        else:
            print("⚠️ Hash stimmt, aber Übertragung unsicher (keine DNSSEC-Signatur)")
            code = 1
        print(f"Gefundener Record: v={match['v']}; k={match['k']}; hash={match['hash']}")
    else:
        print("❌ Kein passender Hash gefunden.")
        code = 2

    sys.exit(code)

if __name__ == "__main__":
    main()

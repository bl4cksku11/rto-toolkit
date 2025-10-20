#!/usr/bin/env python3
"""
parse_curl_domains_tlds.py

Purpose:
  Parse a curl command (stdin or argument) and extract only domains whose
  TLD (last label) appears in a provided/custom TLD list (to reduce false positives).

Features:
  - Accepts curl command via STDIN or as a CLI arg
  - Loads TLD set from a local file (--tld-file) or optionally fetches latest IANA list (--fetch-tlds)
  - Normalizes hosts (removes ports/userinfo)
  - Handles --resolve / --connect-to / -H Host: headers / --url etc.
  - Optional output: wildcard patterns (label.*) or a regex for scanners
  - Minimal dependencies (uses stdlib only)

Usage examples:
  # 1) read command from stdin and use a local tlds.txt
  echo "curl 'https://login.example.com' -H 'Host: api.exampletechnologies.net'" \
    | python3 parse_curl_domains_tlds.py --tld-file tlds.txt

  # 2) fetch latest IANA TLDs and save locally, then parse
  python3 parse_curl_domains_tlds.py --fetch-tlds --save-tlds tlds.txt \
    --cmd "curl https://cb.example.co.uk/path -H 'Host: example.exampletechnologies.io'"

  # 3) produce suggested wildcard patterns
  echo "curl https://login.example.com" \
    | python3 parse_curl_domains_tlds.py --tld-file tlds.txt --wildcards

"""
from __future__ import annotations
import sys, shlex, re, argparse, urllib.request, os
from urllib.parse import urlparse

IANA_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

DOMAIN_RE = re.compile(r'([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)')

def load_tlds_from_file(path: str) -> set[str]:
    tlds = set()
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            s = line.strip().lower()
            if not s or s.startswith('#'):
                continue
            tlds.add(s)
    return tlds

def fetch_iana_tlds() -> set[str]:
    """Fetch IANA TLD file and return lowercase set of TLDs (no comments)."""
    try:
        with urllib.request.urlopen(IANA_TLD_URL, timeout=15) as resp:
            txt = resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        raise RuntimeError(f"Failed to fetch IANA TLDs: {e}")
    tlds = set()
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        tlds.add(line.lower())
    return tlds

def normalize_host(netloc: str) -> str:
    # remove userinfo
    if '@' in netloc:
        netloc = netloc.split('@',1)[1]
    # strip brackets for IPv6
    netloc = netloc.strip('[]')
    # remove port
    netloc = netloc.split(':',1)[0]
    return netloc.lower()

def token_extract_domains(tokens: list[str]) -> set[str]:
    domains = set()
    i = 0
    while i < len(tokens):
        t = tokens[i]

        # direct URLs
        if t.startswith(('http://','https://')):
            try:
                p = urlparse(t)
                if p.netloc:
                    domains.add(normalize_host(p.netloc))
            except Exception:
                pass

        # --url / -I style next-token URLs
        if t in ('--url','--url*','-I','--head') and i+1 < len(tokens):
            u = tokens[i+1]
            if u.startswith(('http://','https://')):
                try:
                    domains.add(normalize_host(urlparse(u).netloc))
                except Exception:
                    pass
            i += 1

        # Headers
        if t in ('-H','--header') and i+1 < len(tokens):
            hdr = tokens[i+1]
            m = re.search(r'Host\s*:\s*([^;,\s"\']+)', hdr, re.IGNORECASE)
            if m:
                domains.add(normalize_host(m.group(1)))
            else:
                for d in DOMAIN_RE.findall(hdr):
                    domains.add(normalize_host(d))
            i += 1

        # --resolve: host:port:addr (can be comma separated)
        if t == '--resolve' and i+1 < len(tokens):
            val = tokens[i+1]
            for part in re.split(r'\s*,\s*', val):
                host = part.split(':',1)[0]
                if host:
                    domains.add(normalize_host(host))
            i += 1

        # --connect-to: host:port:targethost:targetport OR similar
        if t == '--connect-to' and i+1 < len(tokens):
            val = tokens[i+1]
            for part in re.split(r'\s*,\s*', val):
                host = part.split(':',1)[0]
                if host:
                    domains.add(normalize_host(host))
            i += 1

        # generic domain-like substrings in token
        for d in DOMAIN_RE.findall(t):
            domains.add(normalize_host(d))

        i += 1

    return domains

def filter_by_tlds(domains: set[str], tlds: set[str]) -> set[str]:
    """Keep only domains whose last label is in tlds set.
       Also handle IDN punycode 'xn--' (match last label after punycode).
    """
    out = set()
    for d in domains:
        if not d:
            continue
        parts = d.rsplit('.', maxsplit=2)  # keep up to 3 parts for safety
        last = parts[-1].lower()
        if last in tlds:
            out.add(d)
        else:
            # sometimes domains are given as punycode IDN; try to decode last label
            # but decoding requires 'idna' codec: builtin supports it via .encode/.decode
            if last.startswith('xn--'):
                try:
                    # decode the domain fully and re-evaluate
                    decoded = d.encode('utf-8').decode('idna')
                    last_decoded = decoded.rsplit('.', maxsplit=1)[-1].lower()
                    if last_decoded in tlds:
                        out.add(d)  # keep original (or could add decoded)
                except Exception:
                    pass
    return out

def suggest_wildcards(domains: set[str]) -> list[str]:
    """Simple suggested wildcard patterns from domains:
       - uses second-level label (left of last dot) as label.*
       - example: login.example.com -> example.*
    """
    labels = set()
    for d in domains:
        parts = d.split('.')
        if len(parts) >= 2:
            labels.add(parts[-2])
        else:
            labels.add(parts[0])
    return sorted(f"{lbl}.*" for lbl in labels)

def build_regex_for_label(label: str) -> str:
    """Return a regex snippet to match subdomains and the label in any TLD:
       e.g. for 'example' -> r'(^|\.)example\.[A-Za-z0-9.-]+$'
       (useful for IDS/wildcard-style matching)
    """
    esc = re.escape(label)
    return rf'(^|\.){esc}\.[A-Za-z0-9.-]+$'

def main():
    ap = argparse.ArgumentParser(description="Parse curl and extract domains filtered by TLD list")
    ap.add_argument('--cmd', help='curl command as single argument (if omitted, read stdin)')
    ap.add_argument('--tld-file', help='path to newline-separated tld list (lowercase preferred)')
    ap.add_argument('--fetch-tlds', action='store_true', help='fetch latest IANA TLD list (requires network)')
    ap.add_argument('--save-tlds', metavar='PATH', help='save fetched tlds to PATH (if --fetch-tlds used)')
    ap.add_argument('--wildcards', action='store_true', help='print suggested wildcard patterns (label.*)')
    ap.add_argument('--regexes', action='store_true', help='print per-label regex patterns')
    ap.add_argument('--show-all', action='store_true', help='show all matched domains (default)')
    args = ap.parse_args()

    # Read curl command
    if args.cmd:
        curl_cmd = args.cmd
    else:
        curl_cmd = sys.stdin.read().strip()

    if not curl_cmd:
        print("Provide a curl command via --cmd or stdin. See --help.")
        sys.exit(1)

    # Load TLDs
    tlds = set()
    if args.fetch_tlds:
        try:
            print("# fetching IANA TLD list...", file=sys.stderr)
            tlds = fetch_iana_tlds()
            print(f"# fetched {len(tlds)} tlds", file=sys.stderr)
            if args.save_tlds:
                with open(args.save_tlds, 'w', encoding='utf-8') as fh:
                    for t in sorted(tlds):
                        fh.write(t + "\n")
                print(f"# saved tlds to {args.save_tlds}", file=sys.stderr)
        except Exception as e:
            print(f"Error fetching TLDs: {e}", file=sys.stderr)
            if not args.tld_file:
                sys.exit(1)

    if args.tld_file:
        if not os.path.exists(args.tld_file):
            print(f"Error: tld file not found: {args.tld_file}", file=sys.stderr)
            sys.exit(1)
        tlds_from_file = load_tlds_from_file(args.tld_file)
        tlds.update(tlds_from_file)

    if not tlds:
        print("No TLDs available. Provide --tld-file or --fetch-tlds.", file=sys.stderr)
        sys.exit(1)

    # split tokens
    try:
        tokens = shlex.split(curl_cmd)
    except Exception:
        tokens = curl_cmd.split()

    found = token_extract_domains(tokens)
    filtered = filter_by_tlds(found, tlds)

    if args.show_all or not (args.wildcards or args.regexes):
        print("# Matched domains (TLD filtered):")
        if filtered:
            for d in sorted(filtered):
                print(d)
        else:
            print("# (none)")

    if args.wildcards:
        print("\n# Suggested wildcard patterns (label.*):")
        for w in suggest_wildcards(filtered):
            print(w)

    if args.regexes:
        print("\n# Per-label regex patterns:")
        for lbl in sorted({d.split('.')[-2] for d in filtered if '.' in d}):
            print(build_regex_for_label(lbl))

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from contextlib import nullcontext
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple
try:
    import requests
except ImportError:
    print('[!] Missing dependency. Run: pip install requests')
    sys.exit(1)
try:
    from rich.console import Console
    from rich.table import Table
    from rich.tree import Tree
    from rich.text import Text
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = Table = Tree = Text = Panel = None
    box = None
try:
    import mmh3
    HAVE_MMH3 = True
except ImportError:
    HAVE_MMH3 = False
try:
    from jarm.scanner.scanner import Scanner as JarmScanner
    HAVE_JARM = True
except ImportError:
    HAVE_JARM = False
requests.packages.urllib3.disable_warnings()
console = Console() if RICH_AVAILABLE else None
QUIET = False
DEFAULT_TIMEOUT = 5
DEFAULT_C2_DB_PATH = 'c2_signatures.json'
MAX_HEATMAP_HOSTS = 20

def output_notice(message: str) -> None:
    if QUIET:
        return
    if console:
        console.print(message)
    else:
        print(re.sub(r'\[/?(?:yellow|red|green|dim|bold)[^]]*\]', '', message))

def socket_host(host: str) -> str:
    host = host.strip()
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    return host.replace('%25', '%')

def url_host(host: str) -> str:
    host = socket_host(host)
    address = host.split('%', 1)[0]
    try:
        if ipaddress.ip_address(address).version == 6:
            return f'[{host.replace("%", "%25")}]'
    except ValueError:
        pass
    return host

def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(socket_host(host).split('%', 1)[0])
        return True
    except ValueError:
        return False

def parse_ports(value: str) -> Tuple[int, int, int]:
    try:
        ports = tuple(int(part.strip()) for part in value.split(','))
    except ValueError as exc:
        raise argparse.ArgumentTypeError('ports must be three comma-separated integers: SSH,HTTP,HTTPS') from exc
    if len(ports) != 3 or any(port < 1 or port > 65535 for port in ports):
        raise argparse.ArgumentTypeError('ports must be three values in the range 1-65535: SSH,HTTP,HTTPS')
    return ports

@dataclass
class HostFingerprint:
    host: str
    ssh_port_open: bool = False
    ssh_banner: str = ''
    http_port_open: bool = False
    http_status: str = ''
    http_server_header: str = ''
    http_headers_hash: str = ''
    http_body_hash: str = ''
    http_body_snippet: str = ''
    http_meta_tags: List[str] = field(default_factory=list)
    https_port_open: bool = False
    tls_cert_subject: str = ''
    tls_cert_issuer: str = ''
    favicon_hash: str = ''
    favicon_mmh3: str = ''
    jarm: str = ''
    c2_matches: List[str] = field(default_factory=list)
    risk_score: int = 0
    error_notes: List[str] = field(default_factory=list)

    def combined_fingerprint(self) -> str:
        parts = [self.ssh_banner.strip(), self.http_server_header.strip(), self.http_headers_hash, self.favicon_hash, self.http_body_hash, self.jarm.strip()]
        return '|'.join(parts)

    def export_dict(self) -> dict:
        d = asdict(self)
        d.pop('http_body_snippet', None)
        return d

def grab_ssh_banner(host: str, port: int=22, timeout: float=DEFAULT_TIMEOUT) -> Tuple[bool, str, str]:
    try:
        with socket.create_connection((socket_host(host), port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256).decode(errors='ignore').strip()
            return (True, banner, '')
    except Exception as e:
        return (False, '', str(e))

def grab_http_info(host: str, port: int=80, use_https: bool=False, timeout: float=DEFAULT_TIMEOUT, deep: bool=False) -> Tuple[bool, str, str, str, str, str, List[str], str]:
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{url_host(host)}:{port}/'
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        header_keys = sorted((k.lower() for k in r.headers.keys()))
        headers_hash = hashlib.sha256('|'.join(header_keys).encode()).hexdigest()[:16]
        server_header = r.headers.get('Server', '')
        body_hash = ''
        body_snippet = ''
        meta_tags: List[str] = []
        if deep and r.content:
            sample = r.content[:20000]
            body_hash = hashlib.sha256(sample).hexdigest()[:16]
            text_sample = r.text[:20000] if r.text else ''
            body_snippet = text_sample[:500]
            meta_tags = re.findall('<(?:meta|title)[^>]*>.*?(?:</title>)?', text_sample, re.IGNORECASE)[:10]
        return (True, str(r.status_code), server_header, headers_hash, body_hash, body_snippet, meta_tags, '')
    except Exception as e:
        return (False, '', '', '', '', '', [], str(e))

def grab_tls_cert_info(host: str, port: int=443, timeout: float=DEFAULT_TIMEOUT) -> Tuple[bool, str, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        normalized_host = socket_host(host)
        with socket.create_connection((normalized_host, port), timeout=timeout) as sock:
            server_name = None if is_ip_address(normalized_host) else normalized_host
            with ctx.wrap_socket(sock, server_hostname=server_name) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                der = ssock.getpeercert(binary_form=True)
                der_hash = hashlib.sha256(der).hexdigest()[:16] if der else ''
                subject = str(cert.get('subject', '')) if cert else ''
                issuer = str(cert.get('issuer', '')) if cert else ''
                return (True, subject or der_hash, issuer)
    except Exception:
        return (False, '', '')

def grab_favicon_hash(host: str, use_https: bool=False, timeout: float=DEFAULT_TIMEOUT, port: Optional[int]=None) -> Tuple[str, str]:
    scheme = 'https' if use_https else 'http'
    url = f'{scheme}://{url_host(host)}:{port or (443 if use_https else 80)}/favicon.ico'
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        if r.status_code == 200 and r.content:
            md5_hash = hashlib.md5(r.content).hexdigest()
            mmh3_hash = ''
            if HAVE_MMH3:
                b64 = base64.encodebytes(r.content)
                mmh3_hash = str(mmh3.hash(b64))
            return (md5_hash, mmh3_hash)
    except Exception:
        pass
    return ('', '')

def grab_jarm(host: str, port: int=443, timeout: float=DEFAULT_TIMEOUT) -> str:
    if not HAVE_JARM:
        return ''
    try:
        jarm_value, _, _ = JarmScanner.scan(socket_host(host), port, timeout=int(timeout))
        if jarm_value and set(jarm_value) != {'0'}:
            return jarm_value
    except Exception:
        pass
    return ''

def scan_host(host: str, deep: bool=False, timeout: float=DEFAULT_TIMEOUT, do_jarm: bool=False, ssh_port: int=22, http_port: int=80, https_port: int=443) -> HostFingerprint:
    fp = HostFingerprint(host=host)
    ok, banner, err = grab_ssh_banner(host, port=ssh_port, timeout=timeout)
    fp.ssh_port_open = ok
    fp.ssh_banner = banner
    if err:
        fp.error_notes.append(f'ssh: {err}')
    ok, status, server, hhash, bhash, bsnippet, meta, err = grab_http_info(host, port=http_port, use_https=False, timeout=timeout, deep=deep)
    fp.http_port_open = ok
    fp.http_status = status
    fp.http_server_header = server
    fp.http_headers_hash = hhash
    fp.http_body_hash = bhash
    fp.http_body_snippet = bsnippet
    fp.http_meta_tags = meta
    if err:
        fp.error_notes.append(f'http: {err}')
    ok, subject, issuer = grab_tls_cert_info(host, port=https_port, timeout=timeout)
    fp.https_port_open = ok
    fp.tls_cert_subject = subject
    fp.tls_cert_issuer = issuer
    fp.favicon_hash, fp.favicon_mmh3 = grab_favicon_hash(host, use_https=fp.https_port_open, timeout=timeout, port=https_port if fp.https_port_open else http_port)
    if do_jarm:
        if fp.https_port_open:
            fp.jarm = grab_jarm(host, port=https_port, timeout=timeout)
        if not fp.jarm:
            fp.error_notes.append(f'jarm: no completed TLS handshake on {https_port}, or jarm package missing')
    return fp

def load_targets(arg: str) -> List[str]:
    if os.path.isfile(arg):
        with open(arg, 'r') as f:
            return [line.strip() for line in f if line.strip() and (not line.startswith('#'))]
    return [h.strip() for h in arg.split(',') if h.strip()]
DEFAULT_C2_SIGNATURES: Dict[str, dict] = {'Cobalt Strike (possible, heuristic)': {'description': "Cobalt Strike HTTP profiles and certificates are configurable, and generic missing headers or 404 pages are not reliable indicators. Add current, sourced HTTP and JARM indicators; min_matches requires corroboration across distinct indicator types. A match remains a lead, not attribution.", 'http_server_equals': [], 'body_contains': [], 'favicon_hash_in': [], 'jarm_in': [], 'min_matches': 2, 'weight': 2}, 'Sliver C2 (possible, heuristic)': {'description': "Sliver's default self-signed certificates have historically used generic/placeholder subject fields. Check tls_cert_subject manually against current community IOC lists before trusting this.", 'tls_subject_contains': [], 'favicon_hash_in': [], 'jarm_in': [], 'weight': 2}, 'Metasploit handler (possible, heuristic)': {'description': 'Metasploit HTTP(S) handlers can present very minimal, templated responses. This entry is intentionally conservative and will rarely fire without you adding current indicators.', 'http_header_hash_in': [], 'jarm_in': [], 'weight': 1}, 'Mythic C2 (possible, heuristic)': {'description': 'Mythic agent profiles are highly customizable; add known hashes/headers here as you observe them in your own engagements.', 'favicon_hash_in': [], 'http_header_hash_in': [], 'jarm_in': [], 'weight': 2}, 'Generic exposed admin/login panel': {'description': 'Broad heuristic: title/meta content suggesting an exposed admin or login panel worth manual review (not necessarily malicious).', 'meta_contains': ['admin', 'login', 'dashboard'], 'weight': 1}}

def ensure_c2_db(path: str) -> Dict[str, dict]:
    if not os.path.exists(path):
        with open(path, 'w') as f:
            json.dump(DEFAULT_C2_SIGNATURES, f, indent=2)
        output_notice(f"[yellow][*] No signature DB found — created starter file at '{path}'. Edit it to add your own indicators.[/yellow]")
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        output_notice(f"[red][!] Failed to load '{path}': {e}. Using built-in defaults instead.[/red]")
        return DEFAULT_C2_SIGNATURES

def match_c2_signatures(fp: HostFingerprint, db: Dict[str, dict]) -> Tuple[List[str], int]:
    matches: List[str] = []
    score = 0
    for name, sig in db.items():
        hits = 0
        hits += int(any(p and p.lower() in fp.ssh_banner.lower() for p in sig.get('ssh_banner_contains', [])))
        hits += int(bool(fp.http_server_header and fp.http_server_header in sig.get('http_server_equals', [])))
        hits += int(bool(fp.http_headers_hash and fp.http_headers_hash in sig.get('http_header_hash_in', [])))
        hits += int(bool(fp.favicon_hash and fp.favicon_hash in sig.get('favicon_hash_in', [])))
        hits += int(any(p and p.lower() in fp.tls_cert_subject.lower() for p in sig.get('tls_subject_contains', [])))
        hits += int(bool(fp.jarm and fp.jarm in sig.get('jarm_in', [])))
        hits += int(any(p and p.lower() in fp.http_body_snippet.lower() for p in sig.get('body_contains', [])))
        hits += int(any(p and any(p.lower() in m.lower() for m in fp.http_meta_tags) for p in sig.get('meta_contains', [])))
        if hits >= max(1, int(sig.get('min_matches', 1))):
            matches.append(name)
            score += int(sig.get('weight', 1))
    return (matches, score)
CORRELATION_WEIGHTS = {'favicon_hash': 4, 'http_body_hash': 3, 'ssh_banner': 3, 'jarm': 2, 'http_headers_hash': 2, 'http_server_header': 2, 'tls_cert_subject': 2, 'tls_cert_issuer': 1}
FIELD_LABELS = {'favicon_hash': 'Identical favicon hash', 'http_body_hash': 'Identical HTTP body hash', 'ssh_banner': 'Identical SSH banner', 'jarm': 'Identical JARM (same TLS stack behavior)', 'http_headers_hash': 'Identical HTTP header-set', 'http_server_header': "Identical HTTP 'Server' header", 'tls_cert_subject': 'Identical TLS certificate subject', 'tls_cert_issuer': 'Identical TLS certificate issuer'}

def pairwise_correlation(a: HostFingerprint, b: HostFingerprint) -> Tuple[int, List[str], List[str]]:
    score = 0
    reasons: List[str] = []
    matched_fields: List[str] = []
    for field_name, weight in CORRELATION_WEIGHTS.items():
        val_a = getattr(a, field_name, '')
        val_b = getattr(b, field_name, '')
        if val_a and val_b and (val_a == val_b):
            score += weight
            reasons.append(f"{FIELD_LABELS[field_name]} ('{val_a}')")
            matched_fields.append(field_name)
    shared_c2 = set(a.c2_matches) & set(b.c2_matches)
    if shared_c2:
        score += 2 * len(shared_c2)
        reasons.append(f"Shared possible C2 indicator(s): {', '.join(shared_c2)}")
        matched_fields.append('c2_signature')
    return (score, reasons, matched_fields)

def confidence_label(distinct_layer_count: int) -> Tuple[str, str]:
    if distinct_layer_count >= 3:
        return ('HIGH', 'bold red')
    if distinct_layer_count == 2:
        return ('MEDIUM', 'yellow')
    if distinct_layer_count == 1:
        return ('LOW', 'cyan')
    return ('NONE', 'dim')

class UnionFind:

    def __init__(self, items: List[str]):
        self.parent = {item: item for item in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = (self.find(a), self.find(b))
        if ra != rb:
            self.parent[ra] = rb

def compute_pairs(results: List[HostFingerprint]) -> List[Tuple[int, str, str, List[str], List[str]]]:
    usable = [fp for fp in results if fp.combined_fingerprint().replace('|', '')]
    pairs = []
    for i in range(len(usable)):
        for j in range(i + 1, len(usable)):
            score, reasons, matched_fields = pairwise_correlation(usable[i], usable[j])
            if score > 0:
                pairs.append((score, usable[i].host, usable[j].host, reasons, matched_fields))
    pairs.sort(key=lambda p: p[0], reverse=True)
    return pairs

def risk_style(score: int) -> str:
    if score >= 4:
        return 'bold red'
    if score >= 2:
        return 'yellow'
    if score > 0:
        return 'cyan'
    return 'dim'

def print_summary_table(results: List[HostFingerprint], match_c2: bool) -> None:
    table = Table(title='Host Fingerprint Summary', box=box.ROUNDED, show_lines=False)
    table.add_column('Host', style='bold')
    table.add_column('SSH Banner', overflow='fold')
    table.add_column('HTTP Server', overflow='fold')
    table.add_column('Favicon (md5)', overflow='fold')
    table.add_column('Favicon (Shodan mmh3)', overflow='fold')
    table.add_column('JARM', overflow='fold')
    table.add_column('TLS Subject', overflow='fold')
    if match_c2:
        table.add_column('Risk', justify='right')
        table.add_column('Possible Indicators', overflow='fold')
    for fp in results:
        row = [fp.host, fp.ssh_banner or '-', fp.http_server_header or '-', fp.favicon_hash[:12] + '…' if fp.favicon_hash else '-', fp.favicon_mmh3 or '-', fp.jarm[:20] + '…' if fp.jarm else '-', fp.tls_cert_subject[:30] + '…' if len(fp.tls_cert_subject) > 30 else fp.tls_cert_subject or '-']
        if match_c2:
            row.append(Text(str(fp.risk_score), style=risk_style(fp.risk_score)))
            row.append(', '.join(fp.c2_matches) if fp.c2_matches else '-')
        table.add_row(*row)
    console.print(table)

def print_correlation_list(pairs: List[Tuple[int, str, str, List[str], List[str]]], threshold: int) -> None:
    table = Table(title=f'Pairwise Correlation (clustering threshold = {threshold})', box=box.SIMPLE_HEAVY)
    table.add_column('Host A')
    table.add_column('Host B')
    table.add_column('Score', justify='right')
    table.add_column('Confidence')
    table.add_column('Matched Attributes', overflow='fold')
    table.add_column('Status')
    if not pairs:
        console.print(Panel('No two hosts shared any fingerprint attribute.', title='Correlation'))
        return
    for score, h1, h2, reasons, matched_fields in pairs:
        status = Text('CLUSTERED', style='bold red') if score >= threshold else Text('weak overlap', style='dim')
        label, style = confidence_label(len(set(matched_fields)))
        table.add_row(h1, h2, Text(str(score), style=risk_style(score)), Text(label, style=style), '; '.join(reasons), status)
    console.print(table)

def print_heatmap(results: List[HostFingerprint], threshold: int) -> None:
    usable = [fp for fp in results if fp.combined_fingerprint().replace('|', '')]
    if len(usable) < 2:
        return
    if len(usable) > MAX_HEATMAP_HOSTS:
        console.print(Panel(f'Skipping heatmap matrix: {len(usable)} hosts exceeds the readable limit ({MAX_HEATMAP_HOSTS}). See the pairwise correlation table above, or inspect the --csv/--json export instead.', title='Correlation Heatmap', style='dim'))
        return
    score_matrix: Dict[Tuple[str, str], int] = {}
    for i, a in enumerate(usable):
        for j, b in enumerate(usable):
            if i == j:
                continue
            score, _, _ = pairwise_correlation(a, b)
            score_matrix[a.host, b.host] = score
    table = Table(title='Correlation Heatmap (row vs column, score)', box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column('')
    for b in usable:
        table.add_column(b.host[-12:], justify='center')
    for a in usable:
        row = [Text(a.host[-14:], style='bold')]
        for b in usable:
            if a.host == b.host:
                row.append(Text('·', style='dim'))
                continue
            s = score_matrix[a.host, b.host]
            style = risk_style(s if s < threshold else max(s, 4))
            row.append(Text(str(s) if s else '-', style=style))
        table.add_row(*row)
    console.print(table)

def print_cluster_tree(results: List[HostFingerprint], pairs: List[Tuple[int, str, str, List[str], List[str]]], threshold: int) -> None:
    usable = [fp for fp in results if fp.combined_fingerprint().replace('|', '')]
    hosts = [fp.host for fp in usable]
    adjacency: Dict[str, List[Tuple[str, int, List[str], List[str]]]] = defaultdict(list)
    uf = UnionFind(hosts)
    for score, h1, h2, reasons, matched_fields in pairs:
        if score >= threshold:
            adjacency[h1].append((h2, score, reasons, matched_fields))
            adjacency[h2].append((h1, score, reasons, matched_fields))
            uf.union(h1, h2)
    groups: Dict[str, List[str]] = defaultdict(list)
    for h in hosts:
        groups[uf.find(h)].append(h)
    clusters = {root: members for root, members in groups.items() if len(members) > 1}
    if not clusters:
        console.print(Panel('No clusters formed at this threshold. Try a lower --threshold.', title='Auto-Clustered Groups', style='dim'))
        return
    root_tree = Tree('[bold]Auto-Clustered Groups[/bold] (transitive correlation)')
    for idx, (root, members) in enumerate(clusters.items(), 1):
        cluster_layer_types: set = set()
        for h in members:
            for neighbor, score, reasons, matched_fields in adjacency[h]:
                if neighbor in members:
                    cluster_layer_types.update(matched_fields)
        label, style = confidence_label(len(cluster_layer_types))
        cluster_node = root_tree.add(f'[bold magenta]Cluster {idx}[/bold magenta] ({len(members)} hosts) — Confidence: [{style}]{label}[/{style}] ({len(cluster_layer_types)} independent layer(s) agree)')
        visited = {members[0]}
        queue = deque([members[0]])
        node_map = {members[0]: cluster_node.add(f'[bold]{members[0]}[/bold] (root)')}
        while queue:
            current = queue.popleft()
            for neighbor, score, reasons, matched_fields in adjacency[current]:
                if neighbor not in visited and neighbor in members:
                    visited.add(neighbor)
                    label2 = f'[bold]{neighbor}[/bold]  (score {score} <- {current})'
                    neighbor_node = node_map[current].add(label2)
                    for r in reasons:
                        neighbor_node.add(f'[dim]{r}[/dim]')
                    node_map[neighbor] = neighbor_node
                    queue.append(neighbor)
    console.print(root_tree)
    console.print(Panel('Confidence reflects how many INDEPENDENT fingerprint layers agree within a cluster (Chapter 8 of the source methodology: a ladder, not a switch). LOW = one layer, worth a second look. MEDIUM = two layers, worth active monitoring. HIGH = three or more layers, still not proof - validate with a live malware sample or sandbox report before treating any host as confirmed malicious.', title='How to read confidence', style='dim'))

def export_csv(results: List[HostFingerprint], path: str) -> None:
    rows = [fp.export_dict() for fp in results]
    if not rows:
        return
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            row = dict(row)
            row['error_notes'] = '; '.join(row.get('error_notes', []))
            row['http_meta_tags'] = '; '.join(row.get('http_meta_tags', []))
            row['c2_matches'] = '; '.join(row.get('c2_matches', []))
            writer.writerow(row)
    output_notice(f'[green][+] CSV saved to {path}[/green]')

def export_json(results: List[HostFingerprint], path: str) -> None:
    with open(path, 'w') as f:
        json.dump([fp.export_dict() for fp in results], f, indent=2)
    output_notice(f'[green][+] JSON saved to {path}[/green]')

def main() -> None:
    global QUIET
    parser = argparse.ArgumentParser(description='SSH & HTTP Banner/Fingerprint Collector with C2 correlation and rich visual output', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--targets', required=True, help='Comma-separated hosts OR path to a file with one host per line')
    parser.add_argument('--threads', type=int, default=10, help='Concurrent scan threads (default: 10)')
    parser.add_argument('--ports', type=parse_ports, default=(22, 80, 443), metavar='SSH,HTTP,HTTPS', help='SSH, HTTP, and HTTPS ports (default: 22,80,443)')
    parser.add_argument('--delay', type=float, default=0.0, help='Seconds to wait between launching host scans (default: 0)')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help=f'Per-connection timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--threshold', type=int, default=3, help='Minimum correlation score for two hosts to be auto-clustered (default: 3)')
    parser.add_argument('--deep-scan', action='store_true', help='Fetch HTTP body + meta tags for stronger, lower-false-positive correlation')
    parser.add_argument('--jarm', action='store_true', help='Run an active JARM TLS fingerprint probe against port 443 on each host (10 extra TLS connections per host - slower). Requires: pip install pyjarm')
    parser.add_argument('--match-c2', action='store_true', help='Match fingerprints against the heuristic C2 signature database')
    parser.add_argument('--c2-db', default=DEFAULT_C2_DB_PATH, help=f'Path to the C2 signature JSON file (default: {DEFAULT_C2_DB_PATH})')
    parser.add_argument('--csv', help='Optional path to save results as CSV')
    parser.add_argument('--json', help='Optional path to save results as JSON')
    parser.add_argument('--quiet', '--no-rich', dest='quiet', action='store_true', help='Disable Rich output and print only a JSON array to stdout')
    args = parser.parse_args()
    if args.threads < 1:
        parser.error('--threads must be at least 1')
    if args.delay < 0:
        parser.error('--delay must be non-negative')
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    QUIET = args.quiet or not RICH_AVAILABLE
    targets = load_targets(args.targets)
    if not targets:
        print('[!] No targets loaded.', file=sys.stderr)
        sys.exit(1)
    if args.jarm and (not HAVE_JARM):
        print('[!] --jarm requires the pyjarm package. Run: pip install pyjarm', file=sys.stderr)
        sys.exit(1)
    if not HAVE_MMH3:
        output_notice('[dim][*] Note: mmh3 not installed, Shodan-style favicon hashes will be blank. Run: pip install mmh3[/dim]')
    if not QUIET:
        console.print(Panel(f'Scanning {len(targets)} host(s). Deep scan: {args.deep_scan} | JARM: {args.jarm} | C2 matching: {args.match_c2} | Threshold: {args.threshold} | Ports: {args.ports}\n[yellow]Only scan systems you are explicitly authorized to test.[/yellow]', title='infra-scout', style='bold green'))
    c2_db = ensure_c2_db(args.c2_db) if args.match_c2 else {}
    results: List[HostFingerprint] = []
    status = console.status('[bold green]Scanning hosts...') if not QUIET else nullcontext()
    with status:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_map = {}
            for index, host in enumerate(targets):
                if index and args.delay:
                    time.sleep(args.delay)
                future = executor.submit(scan_host, host, args.deep_scan, args.timeout, args.jarm, *args.ports)
                future_map[future] = host
            for future in as_completed(future_map):
                host = future_map[future]
                try:
                    fp = future.result()
                    if args.match_c2:
                        matches, score = match_c2_signatures(fp, c2_db)
                        fp.c2_matches = matches
                        fp.risk_score = score
                    results.append(fp)
                except Exception as e:
                    print(f'[!] Error scanning {host}: {e}', file=sys.stderr)
    results.sort(key=lambda r: r.host)
    if QUIET:
        json.dump([fp.export_dict() for fp in results], sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        print_summary_table(results, match_c2=args.match_c2)
        pairs = compute_pairs(results)
        print_correlation_list(pairs, args.threshold)
        print_heatmap(results, args.threshold)
        print_cluster_tree(results, pairs, args.threshold)
    if args.csv:
        export_csv(results, args.csv)
    if args.json:
        export_json(results, args.json)
if __name__ == '__main__':
    main()
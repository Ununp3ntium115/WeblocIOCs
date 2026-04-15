#!/usr/bin/env python3
import csv
import ipaddress
import re
from pathlib import Path

SRC = Path('data/source_article_iocs.txt')
OUT_CSV = Path('data/master_indicators.csv')
OUT_FLAT = Path('data/indicators_flat.csv')
IP_TXT = Path('blocklists/ip_blacklist.txt')
IP_CSV = Path('blocklists/ip_blacklist.csv')
DNS_TXT = Path('blocklists/dns_blacklist.txt')
COMBINED_TXT = Path('blocklists/combined_blacklist.txt')

SECTION_MAP = {
    'Other Hosts Related to Potential Cobwebs Product Servers': 'other_potential_product_servers',
    'Subdomains Related to Cobwebs’ Wider Server Infrastructure': 'wider_infrastructure_subdomains',
    "Other Hosts Related to Cobwebs’ Wider Server Infrastructure": 'other_wider_infrastructure_hosts',
    'Trapdoor Login Page and Javascript Code': 'trapdoor_login_page_and_javascript',
}


def parse_line(raw: str):
    line = raw.strip()
    if not line:
        return None
    if line.startswith('List of '):
        return None
    if line in SECTION_MAP:
        return ('__section__', line)

    asterisk = ' (*)' in line
    line_clean = line.replace(' (*)', '').strip()

    if '/' in line_clean and re.search(r'\d+\.\d+\.\d+\.\d+:\d+/', line_clean):
        head, path = line_clean.split('/', 1)
        ip, port = head.split(':', 1)
        return {
            'indicator': line_clean,
            'type': 'url_path_on_ip_port',
            'host_or_ip': ip,
            'port': port,
            'path': '/' + path,
            'asterisk_login_page': asterisk,
        }

    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}:\d+', line_clean):
        ip, port = line_clean.split(':', 1)
        return {
            'indicator': line_clean,
            'type': 'ip_port',
            'host_or_ip': ip,
            'port': port,
            'path': '',
            'asterisk_login_page': asterisk,
        }

    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', line_clean):
        return {
            'indicator': line_clean,
            'type': 'ip',
            'host_or_ip': line_clean,
            'port': '',
            'path': '',
            'asterisk_login_page': asterisk,
        }

    if re.fullmatch(r'[a-z0-9][a-z0-9.-]*\.[a-z]{2,}', line_clean):
        return {
            'indicator': line_clean,
            'type': 'domain',
            'host_or_ip': line_clean,
            'port': '',
            'path': '',
            'asterisk_login_page': asterisk,
        }

    return None


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def main():
    rows = []
    section = 'potential_product_server_subdomains'

    for raw in SRC.read_text(encoding='utf-8').splitlines():
        parsed = parse_line(raw)
        if not parsed:
            continue
        if isinstance(parsed, tuple) and parsed[0] == '__section__':
            section = SECTION_MAP[parsed[1]]
            continue

        record = {
            'section': section,
            'indicator': parsed['indicator'],
            'type': parsed['type'],
            'host_or_ip': parsed['host_or_ip'],
            'port': parsed['port'],
            'path': parsed['path'],
            'asterisk_login_page': 'yes' if parsed['asterisk_login_page'] else 'no',
            'source_url': 'https://citizenlab.ca/research/analysis-of-penlinks-ad-based-geolocation-surveillance-tech/',
            'reason_to_block': 'Infrastructure identified in Citizen Lab research as potential Cobwebs/PenLink-related server infrastructure.',
        }
        rows.append(record)

    dedup = []
    seen = set()
    for row in rows:
        key = (row['indicator'], row['section'])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(row)

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(dedup[0].keys()))
        writer.writeheader()
        writer.writerows(dedup)

    unique_indicators = sorted({r['indicator'] for r in dedup})

    with OUT_FLAT.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['indicator'])
        for indicator in unique_indicators:
            writer.writerow([indicator])

    ips = sorted({
        r['host_or_ip']
        for r in dedup
        if r['type'] in {'ip', 'ip_port', 'url_path_on_ip_port'} and valid_ip(r['host_or_ip'])
    }, key=lambda v: tuple(int(x) for x in v.split('.')))

    domains = sorted({r['host_or_ip'] for r in dedup if r['type'] == 'domain'})

    IP_TXT.write_text('\n'.join(ips) + '\n', encoding='utf-8')
    with IP_CSV.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ip'])
        for ip in ips:
            w.writerow([ip])

    DNS_TXT.write_text('\n'.join(domains) + '\n', encoding='utf-8')

    combined = sorted(set(ips) | set(domains))
    COMBINED_TXT.write_text('\n'.join(combined) + '\n', encoding='utf-8')

    print(
        f'wrote {len(dedup)} section-scoped rows, '
        f'{len(unique_indicators)} unique indicators, {len(ips)} IPs, {len(domains)} domains'
    )


if __name__ == '__main__':
    main()

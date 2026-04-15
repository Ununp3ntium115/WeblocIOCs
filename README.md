# WeblocIOCs

IOC and blocklist package derived from Citizen Lab's report:

- **Analysis of PenLink’s ad-based geolocation surveillance technology**  
  https://citizenlab.ca/research/analysis-of-penlinks-ad-based-geolocation-surveillance-tech/

## Scope

This repository tracks indicators extracted from the article text supplied for that report and keeps them in firewall-friendly formats.

- Product-server and wider-infrastructure **domain indicators**.
- The article-explicit **IP indicators** (14 unique IPs).
- Parsed `ip:port` and `ip:port/path` entries preserved in the structured CSV for context.

## Files

- `data/source_article_iocs.txt` — normalized source text used for reproducible parsing.
- `data/master_indicators.csv` — structured IOC table with section, type, host/IP, port/path, and block rationale.
- `data/indicators_flat.csv` — one-column, globally de-duplicated indicator export.
- `blocklists/ip_blacklist.txt` — firewall-ready IP blacklist (one IP per line).
- `blocklists/ip_blacklist.csv` — CSV version of the IP blacklist.
- `blocklists/dns_blacklist.txt` — domain blacklist (one domain per line).
- `blocklists/combined_blacklist.txt` — combined IP + domain list.
- `scripts/build_iocs.py` — parser/builder for all generated artifacts.

## Rebuild

```bash
python scripts/build_iocs.py
```

## Important caveats

- This repo does **not** invent CIDRs/ranges that are not explicitly present in the source text.
- Domain-to-IP mappings are time-sensitive and were not expanded into bulk resolved IPs here.
- Some indicators are marked with an asterisk in the source text to indicate hosts that displayed a related login page in-browser at the time of observation.

## Why block

Each indicator is included because the report associates it with infrastructure tied to the analyzed surveillance tooling ecosystem. Operational blocking decisions should still follow your local policy, legal requirements, and validation process.

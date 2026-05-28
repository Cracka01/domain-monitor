# Domain Monitor

A self-hosted web tool to monitor lists of look-alike / phishing domains and
get notified when an **inactive** domain suddenly goes **live**.

Built for blue teams, brand-protection, and CTI workflows where an upstream
detector produces thousands of candidate domains and you only have time to
manually review the ones that are actually serving content.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

---

## Features

- **Bulk import** — drop a CSV/TXT with thousands of domains; the parser
  tolerates URLs, multi-column CSVs (`;`, `,`, `\t`), headers, whitespace and
  duplicates.
- **HTTP probing** — real `GET` requests (HTTPS then HTTP), follows redirects,
  classifies each domain as `ACTIVE` / `PARKED` / `4XX` / `5XX` /
  `UNREACHABLE`. Parking detection inspects the HTML for typical
  marketplace/sale keywords (`godaddy`, `sedo`, `for sale`, default nginx page…).
- **DNS resolution** — stores the resolved IPv4 address for each domain.
- **VirusTotal integration** (optional) — queries the VT v3 API for each
  domain, classifies the verdict and links straight to the VT report. Built-in
  rate limiter respects the free 4 req/min quota; a 24h cache avoids burning
  quota on repeated runs.
- **Automatic recheck every N hours** (default `4`) — runs in a background
  thread, no cron needed. Survives browser close.
- **Inactive → Active transitions** — when a previously dead domain comes
  online, it is flagged `NEW`, pinned to the top of the table and shown in a
  highlighted alert.
- **Filterable / sortable table**, **CSV export**, per-row recheck/delete,
  persistent SQLite storage.
- **Single command to start**, no Docker, no Redis, no external services.

---

## Install

```bash
pip install domain-monitor
```

Or install the latest development version from GitHub:

```bash
pip install git+https://github.com/Cracka01/domain-monitor.git
```

### From source

```bash
git clone https://github.com/Cracka01/domain-monitor.git
cd domain-monitor
pip install -e .
```

---

## Usage

After installation a `domain-monitor` command becomes available:

```bash
domain-monitor                       # http://127.0.0.1:5000, opens browser
domain-monitor --port 8080           # custom port
domain-monitor --host 0.0.0.0        # expose on LAN (use with care)
domain-monitor --no-browser          # headless mode
domain-monitor --data-dir ./data     # store monitor.db in ./data
domain-monitor --version
```

You can also run the module directly:

```bash
python -m domain_monitor
```

The web UI exposes everything: CSV upload, manual checks, settings, CSV
export. State is persisted to `monitor.db` inside the data directory
(default: `~/.domain-monitor/`).

### Enabling VirusTotal

1. Create a free account at <https://www.virustotal.com/gui/join-us>.
2. Copy your API key from your profile page.
3. In the web UI open **⚙️ Settings → VirusTotal**, paste the key, tick
   *Enable* and click **Save VT**.
4. Start a check. The key is stored only locally in the SQLite database and is
   never logged or sent anywhere except to `virustotal.com` itself.

> **Quotas.** Free VT accounts are limited to **4 req/min** and **500
> req/day**. The runner enforces the per-minute limit with a sliding window
> and skips lookups that were already performed within the last
> *Cache (h)* window (default `24`).

---

## CSV format

Anything is accepted as long as each line contains at least one valid domain.
Examples that all work:

```text
example.com
phishing-site.org
```

```csv
domain,first_seen,score
example.com,2026-05-15,0.92
mi-bank-impersonation.net,2026-05-16,0.88
```

```csv
Dominio;Target
example.com;myorg
phishing-site.org;myorg
```

Schemes (`http://`, `https://`), paths, ports and surrounding whitespace are
stripped automatically. Invalid lines and duplicates are silently skipped.

---

## Architecture

```
┌──────────────┐   uploads   ┌────────────────┐
│ Browser (JS) │ ──────────▶ │  Flask routes  │
│  (templates) │ ◀──────────  │ /api/*         │
└──────────────┘   JSON      └───────┬────────┘
                                     │
                              ┌──────▼─────────┐
                              │   Runner       │  background threads
                              │  ┌──────────┐  │
                              │  │ HTTP+DNS │  │  ThreadPoolExecutor
                              │  │ Phase 1  │  │  (high concurrency)
                              │  └──────────┘  │
                              │  ┌──────────┐  │
                              │  │   VT     │  │  sequential
                              │  │ Phase 2  │  │  + RateLimiter
                              │  └──────────┘  │
                              └──────┬─────────┘
                                     │
                              ┌──────▼─────────┐
                              │ SQLite (file)  │
                              │  monitor.db    │
                              └────────────────┘
```

A single `domain-monitor` process runs everything: Flask serves the UI and the
JSON API, a `Runner` owns the worker threads, and SQLite persists state.

---

## Configuration reference

| Setting          | Default | Description                                                    |
| ---------------- | ------- | -------------------------------------------------------------- |
| Concurrency      | 20      | Parallel HTTP workers in phase 1                               |
| Timeout          | 10 s    | Per-request timeout                                            |
| Auto-recheck     | 4 h     | Interval between full background passes                        |
| VT enabled       | off     | Enable VirusTotal phase                                        |
| VT API key       | —       | Stored locally in `settings` table; remove with **Clear key**  |
| VT req/min       | 4       | Rate-limit ceiling (raise for paid VT plans)                   |
| VT cache         | 24 h    | Skip VT lookup if a domain was queried within this window      |

Environment variables:

| Variable                   | Purpose                                                              |
| -------------------------- | -------------------------------------------------------------------- |
| `DOMAIN_MONITOR_DATA_DIR`  | Override default data directory (`~/.domain-monitor`).               |

---

## Security notes

- Bind to `127.0.0.1` by default. Use `--host 0.0.0.0` *only* on trusted
  networks or behind a reverse proxy with authentication.
- The VT API key is stored in plaintext inside the local SQLite database
  (which is `.gitignore`d). Protect the data directory with normal filesystem
  permissions.
- The HTTP prober reads at most 16 KiB of each response — it never executes
  remote JavaScript and is not a browser sandbox.
- Outbound requests use `User-Agent: Mozilla/5.0 (compatible;
  DomainMonitor/0.1)`. Modify in `app.py` if you need attribution.

---

## Development

```bash
git clone https://github.com/Cracka01/domain-monitor.git
cd domain-monitor
python -m venv .venv
. .venv/Scripts/activate     # on Windows; use "source .venv/bin/activate" elsewhere
pip install -e ".[dev]"
domain-monitor --debug
```

Linting:

```bash
ruff check src
```

Build distributions:

```bash
python -m build
# wheels and sdist appear in dist/
```

---

## Roadmap

- Optional desktop notifications when `NEW` transitions appear.
- Pre-DNS filter to drop NXDOMAIN domains without spending HTTP/VT calls.
- WHOIS / certificate transparency enrichment.
- Multi-user mode with authentication.

---

## License

MIT — see [LICENSE](LICENSE).

VirusTotal is a trademark of Google LLC; this project is **not** affiliated
with or endorsed by VirusTotal.

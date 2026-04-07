# VulnHive AI

AI-powered penetration testing engine — 24 vuln agents, WAF detection, subdomain enum, exploit chaining.

> **IMPORTANT**: Only use this against applications you own or have explicit
> authorization to test. This is for educational and authorized security
> testing purposes only.

## Quick Start

### 1. Install dependencies

```bash
cd VulnHive-AI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set your API key

```bash
cp .env.example .env
# Edit .env and add your Anthropic API key
```

### 3. Start a vulnerable target (DVWA)

```bash
docker compose up -d
# Wait ~30 seconds, then visit http://localhost:8080
# Login: admin / password
# Go to http://localhost:8080/setup.php and click "Create / Reset Database"
```

### 4. Run the agent

```bash
# Full scan (multi-agent mode)
python main.py --target http://localhost:8080

# With authentication
python main.py --target http://localhost:8080 --auth-type form \
    --login-url http://localhost:8080/login.php \
    --username admin --password password

# Custom subdomain wordlist + rate limiting
python main.py --target https://example.com \
    --wordlist ~/SecLists/Discovery/DNS/subdomains-top5000.txt \
    --rate-limit 50 --scan-all

# With exploit chains + WAF bypass + reports
python main.py --target http://localhost:8080 \
    --exploit-chains --adaptive --report-dir ./reports
```

## Architecture

```
main.py                → CLI entry point
pipeline.py            → Scan orchestration (6 modes)
engine/scan_runner.py  → Unified scan runner
engine/decision_engine → Picks what to test, prioritizes
agents/vuln/           → 24 vulnerability agents
discovery/             → WAF detection, WHOIS/DNS, JS crawler, passive recon
exploit/               → Payload libraries, chain engine, filter bypass
report_engine.py       → HTML + JSON reports
```

## Features

- **24 Vulnerability Agents** — SQLi, XSS, CSRF, SSRF, IDOR, CMDi, SSTI, XXE, JWT, subdomain takeover, and more
- **WAF Detection** — 25 WAF fingerprints with bypass strategy mapping
- **Subdomain Enumeration** — Passive OSINT (crt.sh + Wayback), async DNS, 34 takeover fingerprints
- **WHOIS + DNS Recon** — Full DNS enumeration, SPF/DMARC analysis, TXT token extraction
- **Deep JS Crawler** — Source maps, webpack chunks, 14 route patterns
- **Exploit Chaining** — Multi-step attack path discovery and verification
- **Adaptive Payloads** — WAF bypass with 4 payload libraries (SQLi, XSS, CMDi, SSTI)
- **LLM-Powered** — Local (Ollama/deepseek-r1:14b) or Cloud (Anthropic Claude)

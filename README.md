# Pentest Agent

AI-powered penetration testing agent using Claude as the reasoning engine.

> **IMPORTANT**: Only use this against applications you own or have explicit
> authorization to test. This is for educational and authorized security
> testing purposes only.

## Quick Start

### 1. Install dependencies

```bash
cd pentest-agent
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
# Full scan
python main.py --target http://localhost:8080

# Specific task
python main.py --target http://localhost:8080 --task "Find SQL injection in the login form"

# Fewer iterations (faster, less thorough)
python main.py --target http://localhost:8080 --max-iterations 10
```

## Architecture

```
main.py          → CLI entry point
agent.py         → ReAct loop (Reason → Act → Observe)
tools.py         → HTTP tools the agent can call
validator.py     → Deterministic validation (zero false positives)
```

## Next Steps

- Add more tools (Playwright browser, sqlmap integration)
- Build specialized agents (SQLi agent, XSS agent, etc.)
- Add a coordinator for multi-agent orchestration
- Integrate the validator into the agent loop
- Add reporting (HTML/JSON output)

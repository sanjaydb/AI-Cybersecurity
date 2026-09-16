# AI-Cybersecurity

Educational toolkit that shows how **AI and classic detection** can help a defender review *their own* code and logs.

This is not a pentest-as-a-service engine and not a remote attack scanner.
Every module works on **local files** you already have.

## Why this exists

A lean cybersecurity product can start with four jobs that do not require attacking anyone:

1. Find secrets that should never be committed.
2. Flag common insecure coding patterns (SAST).
3. Spot unusual lines in application or access logs.
4. Prepare a structured prompt so an LLM can review a code snippet as a senior reviewer.

Those four jobs are the seed of an online AI-assisted review product. Full authorized VAPT of live systems is a later product with contracts, scope, and human review.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python -m aicsec.cli --help
```

### Scan this repo for secrets and SAST findings

```bash
python -m aicsec.cli secrets samples/
python -m aicsec.cli sast samples/
python -m aicsec.cli logs samples/access.log
python -m aicsec.cli review samples/vulnerable_app.py
```

JSON output (good for a future web API):

```bash
python -m aicsec.cli sast samples/ --json
```

## Modules

| Command | What it does |
|---|---|
| `secrets` | Regex + entropy checks for API keys, passwords, private keys |
| `sast` | Pattern rules for SQLi concatenation, command injection, weak TLS, debug flags |
| `logs` | IsolationForest anomaly scores on parsed log features |
| `review` | Builds a safe LLM review prompt (optional API call if `OPENAI_API_KEY` is set) |
| `headers` | Scores a **saved** HTTP response file for missing security headers |

## Authorized-use rule

Only analyze assets you own or have written permission to review.
Unauthorized access to computer systems is illegal in India, Germany, and most other countries.

## Roadmap toward a paid product

- Wrap `aicsec.cli` in a FastAPI app behind login.
- Store findings per customer project.
- Require a signed authorization checkbox before any live check.
- Keep humans in the loop for severity and false positives.

## License

MIT. See [LICENSE](LICENSE).

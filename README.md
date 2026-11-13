# Client Protocol Miner

An automated toolkit for analyzing client-side JavaScript bundles, tracing custom request-signing routines, and generating standalone Python client SDKs.

## Overview

Modern web applications frequently protect private or undocumented API endpoints using dynamic headers (such as `X-Signature`, `X-Timestamp`, `X-Nonce`, or custom HMAC tokens) calculated inside client-side JavaScript. 

Manually inspecting minified and bundled frontend assets to understand how these signatures are computed can be time-consuming. **Client Protocol Miner** automates this analysis pipeline:

1. **Harvest**: Discovers and downloads remote JavaScript assets and sourcemaps (`.map`).
2. **Trace**: Scans code for signature headers, crypto algorithms (`CryptoJS`, `SubtleCrypto`, `createHmac`), and parameter sorting routines.
3. **Synthesize**: Emits a clean, standalone Python client script ready to make signed requests.

---

## Project Structure

```
client-protocol-miner/
├── miner.py                 # Primary command-line interface
├── SKILL.md                 # Agent skill specification (Antigravity, Claude, Cursor)
├── requirements.txt         # Runtime dependencies
├── scripts/
│   ├── bundle_fetcher.py    # Extracts and downloads JS bundles from target URLs
│   ├── signature_tracer.py  # Regex and AST-based pattern matching engine
│   └── sdk_synthesizer.py   # Synthesizes standalone Python client SDKs
└── examples/
    └── demo_target.js       # Reference minified client with HMAC signing
```

---

## Installation

Ensure you have Python 3.9+ installed:

```bash
git clone <your-repo-url>
cd client-protocol-miner
pip install -r requirements.txt
```

---

## Quickstart

### 1. Analyze a Live Website
```bash
python miner.py --url "https://target-site.com" --out my_client.py
```

### 2. Analyze Local JavaScript Files
```bash
python miner.py --path "./bundles" --header "X-Signature" --out my_client.py
```

### 3. Test the Included Example
```bash
python miner.py --path "./examples/demo_target.js" --out test_output.py
python test_output.py
```

---

## Agent Skill Usage

This repository includes a `SKILL.md` file, making it directly mountable as an AI agent skill for platforms such as Antigravity, Claude Code, Cursor, or Windsurf.

---

## Disclaimer

This project is intended strictly for authorized educational research, security testing, and interoperability engineering. Users are responsible for complying with all applicable terms of service and laws.

---
name: client-protocol-miner
description: Automated web client protocol reverse-engineering, signature tracing, and standalone Python API client synthesizer. Use when analyzing undocumented APIs, reversing client-side request signatures (X-Signature, HMAC, timestamp, nonce, tokens), or generating replay SDKs from JavaScript frontend bundles.
---

# Client Protocol Miner

**Client Protocol Miner** is an automated reverse-engineering and protocol analysis skill designed to inspect frontend web client bundles (JavaScript), locate custom request signing routines, extract cryptographic parameters (algorithms, salts, nonces, timestamps), and synthesize standalone Python API client SDKs.

---

## 🛠 Capabilities & Workflow

1. **Bundle Harvester (`bundle_fetcher.py`)**:
   - Discovers all `<script src="...">` tags, inline scripts, and dynamic webpack chunks from a target URL.
   - Detects and downloads `.js.map` sourcemaps when available for original source code recovery.

2. **Signature & Crypto Tracer (`signature_tracer.py`)**:
   - Scans JavaScript files for signature headers (`X-Signature`, `X-Sign`, `X-Token`, `sign`, `sig`, `X-Timestamp`, `X-Nonce`).
   - Identifies Axios/Fetch request interceptors (`interceptors.request.use`, `headers.set`).
   - Detects cryptographic routines (`CryptoJS.HmacSHA256`, `MD5`, `SHA1`, `SubtleCrypto`, `createHmac`).
   - Extracts hardcoded secret keys, API salts, and parameter sorting/serialization logic.

3. **Standalone SDK Synthesizer (`sdk_synthesizer.py`)**:
   - Emits a production-ready, standalone Python script (`generated_client.py`) with complete session management, dynamic nonce/timestamp generation, and signature hashing.

---

## 🚀 Quick Usage

### 1. Unified Full Pipeline
Analyze a live website URL or local JS bundle in one command:
```bash
# Analyze a live web page
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\miner.py --url "https://target.com" --out client_sdk.py

# Analyze local JS file or folder of bundles
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\miner.py --path "/path/to/bundles" --out client_sdk.py
```

### 2. Targeted Signature Header Search
If you already know the header name seen in DevTools (e.g., `X-Sign` or `X-Token`):
```bash
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\miner.py --path ./bundles --header "X-Sign" --out target_client.py
```

### 3. Modular Steps

**Download JS bundles:**
```bash
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\scripts\bundle_fetcher.py --url "https://target.com" --out ./downloaded_js
```

**Trace and inspect signature logic:**
```bash
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\scripts\signature_tracer.py --path ./downloaded_js
```

**Generate Python SDK:**
```bash
python C:\Users\habib\.gemini\config\skills\client-protocol-miner\scripts\sdk_synthesizer.py --url "https://api.target.com" --header "X-Signature" --algo "HMAC-SHA256" --salt "EXTRACTED_SALT" --out target_sdk.py
```

---

## 💡 Key Heuristics

- **Alphabetical Key Sorting**: Many custom signature APIs sort query parameters or JSON keys alphabetically before hashing (`Object.keys(p).sort()`).
- **Timestamp & Nonce Freshness**: Most servers enforce timestamp freshness (e.g. ±60 seconds). The generated SDK automatically generates fresh millisecond timestamps.
- **Sourcemaps (`.map`)**: When present, `.map` files contain original unminified variable names and comments, revealing the exact signing algorithms effortlessly.

import os
import re
import json
import argparse
from typing import Dict, List, Any

# Signature & Security Header Keywords
SIGNATURE_KEYWORDS = [
    r'x-sign(?:ature)?',
    r'x-token',
    r'x-auth(?:-token)?',
    r'x-timestamp',
    r'x-nonce',
    r'x-request-id',
    r'["\']sign(?:ature)?["\']\s*:',
    r'["\']sig["\']\s*:',
    r'headers\.set\(["\'](x-[a-z0-9_-]+)["\']',
    r'setRequestHeader\(["\'](x-[a-z0-9_-]+)["\']',
]

# Hashing & Crypto Signatures
CRYPTO_PATTERNS = [
    (r'CryptoJS\.(HmacSHA256|HmacSHA1|HmacMD5|SHA256|MD5|SHA1)\s*\(([^)]+)\)', "CryptoJS Algorithm"),
    (r'(?:crypto\.subtle\.digest|createHash|createHmac)\s*\(\s*["\']([^"\']+)["\']', "Native Crypto Engine"),
    (r'(?:md5|sha256|sha1|hmac)\s*\(([^)]+)\)', "Direct Hash Function Call"),
    (r'(?:const|let|var)?\s*(?:[a-zA-Z0-9_]*(?:secret|salt|api_?key|app_?secret)[a-zA-Z0-9_]*)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\$\/+=]{8,})["\']', "Potential Hardcoded Secret/Salt"),
    (r'["\'](?:secret|salt|api_?key|app_?secret)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\$\/+=]{8,})["\']', "Potential Hardcoded Secret/Salt"),
]

# Client Interceptor & Serialization Patterns
INTERCEPTOR_PATTERNS = [
    (r'interceptors\.request\.use\s*\(\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{', "Axios Request Interceptor"),
    (r'Object\.keys\(([^)]+)\)\.sort\(\)', "Alphabetical Parameter Sorting (Common Sign Pattern)"),
    (r'encodeURIComponent\(([^)]+)\)', "URI Component Encoding Routine"),
    (r'Date\.now\(\)|getTime\(\)|performance\.now\(\)', "Timestamp Generation Routine"),
    (r'Math\.random\(\)\.toString\((?:16|36)\)', "Nonce / Random Token Routine"),
]

def format_snippet(content: str, match_start: int, match_end: int, window: int = 250) -> str:
    start = max(0, match_start - window)
    end = min(len(content), match_end + window)
    snippet = content[start:end].replace("\r", " ").replace("\n", " ")
    snippet = re.sub(r'\s+', ' ', snippet)
    return snippet.strip()

def scan_file(file_path: str, custom_headers: List[str] = None) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    results = {
        "file": file_path,
        "size_kb": round(len(content) / 1024, 2),
        "headers_found": [],
        "crypto_routines": [],
        "interceptors_found": [],
        "secrets_found": []
    }

    # 1. Scan for custom headers & default keywords
    search_keywords = SIGNATURE_KEYWORDS.copy()
    if custom_headers:
        for ch in custom_headers:
            search_keywords.append(re.escape(ch))

    for pat in search_keywords:
        for m in re.finditer(pat, content, re.IGNORECASE):
            results["headers_found"].append({
                "pattern": pat,
                "matched": m.group(0),
                "position": m.start(),
                "snippet": format_snippet(content, m.start(), m.end(), window=200)
            })

    # 2. Scan for crypto routines & secrets
    for pat, label in CRYPTO_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            val = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            entry = {
                "type": label,
                "matched": val,
                "args": val,
                "snippet": format_snippet(content, m.start(), m.end(), window=220)
            }
            if "Secret" in label:
                results["secrets_found"].append(entry)
            else:
                results["crypto_routines"].append(entry)

    # 3. Scan for interceptors & sorting routines
    for pat, label in INTERCEPTOR_PATTERNS:
        for m in re.finditer(pat, content, re.IGNORECASE):
            results["interceptors_found"].append({
                "type": label,
                "snippet": format_snippet(content, m.start(), m.end(), window=200)
            })

    return results

def trace_directory(dir_path: str, custom_headers: List[str] = None) -> List[Dict[str, Any]]:
    all_findings = []
    for root, _, files in os.walk(dir_path):
        for f in files:
            if f.endswith(".js"):
                fp = os.path.join(root, f)
                data = scan_file(fp, custom_headers)
                has_hit = (
                    data["headers_found"] or 
                    data["crypto_routines"] or 
                    data["secrets_found"] or 
                    data["interceptors_found"]
                )
                if has_hit:
                    all_findings.append(data)
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Trace and isolate client-side signature generation routines in JS.")
    parser.add_argument("--path", required=True, help="Path to JS file or directory of JS bundles")
    parser.add_argument("--header", action="append", help="Specific header name to trace (e.g. X-Signature)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        findings = trace_directory(args.path, args.header)
    else:
        findings = [scan_file(args.path, args.header)]

    if args.json:
        print(json.dumps(findings, indent=2))
        return

    print("=" * 70)
    print(" 🔍 CLIENT PROTOCOL MINER — SIGNATURE TRACER RESULTS")
    print("=" * 70)
    total_files = len(findings)
    print(f"[*] Analyzed candidate files with findings: {total_files}\n")

    for f_idx, item in enumerate(findings):
        print(f"[{f_idx+1}] File: {item['file']} ({item['size_kb']} KB)")
        
        if item["headers_found"]:
            print("  📌 Signature Headers Detected:")
            for h in item["headers_found"][:5]:
                print(f"     - Matched: {h['matched']}")
                print(f"       Snippet: ...{h['snippet']}...")
        
        if item["secrets_found"]:
            print("  🔑 Potential Hardcoded Salts/Secrets:")
            for s in item["secrets_found"]:
                print(f"     - Key: {s['matched']}")
                print(f"       Context: ...{s['snippet']}...")

        if item["crypto_routines"]:
            print("  ⚡ Cryptographic Hashing Routines:")
            for c in item["crypto_routines"][:5]:
                print(f"     - [{c['type']}]: {c['matched']}")
                print(f"       Snippet: ...{c['snippet']}...")

        if item["interceptors_found"]:
            print("  🔄 Request Interceptors & Normalizers:")
            for i in item["interceptors_found"][:3]:
                print(f"     - [{i['type']}]")
                print(f"       Snippet: ...{i['snippet']}...")
        print("-" * 70)

if __name__ == "__main__":
    main()

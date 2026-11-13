import os
import sys
import argparse
import tempfile
import json

from scripts.bundle_fetcher import fetch_url, extract_script_urls, download_bundles
from scripts.signature_tracer import scan_file, trace_directory
from scripts.sdk_synthesizer import synthesize_client

def run_mining_pipeline(url: str = None, local_path: str = None, header_filter: list = None, output_sdk: str = "generated_client.py"):
    temp_dir = None
    target_scan_path = local_path

    try:
        if url:
            print(f"[*] Step 1/3: Harvesting client JavaScript bundles from: {url}")
            temp_dir = tempfile.mkdtemp(prefix="miner_bundles_")
            html = fetch_url(url)
            scripts = extract_script_urls(html, url)
            print(f"[+] Found {len(scripts)} scripts. Downloading to inspection sandbox...")
            download_bundles(scripts, temp_dir)
            target_scan_path = temp_dir

        print(f"\n[*] Step 2/3: Tracing signature routines & encryption functions...")
        if os.path.isdir(target_scan_path):
            findings = trace_directory(target_scan_path, header_filter)
        else:
            findings = [scan_file(target_scan_path, header_filter)]

        # Collect summary data
        discovered_headers = set()
        discovered_secrets = set()
        discovered_algos = set()

        for f in findings:
            for h in f.get("headers_found", []):
                discovered_headers.add(h["matched"])
            for s in f.get("secrets_found", []):
                discovered_secrets.add(s["matched"])
            for c in f.get("crypto_routines", []):
                discovered_algos.add(c["matched"])

        print("\n" + "=" * 70)
        print(" 🎯 MINING ANALYSIS SUMMARY")
        print("=" * 70)
        print(f"  Files with Signature Indicators : {len(findings)}")
        print(f"  Candidate Headers Detected      : {list(discovered_headers) or 'None'}")
        print(f"  Candidate Secrets / Salts       : {list(discovered_secrets) or 'None'}")
        print(f"  Candidate Crypto Primitives     : {list(discovered_algos) or 'None'}")
        print("=" * 70)

        # Print top code snippets
        if findings:
            print("\n🔍 Top Extracted Logic Snippets:")
            for item in findings[:3]:
                print(f"\n[File: {os.path.basename(item['file'])}]")
                for h in item.get("headers_found", [])[:2]:
                    print(f"  • Header Context: ...{h['snippet']}...")
                for c in item.get("crypto_routines", [])[:2]:
                    print(f"  • Crypto Context: ...{c['snippet']}...")
                for s in item.get("secrets_found", [])[:2]:
                    print(f"  • Secret Context: ...{s['snippet']}...")

        # Step 3: Synthesis
        print(f"\n[*] Step 3/3: Synthesizing standalone Python SDK...")
        
        # Pick the most relevant signature header
        primary_header = "X-Signature"
        for cand in discovered_headers:
            clean_cand = cand.replace("headers.set(", "").replace("setRequestHeader(", "").strip("\"': ")
            if any(term in clean_cand.lower() for term in ["sign", "sig", "token", "auth"]):
                primary_header = clean_cand
                break

        chosen_salt = list(discovered_secrets)[0] if discovered_secrets else "DISCOVERED_SALT_KEY"
        chosen_algo = "HMAC-SHA256"
        for cand in discovered_algos:
            if "hmac" in cand.lower():
                chosen_algo = "HMAC-SHA256"
                break
            elif "sha256" in cand.lower():
                chosen_algo = "SHA256"
            elif "md5" in cand.lower():
                chosen_algo = "MD5"

        synthesize_client(
            base_url=url or "https://api.target.com",
            header_name=primary_header,
            algorithm=chosen_algo,
            secret_salt=chosen_salt,
            output_path=output_sdk
        )

        print(f"\n✨ Done! Reconstructed client ready at: {output_sdk}")

    finally:
        pass

def main():
    parser = argparse.ArgumentParser(description="Client Protocol Miner — Automated Client Signature & API Reverse-Engineering Toolkit")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="Target website URL to fetch and analyze")
    group.add_argument("--path", help="Local JS file or directory of downloaded JS files")
    
    parser.add_argument("--header", action="append", help="Specific header name to trace (e.g. X-Signature)")
    parser.add_argument("--out", default="generated_client.py", help="Output path for synthesized Python SDK")
    args = parser.parse_args()

    run_mining_pipeline(
        url=args.url,
        local_path=args.path,
        header_filter=args.header,
        output_sdk=args.out
    )

if __name__ == "__main__":
    main()

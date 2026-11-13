import os
import argparse

SDK_TEMPLATE = '''"""
Generated API Client by Client Protocol Miner
Target Base URL: {base_url}
Algorithm: {algorithm}
"""

import time
import hashlib
import hmac
import json
import urllib.parse
from typing import Dict, Any, Optional
import requests

class TargetAPIClient:
    def __init__(self, base_url: str = "{base_url}", secret_salt: str = "{secret_salt}"):
        self.base_url = base_url.rstrip("/")
        self.secret_salt = secret_salt
        self.session = requests.Session()
        self.session.headers.update({{
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }})

    def generate_signature(self, path: str, params: Optional[Dict[str, Any]] = None, body: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Calculates client signature headers reconstructed from target JavaScript client.
        """
        timestamp = str(int(time.time() * 1000))
        nonce = hashlib.md5(f"{{timestamp}}-{{time.perf_counter()}}".encode()).hexdigest()[:16]

        # 1. Normalize and sort parameters if present
        param_str = ""
        if params:
            sorted_keys = sorted(params.keys())
            param_str = "&".join(f"{{k}}={{params[k]}}" for k in sorted_keys)

        # 2. Serialize body if present
        body_str = ""
        if body is not None:
            body_str = json.dumps(body, separators=(',', ':'), sort_keys=True)

        # 3. Construct signing base payload
        # Common convention: PATH + PARAM_STR + BODY_STR + TIMESTAMP + NONCE + SALT
        sign_string = f"{{path}}|{{param_str}}|{{body_str}}|{{timestamp}}|{{nonce}}|{{self.secret_salt}}"

        # 4. Compute hash using selected algorithm
        {hash_calculation}

        return {{
            "{header_name}": signature,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce
        }}

    def request(self, method: str, path: str, params: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None) -> requests.Response:
        url = f"{{self.base_url}}/{{path.lstrip('/')}}"
        sig_headers = self.generate_signature(path, params=params, body=json_body)
        
        headers = {{**self.session.headers, **sig_headers}}
        resp = self.session.request(
            method=method,
            url=url,
            params=params,
            json=json_body,
            headers=headers,
            timeout=15
        )
        return resp

# Quick Self-Test
if __name__ == "__main__":
    client = TargetAPIClient()
    test_path = "/api/v1/ping"
    print(f"[*] Testing signature generation for: {{test_path}}")
    headers = client.generate_signature(test_path, params={{"test": "1"}})
    print("[+] Generated Headers:")
    for k, v in headers.items():
        print(f"    {{k}}: {{v}}")
'''

def synthesize_client(base_url: str, header_name: str, algorithm: str, secret_salt: str, output_path: str):
    algo_lower = algorithm.lower()
    
    if "hmac" in algo_lower or "sha256" in algo_lower:
        hash_calc = 'signature = hmac.new(self.secret_salt.encode(), sign_string.encode(), hashlib.sha256).hexdigest()'
    elif "md5" in algo_lower:
        hash_calc = 'signature = hashlib.md5(sign_string.encode()).hexdigest()'
    else:
        # Default standard SHA-256
        hash_calc = 'signature = hashlib.sha256(sign_string.encode()).hexdigest()'

    code = SDK_TEMPLATE.format(
        base_url=base_url or "https://api.target.com",
        secret_salt=secret_salt or "SECRET_SALT_KEY",
        algorithm=algorithm or "HMAC-SHA256",
        header_name=header_name or "X-Signature",
        hash_calculation=hash_calc
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(code)
    print(f"[+] Successfully synthesized API Client SDK -> {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Synthesize executable Python SDK client from mined signature parameters.")
    parser.add_argument("--url", default="https://api.target.com", help="Target API Base URL")
    parser.add_argument("--header", default="X-Signature", help="Signature Header Name")
    parser.add_argument("--algo", default="HMAC-SHA256", help="Algorithm (HMAC-SHA256, SHA256, MD5)")
    parser.add_argument("--salt", default="CUSTOM_SECRET_KEY", help="Discovered Secret Key or Salt")
    parser.add_argument("--out", default="client_sdk.py", help="Output file path for generated SDK")
    args = parser.parse_args()

    synthesize_client(args.url, args.header, args.algo, args.salt, args.out)

if __name__ == "__main__":
    main()

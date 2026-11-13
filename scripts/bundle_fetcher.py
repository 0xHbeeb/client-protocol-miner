import os
import re
import urllib.parse
import urllib.request
import argparse
from typing import List, Tuple

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8", errors="replace")

def extract_script_urls(html_content: str, base_url: str) -> List[str]:
    # Match standard <script ... src="..."
    src_patterns = [
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'["\'](/[^"\']+\.js(?:\?[^"\']*)?)["\']',
    ]
    found = set()
    for pat in src_patterns:
        for match in re.findall(pat, html_content, re.IGNORECASE):
            full_url = urllib.parse.urljoin(base_url, match)
            if full_url.startswith("http://") or full_url.startswith("https://"):
                found.add(full_url)
    return sorted(list(found))

def download_bundles(urls: List[str], output_dir: str) -> List[Tuple[str, str]]:
    os.makedirs(output_dir, exist_ok=True)
    saved_files = []
    
    for idx, script_url in enumerate(urls):
        try:
            parsed = urllib.parse.urlparse(script_url)
            filename = os.path.basename(parsed.path) or f"bundle_{idx}.js"
            if not filename.endswith(".js"):
                filename += ".js"
            safe_name = f"{idx:02d}_{re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)}"
            target_path = os.path.join(output_dir, safe_name)
            
            print(f"[*] Downloading [{idx+1}/{len(urls)}]: {script_url}")
            content = fetch_url(script_url)
            with open(target_path, "w", encoding="utf-8") as f:
                f.write(content)
            saved_files.append((script_url, target_path))

            # Check if source map exists
            map_url = script_url + ".map"
            try:
                map_content = fetch_url(map_url)
                map_path = target_path + ".map"
                with open(map_path, "w", encoding="utf-8") as mf:
                    mf.write(map_content)
                print(f"  [+] Found Source Map: {map_url}")
            except Exception:
                pass

        except Exception as e:
            print(f"  [-] Failed downloading {script_url}: {e}")
            
    return saved_files

def main():
    parser = argparse.ArgumentParser(description="Fetch all JavaScript client bundles from a web target.")
    parser.add_argument("--url", required=True, help="Target website URL")
    parser.add_argument("--out", default="downloaded_bundles", help="Output directory for JS files")
    args = parser.parse_args()

    print(f"[*] Fetching target page: {args.url}")
    html = fetch_url(args.url)
    scripts = extract_script_urls(html, args.url)
    print(f"[+] Discovered {len(scripts)} JavaScript bundle URLs.")
    download_bundles(scripts, args.out)

if __name__ == "__main__":
    main()

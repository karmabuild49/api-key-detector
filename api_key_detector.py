#!/usr/bin/env python3
"""
API Key Detector - Scans websites for exposed API keys and tokens
"""

import re
import sys
import json
import csv
import argparse
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: requests library not found. Install with: pip install requests")
    sys.exit(1)


class APIKeyDetector:
    PATTERNS = [
        (re.compile(r'(?i)(?:api[_-]?key|apikey)[\'"\s:=]+([A-Za-z0-9_\-]{16,})'), 'Generic API Key'),
        (re.compile(r'(?i)(?:secret[_-]?key|secret)[\'"\s:=]+([A-Za-z0-9_\-]{16,})'), 'Secret Key'),
        (re.compile(r'(?i)(?:access[_-]?token|accesstoken)[\'"\s:=]+([A-Za-z0-9_\-\.]{20,})'), 'Access Token'),
        (re.compile(r'(?i)(?:bearer\s+)([A-Za-z0-9\-_\.]{20,})'), 'Bearer Token'),
        (re.compile(r'(AKIA[0-9A-Z]{16})'), 'AWS Access Key'),
        (re.compile(r'(?i)(?:aws[_-]?secret[_-]?access[_-]?key)[\'"\s:=]+([A-Za-z0-9/+=]{40})'), 'AWS Secret Key'),
        (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), 'Google API Key'),
        (re.compile(r'(pk_live_[0-9a-zA-Z]{24})'), 'Stripe Public Key'),
        (re.compile(r'(sk_live_[0-9a-zA-Z]{24})'), 'Stripe Secret Key'),
        (re.compile(r'(ghp_[A-Za-z0-9_]{36})'), 'GitHub Personal Access Token'),
        (re.compile(r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)'), 'Slack Token'),
        (re.compile(r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'), 'JWT Token'),
    ]

    def __init__(self, timeout: int = 15, max_retries: int = 3):
        self.timeout = timeout
        self.session = self._create_session(max_retries)
        self.findings: List[Dict] = []
        self.visited_urls: Set[str] = set()

    def _create_session(self, max_retries: int) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def fetch_page(self, url: str) -> Tuple[str, str]:
        try:
            headers = {"User-Agent": "Mozilla/5.0"}
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            return response.text, response.url
        except requests.exceptions.RequestException as e:
            print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
            return "", url

    def extract_links(self, html: str, base_url: str) -> Set[str]:
        link_pattern = re.compile(r'''(?:href|src)=["']([^"'<>]+)["']''', re.I)
        links = set()
        for match in link_pattern.findall(html):
            if match.startswith(("http://", "https://")):
                links.add(match)
            elif match and not match.startswith(("data:", "javascript:", "#")):
                links.add(urljoin(base_url, match))
        return links

    def find_secrets_in_text(self, text: str, source: str) -> List[Dict]:
        results = []
        seen = set()

        for pattern, pattern_name in self.PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group(0)
                if not value or len(value) < 8 or value in seen:
                    continue
                if any(p in value.lower() for p in ['example', 'test', 'demo', 'placeholder', 'xxx']):
                    continue
                seen.add(value)
                results.append({
                    "type": pattern_name,
                    "value": value,
                    "source": source,
                    "timestamp": datetime.now().isoformat(),
                })

        return results

    def scan_url(self, url: str, recursive: bool = False, max_depth: int = 2, current_depth: int = 0) -> None:
        if url in self.visited_urls or current_depth > max_depth:
            return
        self.visited_urls.add(url)

        parsed = urlparse(url)
        print(f"  [→] Scanning: {url}")

        html, final_url = self.fetch_page(url)
        if not html:
            return

        self.findings.extend(self.find_secrets_in_text(html, final_url))

        for link in self.extract_links(html, final_url):
            link_parsed = urlparse(link)
            if recursive and link_parsed.netloc == parsed.netloc and current_depth < max_depth:
                self.scan_url(link, recursive=True, max_depth=max_depth, current_depth=current_depth + 1)

            if any(link.endswith(ext) for ext in ['.js', '.json', '.txt', '.xml', '.config']):
                resource_html, _ = self.fetch_page(link)
                if resource_html:
                    self.findings.extend(self.find_secrets_in_text(resource_html, link))

    def deduplicate_findings(self) -> List[Dict]:
        seen = set()
        unique = []
        for item in self.findings:
            key = (item['type'], item['value'], item['source'])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def print_results(self) -> None:
        unique_findings = self.deduplicate_findings()
        if not unique_findings:
            print("\n✓ No API keys or secrets found.")
            return

        print(f"\n⚠ Found {len(unique_findings)} potential API key(s) / secret(s):\n")
        print("─" * 80)
        for idx, finding in enumerate(unique_findings, 1):
            print(f"\n[{idx}] {finding['type']}")
            print(f"    Source: {finding['source']}")
            print(f"    Value:  {finding['value']}")
        print("\n" + "─" * 80)

    def save_results(self, output_format: str = "json", output_file: str = None) -> None:
        unique_findings = self.deduplicate_findings()
        if not unique_findings:
            print("No findings to save.")
            return

        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"api_keys_{timestamp}.{output_format}"

        try:
            if output_format == "json":
                with open(output_file, 'w') as f:
                    json.dump(unique_findings, f, indent=2)
            elif output_format == "csv":
                with open(output_file, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["type", "value", "source", "timestamp"])
                    writer.writeheader()
                    writer.writerows(unique_findings)
            print(f"✓ Results saved to: {output_file}")
        except IOError as e:
            print(f"✗ Failed to save results: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Scan websites for exposed API keys and tokens")
    parser.add_argument("url", nargs="?", help="Website URL to scan")
    parser.add_argument("--recursive", action="store_true", help="Recursively scan linked pages on the same domain")
    parser.add_argument("--max-depth", type=int, default=2, help="Max depth for recursive scanning")
    parser.add_argument("--output", choices=["json", "csv", "text"], default="text", help="Output format")
    parser.add_argument("--file", help="Output file name")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    args = parser.parse_args()

    url = args.url or input("Enter website URL to scan: ").strip()
    if not url:
        print("Error: URL is required.")
        sys.exit(1)
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"\n🔍 API Key Detector\n{'─' * 80}\nURL: {url}\nRecursive: {args.recursive} (max depth: {args.max_depth})\n{'─' * 80}\n")

    detector = APIKeyDetector(timeout=args.timeout)
    try:
        detector.scan_url(url, recursive=args.recursive, max_depth=args.max_depth)
        detector.print_results()
        if args.output != "text":
            detector.save_results(output_format=args.output, output_file=args.file)
    except KeyboardInterrupt:
        print("\n\n⊘ Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error during scan: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


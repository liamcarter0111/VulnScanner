import requests
import sys
import re
from urllib.parse import urlparse
import socket
import argparse
from typing import List, Optional

class VulnScanner:
    """A simple web vulnerability scanner for detecting XSS, SQLi, and open ports."""
    
    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url
        self.timeout = timeout
        self.vulnerabilities = []
        self.payloads = {
            "xss": ["<script>alert('xss')</script>", "'><img src=x onerror=alert('xss')>"],
            "sqli": ["' OR '1'='1", "1; DROP TABLE users --"]
        }

    def validate_url(self) -> bool:
        """Validate the target URL."""
        try:
            result = requests.get(self.target_url, timeout=self.timeout)
            return result.status_code == 200
        except requests.RequestException:
            print(f"[!] Invalid or unreachable URL: {self.target_url}")
            return False

    def scan_xss(self) -> None:
        """Test for XSS vulnerabilities by injecting payloads."""
        parsed_url = urlparse(self.target_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        for payload in self.payloads["xss"]:
            try:
                test_url = f"{base_url}?test={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    self.vulnerabilities.append(f"[!] Potential XSS vulnerability found with payload: {payload}")
            except requests.RequestException:
                print(f"[!] Error testing XSS payload: {payload}")

    def scan_sqli(self) -> None:
        """Test for SQL Injection vulnerabilities."""
        for payload in self.payloads["sqli"]:
            try:
                test_url = f"{self.target_url}?id={payload}"
                response = requests.get(test_url, timeout=self.timeout)
                if re.search(r"sql|mysql|syntax|error", response.text, re.IGNORECASE):
                    self.vulnerabilities.append(f"[!] Potential SQL Injection vulnerability found with payload: {payload}")
            except requests.RequestException:
                print(f"[!] Error testing SQLi payload: {payload}")

    def scan_ports(self, ports: List[int] = [80, 443, 22, 21]) -> None:
        """Scan for open ports on the target host."""
        parsed_url = urlparse(self.target_url)
        target_host = parsed_url.netloc.split(":")[0]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((target_host, port))
                if result == 0:
                    self.vulnerabilities.append(f"[!] Open port found: {port}")
                sock.close()
            except socket.error:
                print(f"[!] Error scanning port: {port}")

    def run(self, scan_ports: bool = False) -> List[str]:
        """Run the full vulnerability scan."""
        print(f"[*] Starting scan on {self.target_url}")
        
        if not self.validate_url():
            return ["[!] Scan aborted due to invalid URL"]
        
        print("[*] Scanning for XSS vulnerabilities...")
        self.scan_xss()
        
        print("[*] Scanning for SQL Injection vulnerabilities...")
        self.scan_sqli()
        
        if scan_ports:
            print("[*] Scanning for open ports...")
            self.scan_ports()
        
        print("[*] Scan completed!")
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(description="VulnScanner - A simple web vulnerability scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--ports", action="store_true", help="Enable port scanning")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    
    args = parser.parse_args()
    
    scanner = VulnScanner(args.url, args.timeout)
    results = scanner.run(scan_ports=args.ports)
    
    if results:
        print("\n[+] Vulnerabilities Found:")
        for vuln in results:
            print(vuln)
    else:
        print("\n[+] No vulnerabilities detected.")

if __name__ == "__main__":
    main()

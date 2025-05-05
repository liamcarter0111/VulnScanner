# VulnScanner Usage Guide

VulnScanner is a Python-based tool designed to detect common web vulnerabilities, such as Cross-Site Scripting (XSS), SQL Injection (SQLi), and open ports. This guide provides clear instructions for setting up and using the tool effectively.

## 📋 Prerequisites

- **Python 3.6+** installed on your system.
- A stable internet connection for sending HTTP requests.
- Basic familiarity with command-line interfaces.
- Explicit permission to scan the target system (unauthorized scanning is illegal and unethical).

## 🛠️ Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/liamcarter0111/VulnScanner.git
   cd VulnScanner
   ```

2. **Install Dependencies**:
   The script requires the `requests` library. Install it using pip:
   ```bash
   pip install requests
   ```

3. **Verify Setup**:
   Confirm the script runs and dependencies are installed:
   ```bash
   python3 vulnscanner.py --help
   ```

## 🚀 Usage

Execute the script via the command line, providing the target URL and optional arguments.

### Basic Command
```bash
python3 vulnscanner.py <target_url>
```

- `<target_url>`: The URL to scan (e.g., `http://example.com`).

### Optional Arguments
- `--ports`: Enable scanning of common ports (80, 443, 22, 21).
- `--timeout <seconds>`: Set the timeout for HTTP requests and port scans (default: 5 seconds).

### Examples

1. **Basic Scan** (XSS and SQLi):
   ```bash
   python3 vulnscanner.py http://example.com
   ```

   Example Output:
   ```
   [*] Starting scan on http://example.com
   [*] Scanning for XSS vulnerabilities...
   [*] Scanning for SQL Injection vulnerabilities...
   [*] Scan completed!
   [+] No vulnerabilities detected.
   ```

2. **Scan with Port Scanning**:
   ```bash
   python3 vulnscanner.py http://example.com --ports
   ```

   Example Output:
   ```
   [*] Starting scan on http://example.com
   [*] Scanning for XSS vulnerabilities...
   [*] Scanning for SQL Injection vulnerabilities...
   [*] Scanning for open ports...
   [*] Scan completed!
   [+] Vulnerabilities Found:
   [!] Open port found: 80
   [!] Open port found: 443
   ```

3. **Custom Timeout**:
   ```bash
   python3 vulnscanner.py http://example.com --timeout 10
   ```

## ⚠️ Important Notes

- **Legal Disclaimer**: Only scan systems you have explicit permission to test. Unauthorized scanning is illegal and unethical.
- **Limitations**: This tool is for educational purposes and may not detect complex vulnerabilities.
- **False Positives/Negatives**: Always verify results manually, as simple payloads may miss stealthy issues or flag benign behavior.
- **Network Restrictions**: Firewalls or network policies may block port scanning, impacting results.

## 🐛 Troubleshooting

- **Error: "Invalid or unreachable URL"**:
  - Verify the URL is correct and accessible.
  - Check your internet connection.
- **Error: "ModuleNotFoundError: No module named 'requests'"**:
  - Install the `requests` library: `pip install requests`.
- **Slow Scans**:
  - Increase `--timeout` for slower networks.
  - Edit the `scan_ports` method in the script to reduce scanned ports.

## 📬 Feedback

Encountered an issue or have a suggestion? File an issue on the [GitHub repository](https://github.com/liamcarter0111/VulnScanner) or contact me at [liamcarter0111@outlook.com](mailto:liamcarter0111@outlook.com).

Happy bug hunting! 🕵️‍♂️

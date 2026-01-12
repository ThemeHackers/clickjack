# 🚨 ClickJacking Vulnerability Scanner (Golang Edition) 

Refactored and supercharged version of the ClickJacking Scanner, now written in **Golang**. Fast, concurrent, and packed with advanced detection logic.

## ⚡ Key Updates
- **🚀 Pure Golang:** Compiled into a single, portable binary. No Python dependencies.
- **⚡ Concurrency:** Scans hundreds of targets in seconds using Goroutines.
- **🛡️ Advanced Detection:** Checks not just for headers, but also for **Content-Security-Policy (CSP)** logic and **Frame Busting** JavaScript patterns.
- **🔍 CSP Analyzer:** Built-in analyzer to inspect and color-code CSP headers for security flaws (`-csp-analyzer`).
- **🥷 Stealth Mode:** Randomized User-Agents and Jitter delay to evade WAF/IPS (`-stealth`).
- **📊 JSON Output:** Machine-readable output for easy integration (`-json`).
- **🕹️ Vulnerable Lab:** Includes a Docker-based **Vulnerable App** with a realistic "Reward Center" theme for testing.

## 🛠️ Installation & Build

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Raiders0786/ClickjackPoc.git
   cd ClickjackPoc
   ```

2. **Build the binary:**
   ```bash
   go build -o clickjack
   ```

## 💻 Usage

```bash
./clickjack -h
```

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Single target URL | |
| `-f` | File containing list of domains | |
| `-c` | Number of concurrent threads | `20` |
| `-o` | Output file path | |
| `-csp-analyzer` | Analyze CSP headers (requires `-t`) | `false` |
| `-stealth` | Enable Stealth Mode (Random UA, Jitter) | `false` |
| `-json` | Output results in JSON format | `false` |
| `-proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | |
| `-timeout` | Request timeout in seconds | `10` |
| `-ua` | Custom User-Agent | `RedTeam-Clickjack-Scanner/1.0` |

### Examples

**1. Scan a Single Target:**
```bash
./clickjack -t "http://target.com"
```

**2. Red Team Stealth Scan (JSON Output):**
```bash
./clickjack -f domains.txt -stealth -json -o results.json
```

**3. Analyze CSP Headers:**
```bash
./clickjack -t "https://github.com" -csp-analyzer
```

**4. Scan with Proxy (e.g., Burp Suite):**
```bash
./clickjack -t "http://target.com" -proxy "http://127.0.0.1:8080"
```

## 🧪 Testing with Vulnerable App

We provide a **Vulnerable App** to test the scanner. It simulates a "Prize Claim" page vulnerable to Clickjacking.

1. **Start the App:**
   ```bash
   cd vulnerable_app
   docker build -t vulnerable-app .
   docker run -d -p 8080:80 vulnerable-app
   ```

2. **Access the App:** 
   Open `http://localhost:8080` in your browser.

3. **Scan it:**
   ```bash
   ./clickjack -t "http://localhost:8080"
   ```
   *Result: Should be detected as Vulnerable.*

## 📝 Output Explanation

- **[+] Vulnerable:** No `X-Frame-Options` or `Content-Security-Policy` (frame-ancestors) found.
- **[?] Potentially Vulnerable:** Headers are missing, but **Frame Busting JavaScript** was detected. This might be bypassable.
- **[Secure]:** Proper headers are present.

---
**Disclaimer:** This tool is for educational and security testing purposes only. Use responsibly.

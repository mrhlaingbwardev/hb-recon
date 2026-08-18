# HB-Recon

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/mrhlaingbwardev/hb-recon?style=social)](https://github.com/mrhlaingbwardev/hb-recon/stargazers)

**Automated reconnaissance workflow with AI-ready report generation.**

Perfect for bug bounty hunters, pentesters, and security researchers.

---

## ⚠️ Important Notice

**HB-Recon is a workflow automation tool** — it orchestrates external security tools and generates structured reports.

**What it does:**
- ✅ Automates reconnaissance workflows
- ✅ Chains multiple tools together
- ✅ Generates AI-ready JSON reports
- ✅ Organizes scan results

**What it does NOT do:**
- ❌ Include built-in scanning capabilities
- ❌ Auto-install required tools
- ❌ Work without dependencies

---

## Features

✅ **Subdomain Enumeration** — subfinder integration  
✅ **Live Host Detection** — httpx for alive checks  
✅ **Technology Stack Scan** — WhatWeb detection  
✅ **Endpoint Crawling** — Katana deep crawl (depth 3)  
✅ **Vulnerability Patterns** — gf pattern matching (XSS, SQLi, IDOR)  
✅ **AI Report Generation** — Structured JSON with risk scoring  

---

## Prerequisites

### System Requirements
- **OS:** Linux / WSL (Windows Subsystem for Linux)
- **Python:** 3.8+
- **Go:** 1.19+ (for tool installation)

### Required External Tools

You **MUST** install these tools before using hb-recon:

| Tool | Purpose | Installation |
|------|---------|--------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probe | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawler | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| [gf](https://github.com/tomnomnom/gf) | Pattern matcher | `go install github.com/tomnomnom/gf@latest` |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | Tech detection | `sudo apt install whatweb` (Debian/Ubuntu) |

### Quick Install (All Tools)

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest

# Install WhatWeb
sudo apt install whatweb

# Verify installations
subfinder -version
httpx -version
katana -version
gf -h
whatweb --version
```

---

## Installation

### Option 1: Docker (Recommended for Windows)

```bash
docker build -t hb-recon .
docker run -it hb-recon -h
```

### Option 2: From Source (Linux/WSL)

```bash
git clone https://github.com/mrhlaingbwardev/hb-recon.git
cd hb-recon
pip install -e .
```

---

## Usage

### Interactive Mode

```bash
python -m hb_recon
```

**Example:**
```
=======================================================
  Auto Recon -> AI Ready
=======================================================

[>] Domain: example.com

[+] Subfinder + Httpx
[v] Done (5.2s)

[*] WhatWeb + Katana (parallel)...
[+] Katana (crawl)
[v] Done (12.4s)

[+] gf (XSS/SQLi/IDOR patterns)
[v] Done (1.8s)

[√] Total: 19.4s
```

### Output Structure

```
recon_example.com/
├── subdomains.txt      # All discovered subdomains
├── alive.txt           # Live hosts (200, 301, 403)
├── urls.txt            # Crawled endpoints (depth 3)
├── xss.txt             # XSS-prone endpoints
├── sqli.txt            # SQLi-prone endpoints
├── idor.txt            # IDOR-prone endpoints
├── tech_stack.txt      # Technology detection
└── ai_report.json      # AI-ready structured report
```

---

## AI Report Format

The tool generates `ai_report.json` with structured data perfect for AI analysis:

```json
{
  "target": "example.com",
  "timestamp": "2026-06-20T13:45:00",
  "summary": {
    "subdomains": 15,
    "alive_hosts": 8,
    "endpoints": 324,
    "technologies": 12,
    "high_risk": 3,
    "medium_risk": 7,
    "low_risk": 15
  },
  "endpoints": [
    {
      "url": "https://admin.example.com/api/users?id=123",
      "category": "idor",
      "risk": "high",
      "params": ["id"]
    }
  ],
  "tech_stack": {
    "server": "nginx/1.18.0",
    "frameworks": ["React", "Node.js"],
    "cms": "WordPress 6.2"
  }
}
```

**Use with AI:**
```bash
# After scan
cat recon_example.com/ai_report.json | pbcopy
# Paste into ChatGPT/Claude: "Analyze this recon data for vulnerabilities"
```

---

## Workflow Logic

```
Input: Domain
    ↓
1. Subdomain Enumeration (subfinder)
    → hackertarget, waybackarchive sources
    ↓
2. Live Detection (httpx)
    → Filter 200, 301, 403 status codes
    ↓
3. Parallel Execution:
    ├─→ Tech Stack (WhatWeb)
    └─→ Endpoint Crawl (Katana depth=3)
    ↓
4. Pattern Detection (gf)
    ├─→ XSS patterns
    ├─→ SQLi patterns
    └─→ IDOR patterns
    ↓
5. AI Report Generation
    → Risk scoring
    → Category grouping
    → JSON export
```

---

## Example Workflow

```bash
# 1. Install hb-recon (from source)
git clone https://github.com/mrhlaingbwardev/hb-recon.git
cd hb-recon
pip install -e .

# 2. Run scan
python -m hb_recon
# Enter: bugcrowd.com

# 3. Wait 30-60 seconds

# 4. Check results
cd recon_bugcrowd.com
cat ai_report.json

# 5. Analyze with AI
# Copy ai_report.json content to ChatGPT/Claude
```

---

## Security Notice

⚠️ **Only use on authorized targets.**

This tool is for:
- Bug bounty programs (with scope)
- Authorized penetration testing
- Your own infrastructure

Unauthorized scanning is **illegal** and violates:
- Computer Fraud and Abuse Act (CFAA)
- Most countries' cybercrime laws
- Bug bounty program rules

**You are responsible for your actions.**

---

## Troubleshooting

### "Command not found" errors

**Problem:** Tool binaries not in PATH

**Solution:**
```bash
# Add Go bin to PATH (add to ~/.bashrc or ~/.zshrc)
export PATH="$HOME/go/bin:$PATH"

# Reload shell
source ~/.bashrc
```

### "Platform Error" on Windows

**Problem:** hb-recon requires Linux/WSL

**Solution:**
```bash
# Use WSL (Windows Subsystem for Linux)
wsl -d kali-linux
pip install hb-recon
python -m hb_recon
```

### Network timeouts

**Problem:** Slow/unstable connection

**Solution:**
```bash
# Increase timeout in cli.py
# Default: timeout=300 (5 minutes)
```

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## License

MIT License - See [LICENSE](LICENSE)

---

## Author

**Hlaing Bwar**  
- GitHub: [@mrhlaingbwardev](https://github.com/mrhlaingbwardev)
- Website: [hlaingbwar.me](https://www.hlaingbwar.me)

---

**Made with ❤️ for the bug bounty community**

**Disclaimer:** This tool is for educational and authorized testing only. Misuse may result in legal consequences.

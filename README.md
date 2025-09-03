# OWASP Top 10 Web Scanner

A comprehensive automated web application security scanner that orchestrates multiple security testing tools to identify vulnerabilities based on the OWASP Top 10.

## 🎯 Features

- **Automated Web Crawling**: Discovers URLs, forms, and API endpoints using gospider and hakrawler
- **SQL Injection Detection**: Tests for SQL injection vulnerabilities using sqlmap and custom payloads
- **XSS Detection**: Identifies reflected, stored, and DOM-based XSS vulnerabilities
- **Path Enumeration**: Discovers hidden directories and sensitive files
- **Security Header Analysis**: Checks for missing or misconfigured security headers
- **Form Testing**: Automatically discovers and tests HTML forms for vulnerabilities
- **Comprehensive Reporting**: Generates detailed HTML and JSON reports

## 📋 Prerequisites

- Python 3.7+
- Go 1.18+
- Linux, macOS, or WSL on Windows

## 🚀 Quick Installation

### Automated Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/owasp-scanner.git
cd owasp-scanner

# Run the setup script
chmod +x setup.sh
./setup.sh

# Reload your shell configuration
source ~/.bashrc  # or ~/.zshrc on macOS

# Install Python dependencies
pip3 install -r requirements.txt
```

### Manual Installation

If the automated setup fails, install these tools manually:

**Go-based tools:**

```bash
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/ffuf/ffuf@latest
go install -v github.com/OJ/gobuster/v3@latest
```

**Git-based tools:**

```bash
# SQLMap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap

# XSStrike
git clone https://github.com/s0md3v/XSStrike.git ~/tools/XSStrike
pip3 install -r ~/tools/XSStrike/requirements.txt
```

**Python dependencies:**

```bash
pip3 install rich beautifulsoup4 lxml aiohttp urllib3 requests
```

## 💻 Usage

### Basic Scan

```bash
python3 orchestrator.py -t https://example.com
```

### Advanced Options

```bash
# Specify output directory
python3 orchestrator.py -t https://example.com -o ./scan_results

# Run specific modules only
python3 orchestrator.py -t https://example.com -m crawler,sql,xss

# Use custom configuration
python3 orchestrator.py -t https://example.com -c config.json

# Verbose output
python3 orchestrator.py -t https://example.com -v

# Check if all tools are installed
python3 orchestrator.py --check-tools
```

### Available Modules

- `crawler` - Web crawling and URL discovery
- `filter` - URL filtering and categorization
- `sql` - SQL injection testing
- `xss` - Cross-site scripting testing
- `paths` - Path enumeration and directory brute-forcing
- `headers` - Security header analysis

## 🔧 Configuration

Create a `config.json` file to customize scan parameters:

```json
{
  "general": {
    "user_agents": [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ],
    "timeout": 30
  },
  "crawler": {
    "depth": 3,
    "concurrency": 10,
    "include_subdomains": false,
    "delay": 1
  },
  "sqlmap": {
    "level": 2,
    "risk": 2,
    "threads": 5,
    "technique": "BEUSTQ",
    "batch": true
  },
  "xss": {
    "payload_level": 6,
    "timeout": 20,
    "skip_dom": false
  }
}
```

## 🧪 Testing Your Scanner

### Setting Up the Test Environment

1. Save the provided vulnerable PHP application as `index.php`
2. Start a PHP development server:

```bash
# Make sure SQLite extension is enabled in PHP
php -S localhost:8000
```

3. Run the scanner against the test application:

```bash
python3 orchestrator.py -t http://localhost:8000 -v
```

### Expected Vulnerabilities to Detect

The test application contains:

- **SQL Injection** in login form (username/password fields)
- **SQL Injection** in search functionality (GET parameter)
- **Reflected XSS** in comment form (POST)
- **Reflected XSS** in search results (GET)
- **Stored XSS** simulation in stored_comment field

## 📊 Output

The scanner generates:

- **JSON Report** (`complete_results.json`) - Machine-readable results
- **HTML Report** (`security_report.html`) - Human-readable report with charts
- **Intermediate Results** - Individual module outputs for debugging

## 🐛 Troubleshooting

### Common Issues

**1. Tools not found:**

```bash
# Check if tools are in PATH
which gospider hakrawler sqlmap

# Add tools to PATH manually
export PATH=$PATH:$HOME/go/bin:$HOME/tools/sqlmap
```

**2. Permission denied:**

```bash
# Make scripts executable
chmod +x setup.sh
chmod +x orchestrator.py
```

**3. Module import errors:**

```bash
# Ensure you're in the correct directory
cd /path/to/owasp-scanner

# Reinstall dependencies
pip3 install --upgrade -r requirements.txt
```

**4. Gospider delay parameter error:**
The scanner has been fixed to pass the delay parameter correctly to gospider (as an integer without "s" suffix).

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Usage against targets without explicit permission is illegal and unethical. The authors assume no liability for misuse of this tool.

**Always ensure you have:**

- Written authorization to test the target
- Understanding of the scope and limitations
- Compliance with local laws and regulations

## 📜 License

MIT License - See LICENSE file for details

## 🔍 Known Limitations

- **JavaScript rendering**: The scanner doesn't execute JavaScript, so some dynamic content may be missed
- **Authentication**: Currently supports basic authentication only
- **Rate limiting**: Be mindful of target rate limits; adjust delays in configuration
- **WAF detection**: Some WAFs may block scanner traffic

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [XSStrike Documentation](https://github.com/s0md3v/XSStrike)

## 🏗️ Architecture

```
owasp-scanner/
├── orchestrator.py          # Main scanner orchestrator
├── modules/
│   ├── crawler.py          # Web crawling module
│   ├── filter.py           # URL filtering and categorization
│   ├── sql_injection.py    # SQL injection testing
│   ├── xss.py              # XSS testing
│   ├── path_enum.py        # Path enumeration
│   ├── header_check.py     # Security header analysis
│   ├── report.py           # Report generation
│   └── utils.py            # Utility functions
├── config.json             # Configuration file (optional)
├── requirements.txt        # Python dependencies
├── setup.sh               # Automated setup script
└── results/               # Scan results directory
```

## 📈 Roadmap

- [ ] Add authentication support (OAuth, JWT)
- [ ] Implement parallel scanning for multiple targets
- [ ] Add API scanning capabilities
- [ ] Integrate more OWASP Top 10 checks
- [ ] Add WebSocket testing
- [ ] Implement custom vulnerability signatures
- [ ] Add CI/CD integration examples
- [ ] Create Docker container

## 💡 Tips for Effective Scanning

1. **Start with crawling only** to understand the target structure:

   ```bash
   python3 orchestrator.py -t https://example.com -m crawler,filter
   ```

2. **Test in stages** to avoid overwhelming the target:

   ```bash
   # First: Discovery
   python3 orchestrator.py -t https://example.com -m crawler,filter,paths
   
   # Then: Vulnerability testing
   python3 orchestrator.py -t https://example.com -m sql,xss
   ```

3. **Adjust delays** for slow or rate-limited targets:

   ```json
   {
     "crawler": {"delay": 2},
     "sqlmap": {"delay": 3}
   }
   ```

4. **Use verbose mode** for debugging:

   ```bash
   python3 orchestrator.py -t https://example.com -v 2>&1 | tee scan.log
   ```

## 🆘 Support

For issues, questions, or suggestions:

- Open an issue on GitHub
- Check existing issues for solutions
- Provide detailed logs when reporting problems

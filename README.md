# DNScope

A powerful DNS reconnaissance and enumeration tool designed for security researchers, penetration testers, and system administrators. DNScope helps you discover and map DNS records, subdomains, and network infrastructure.

## 📋 Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Windows](#windows)
  - [Kali Linux](#kali-linux)
  - [Ubuntu/Debian Linux](#ubuntudebian-linux)
- [Usage](#usage)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **DNS Enumeration**: Perform comprehensive DNS record enumeration
- **Subdomain Discovery**: Identify subdomains associated with target domains
- **Zone Transfer Detection**: Test for vulnerable DNS zone transfers
- **Reverse DNS Lookup**: Map IP addresses to domain names
- **DNS Brute Force**: Brute force common subdomains
- **SOA Record Analysis**: Extract and analyze SOA records
- **MX Record Enumeration**: Discover mail server configurations
- **NS Record Discovery**: Identify authoritative nameservers
- **TXT Record Analysis**: Retrieve and parse TXT records
- **SRV Record Enumeration**: Discover service records
- **Fast & Efficient**: Optimized for speed and minimal resource usage
- **Multiple Output Formats**: Support for JSON, CSV, and text output
- **Customizable Wordlists**: Use built-in or custom wordlists for brute forcing
- **Proxy Support**: Route requests through proxies if needed
- **Error Handling**: Robust error handling and logging

## 📦 Installation

### Windows

#### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git

#### Steps

1. **Download and Install Python**
   - Download Python from [python.org](https://www.python.org/downloads/)
   - During installation, make sure to check "Add Python to PATH"
   - Click "Install Now"

2. **Clone the Repository**
   ```bash
   git clone https://github.com/mrdineshpathro-dot/DNScope.git
   cd DNScope
   ```

3. **Create a Virtual Environment (Recommended)**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Verify Installation**
   ```bash
   python dnscope.py --help
   ```

### Kali Linux

#### Prerequisites
- Kali Linux (any recent version)
- Python 3.8+
- pip3

#### Steps

1. **Update System Packages**
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **Install Python and Dependencies**
   ```bash
   sudo apt install -y python3 python3-pip python3-venv git
   ```

3. **Clone the Repository**
   ```bash
   git clone https://github.com/mrdineshpathro-dot/DNScope.git
   cd DNScope
   ```

4. **Create a Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

5. **Install Python Requirements**
   ```bash
   pip3 install -r requirements.txt
   ```

6. **Make Script Executable (Optional)**
   ```bash
   chmod +x dnscope.py
   ```

7. **Verify Installation**
   ```bash
   python3 dnscope.py --help
   ```

### Ubuntu/Debian Linux

#### Prerequisites
- Ubuntu 18.04+ or Debian 10+
- Python 3.8+
- pip3

#### Steps

1. **Update Package Lists**
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **Install Required Packages**
   ```bash
   sudo apt install -y python3 python3-pip python3-venv git build-essential
   ```

3. **Clone the Repository**
   ```bash
   git clone https://github.com/mrdineshpathro-dot/DNScope.git
   cd DNScope
   ```

4. **Set Up Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

5. **Install Dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

6. **Make Script Executable**
   ```bash
   chmod +x dnscope.py
   ```

7. **Verify Installation**
   ```bash
   python3 dnscope.py --help
   ```

## 🚀 Usage

### Basic Usage

#### Simple DNS Lookup
```bash
python dnscope.py -d example.com
```

#### Subdomain Enumeration
```bash
python dnscope.py -d example.com --subdomains
```

#### Brute Force DNS Records
```bash
python dnscope.py -d example.com --brute-force
```

### Advanced Usage

#### With Custom Wordlist
```bash
python dnscope.py -d example.com --wordlist custom_wordlist.txt
```

#### Zone Transfer Attempt
```bash
python dnscope.py -d example.com --zone-transfer
```

#### Reverse DNS Lookup
```bash
python dnscope.py --reverse-lookup 8.8.8.8
```

#### Export Results
```bash
python dnscope.py -d example.com --output results.json --format json
```

```bash
python dnscope.py -d example.com --output results.csv --format csv
```

#### Enumeration with Multiple Record Types
```bash
python dnscope.py -d example.com --record-types A,MX,NS,TXT,SRV
```

#### Brute Force with Threading
```bash
python dnscope.py -d example.com --brute-force --threads 50
```

#### Proxy Support
```bash
python dnscope.py -d example.com --proxy http://proxy.example.com:8080
```

### Command Line Options

```
usage: dnscope.py [-h] [-d DOMAIN] [-w WORDLIST] [-o OUTPUT] [-f FORMAT]
                  [--subdomains] [--brute-force] [--zone-transfer]
                  [--reverse-lookup IP] [--threads THREADS]
                  [--record-types TYPES] [--proxy PROXY] [--timeout TIMEOUT]

options:
  -h, --help                Show help message
  -d, --domain DOMAIN       Target domain to enumerate
  -w, --wordlist WORDLIST   Custom wordlist for brute forcing
  -o, --output OUTPUT       Output file path
  -f, --format FORMAT       Output format (json, csv, txt)
  --subdomains              Enumerate subdomains
  --brute-force             Perform DNS brute forcing
  --zone-transfer           Attempt DNS zone transfer
  --reverse-lookup IP       Perform reverse DNS lookup
  --threads THREADS         Number of threads (default: 10)
  --record-types TYPES      Comma-separated record types (A,MX,NS,TXT,SRV)
  --proxy PROXY             Proxy URL for requests
  --timeout TIMEOUT         Request timeout in seconds (default: 5)
```

### Example Scenarios

#### Complete Reconnaissance
```bash
python dnscope.py -d example.com --subdomains --brute-force --threads 50 -o results.json --format json
```

#### Security Assessment
```bash
python dnscope.py -d example.com --record-types A,AAAA,MX,NS,TXT,SOA,SRV --output assessment.txt --format txt
```

#### Quick Scan
```bash
python dnscope.py -d example.com
```

## 📋 Requirements

- Python 3.8 or higher
- dnspython
- requests
- colorama (for colored output)
- argparse (built-in)

Install all requirements:
```bash
pip install -r requirements.txt
```

## ⚠️ Legal Disclaimer

DNScope is intended for authorized security testing and educational purposes only. Users are responsible for obtaining proper authorization before performing any security assessments. Unauthorized access to computer networks is illegal. Always follow applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Dinesh Pathro**
- GitHub: [@mrdineshpathro-dot](https://github.com/mrdineshpathro-dot)

## 🙏 Acknowledgments

- Built with Python and DNS libraries
- Inspired by popular DNS enumeration tools
- Thanks to the security community

## 📞 Support

For issues, questions, or suggestions, please open an issue on the [GitHub Issues](https://github.com/mrdineshpathro-dot/DNScope/issues) page.

---

**Last Updated**: September 2026

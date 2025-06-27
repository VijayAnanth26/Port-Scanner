# 🔍 Network Port Scanner

A comprehensive Python-based tool to scan open TCP ports on a given IP address, with both CLI and web interface options.

## 🚀 Features

- **Multithreaded scanning** for high performance
- **Dual interfaces**: CLI and Streamlit web UI
- **Enhanced service identification** with custom service database
- **Banner grabbing** for deeper service detection
- **Vulnerability assessment** for common security issues
- **PDF and CSV report generation** with detailed findings
- **Progress tracking** with real-time updates
- **Colorized CLI output** for better readability
- **Multiple output formats** (console, JSON, TXT, CSV)
- **Hostname resolution** for target IPs
- **Detailed port information** with security notes

## 🧪 CLI Usage

```bash
# Basic scan of default ports (1-1024)
python scanner.py 127.0.0.1

# Scan specific port range
python scanner.py 192.168.1.1 -p 20-100

# Scan with vulnerability checks and save results to JSON
python scanner.py 10.0.0.1 --vuln -o results.json

# Scan only top common ports with verbose output and banner grabbing
python scanner.py scanme.nmap.org --top-ports -v --banner

# Scan comma-separated ports and save as CSV file
python scanner.py 172.16.0.1 -p 22,80,443,3389 -o results.csv -f csv

# Deep scan with hostname resolution
python scanner.py 8.8.8.8 --banner --vuln --resolve
```

## 🌐 Web Interface

```bash
# Start the Streamlit web interface
streamlit run app.py
```

## ⚙️ CLI Options

| Option                | Description                                       |
| --------------------- | ------------------------------------------------- |
| `ip`                  | Target IP address                                 |
| `-p`, `--ports`       | Port range (default: 1–1024) or comma-separated list |
| `-v`, `--verbose`     | Show detailed information during scan             |
| `-o`, `--output`      | Save results to file (specify filename)           |
| `-f`, `--format`      | Output format (json, txt, or csv)                 |
| `--vuln`              | Check for common vulnerabilities                  |
| `--banner`            | Attempt to grab service banners                   |
| `--top-ports`         | Scan only the most common ports                   |
| `--no-banner`         | Don't display the banner                          |
| `--resolve`           | Resolve hostname of the target IP                 |

## 📊 Web Interface Features

- **User-friendly form** for scan configuration
- **Interactive visualizations** of scan results
- **Deep scan option** for banner grabbing
- **Hostname resolution** for target IPs
- **Detailed port information** with expandable sections
- **PDF and CSV report generation** with security recommendations
- **Port information database** with searchable interface
- **Real-time progress tracking**

## 📦 Tech Stack

* Python 3
* Socket Programming
* ThreadPoolExecutor
* Streamlit
* Pandas
* Plotly
* FPDF
* ipaddress

## 📋 Installation

```bash
# Install required packages using requirements.txt
pip install -r requirements.txt
```

## 📄 Reports

The scanner can generate comprehensive reports in multiple formats:

- **PDF Reports**: Include scan summary, port details, vulnerabilities, and security recommendations
- **CSV Reports**: Tabular data for easy import into spreadsheets or databases
- **JSON Reports**: Structured data for programmatic processing
- **TXT Reports**: Simple text format for quick review

## 🔒 Security Features

- **Enhanced service detection** for better identification
- **Banner grabbing** to identify service versions
- **Vulnerability assessment** for common ports
- **Security recommendations** based on findings
- **Detailed port information** with security notes

## 🌟 Enhanced Service Detection

The scanner uses multiple methods to identify services:

1. **Standard service database** - System's service database for well-known ports
2. **Custom service mapping** - Built-in database of common services
3. **Banner grabbing** - Active probing for service identification

## 📦 Project Structure

The project is organized as follows:

- **Scanner.py**: Core scanning functionality and CLI interface
- **app.py**: Streamlit web interface that imports core functions from Scanner.py
- **requirements.txt**: Dependencies required for the project

This modular design reduces code duplication and ensures consistency between the CLI and web interfaces.

## 📜 License

MIT 
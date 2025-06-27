# 🔍 Network Port Scanner CLI

A Python-based command-line tool to scan open TCP ports on a given IP address.

## 🚀 Features
- Scan any IP address with custom port ranges
- Multithreaded scanning (fast!)
- Timeout and exception handling
- Simple command-line interface

## 🧪 Example Usage

```bash
python3 scanner.py 127.0.0.1 -p 20-100 -t 0.5
```

## ⚙️ Options

| Option              | Description                        |
| ------------------- | ---------------------------------- |
| `ip`                | Target IP (e.g., 192.168.1.1)      |
| `-p` or `--ports`   | Port range (default: 1–1024)       |
| `-t` or `--timeout` | Timeout per port scan (in seconds) |
| `-T` or `--threads` | Number of threads (default: 100)   |

## 📦 Tech Stack

* Python 3
* Socket Programming
* argparse
* ThreadPoolExecutor

## 📜 License

MIT 
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="TCP Port Scanner CLI Tool")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 20-80)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout per port (sec)")
    parser.add_argument("-T", "--threads", type=int, default=100, help="Number of threads (default: 100)")

    args = parser.parse_args()
    start_port, end_port = map(int, args.ports.split("-"))

    print(f"\n🔍 Scanning {args.ip} from port {start_port} to {end_port}...\n")
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_port, args.ip, port, args.timeout) for port in range(start_port, end_port + 1)]
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)

    if open_ports:
        print(f"\n✅ Open ports on {args.ip}: {', '.join(map(str, open_ports))}")
    else:
        print("\n❌ No open ports found.")

if __name__ == "__main__":
    main()

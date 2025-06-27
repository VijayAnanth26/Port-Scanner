import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
import sys
import time
import json
import os
import platform
import ipaddress

# ANSI colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Check if we're on Windows and enable ANSI colors
if platform.system() == "Windows":
    os.system('color')

# Default values for timeout and threads
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100

# Common service mapping used by both CLI and web interface
def get_enhanced_service_name(port):
    """Get service name with enhanced detection"""
    # First try the standard service lookup
    try:
        return socket.getservbyport(port)
    except:
        # If standard lookup fails, use our custom mapping
        custom_services = {
            # Web and application servers
            3000: "Node.js/Development Server",
            3001: "Development Server",
            5000: "Flask/Development Server",
            8000: "Web Server",
            8080: "Alternative HTTP",
            8443: "Alternative HTTPS",
            8500: "Consul",
            8501: "Streamlit",
            8888: "Jupyter Notebook",
            9000: "Web Server",
            
            # Database ports
            1433: "MS SQL Server",
            1521: "Oracle DB",
            3306: "MySQL/MariaDB",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            
            # Windows specific
            135: "MSRPC",
            139: "NetBIOS",
            445: "SMB",
            3389: "RDP",
            5040: "Windows Media Connect",
            5357: "Web Services for Devices",
            
            # Other common services
            22: "SSH",
            5353: "mDNS",
            5354: "mDNS/DNS-SD",
            5900: "VNC",
            5938: "TeamViewer",
        }
        
        return custom_services.get(port, "Unknown")

def grab_banner(ip, port, timeout=DEFAULT_TIMEOUT):
    """Attempt to grab service banner"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Send common protocol-specific queries
            if port == 80 or port == 8080 or port == 8000:
                s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP servers typically send banner on connect
            elif port == 22:
                pass  # SSH servers typically send banner on connect
            elif port == 25 or port == 587:
                s.send(b"EHLO example.com\r\n")
            
            # Receive data
            banner = s.recv(1024)
            
            # Clean and decode the banner
            try:
                banner_text = banner.decode('utf-8', errors='ignore').strip()
                # Remove control characters
                banner_text = ''.join(c for c in banner_text if c.isprintable())
                return banner_text[:100] if banner_text else "No banner"
            except:
                return "Binary data received"
                
    except Exception:
        return "No banner available"

def check_vulnerability(port, service=None):
    """Check for common vulnerabilities based on port"""
    vulnerabilities = {
        21: "FTP might allow anonymous access or have outdated versions with vulnerabilities.",
        22: "SSH may have weak configurations or outdated versions.",
        23: "Telnet sends data in cleartext, posing a security risk.",
        25: "SMTP might be vulnerable to relay attacks or information disclosure.",
        53: "DNS may be vulnerable to cache poisoning or amplification attacks.",
        80: "HTTP services may have various web vulnerabilities (XSS, SQLi, etc.).",
        443: "HTTPS might have SSL/TLS vulnerabilities if using outdated versions.",
        445: "SMB has had critical vulnerabilities (e.g., EternalBlue).",
        1433: "SQL Server may have authentication or injection vulnerabilities.",
        3306: "MySQL might have authentication or injection vulnerabilities.",
        3389: "RDP has had multiple vulnerabilities, including BlueKeep.",
        5432: "PostgreSQL may have authentication or injection vulnerabilities.",
        6379: "Redis without authentication is vulnerable to remote attacks.",
        8080: "Alternative HTTP port may have web vulnerabilities or be unintentionally exposed.",
        8443: "Alternative HTTPS port may have SSL/TLS vulnerabilities.",
        27017: "MongoDB without authentication is vulnerable to data theft."
    }
    
    # Check by port first
    if port in vulnerabilities:
        return vulnerabilities[port]
    
    # If service name is provided, check by service keywords
    if service:
        service_lower = service.lower()
        if "http" in service_lower:
            return "Web services may have various vulnerabilities (XSS, SQLi, etc.)."
        elif "sql" in service_lower or "db" in service_lower or "database" in service_lower:
            return "Database services may have authentication or injection vulnerabilities."
        elif "ftp" in service_lower:
            return "FTP might allow anonymous access or have outdated versions with vulnerabilities."
        elif "ssh" in service_lower:
            return "SSH may have weak configurations or outdated versions."
        elif "telnet" in service_lower:
            return "Telnet sends data in cleartext, posing a security risk."
    
    return "No common vulnerabilities known"

def is_valid_ip(ip):
    """Check if the IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_hostname(ip):
    """Attempt to get hostname from IP"""
    try:
        if is_valid_ip(ip):
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        return None
    except:
        return None

def scan_port(ip, port, timeout=DEFAULT_TIMEOUT, grab_banners=False, check_vulns=False):
    """Scan a single port and return details if open"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                # Get service name with enhanced detection
                service = get_enhanced_service_name(port)
                
                # Grab banner if requested
                banner = grab_banner(ip, port, timeout) if grab_banners else "No banner available"
                
                # Check for vulnerabilities if requested
                vulnerability = check_vulnerability(port, service) if check_vulns else "Not checked"
                
                return {
                    "port": port,
                    "status": "Open",
                    "service": service,
                    "banner": banner,
                    "vulnerability": vulnerability
                }
    except Exception:
        pass
    return None

def print_banner():
    """Print a fancy banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  {Colors.GREEN}███╗   ██╗███████╗████████╗{Colors.CYAN} ███████╗ ██████╗ █████╗ ███╗   ██╗{Colors.CYAN}  ║
║  {Colors.GREEN}████╗  ██║██╔════╝╚══██╔══╝{Colors.CYAN} ██╔════╝██╔════╝██╔══██╗████╗  ██║{Colors.CYAN}  ║
║  {Colors.GREEN}██╔██╗ ██║█████╗     ██║   {Colors.CYAN} ███████╗██║     ███████║██╔██╗ ██║{Colors.CYAN}  ║
║  {Colors.GREEN}██║╚██╗██║██╔══╝     ██║   {Colors.CYAN} ╚════██║██║     ██╔══██║██║╚██╗██║{Colors.CYAN}  ║
║  {Colors.GREEN}██║ ╚████║███████╗   ██║   {Colors.CYAN} ███████║╚██████╗██║  ██║██║ ╚████║{Colors.CYAN}  ║
║  {Colors.GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Colors.CYAN} ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Colors.CYAN}  ║
║                                                           ║
║  {Colors.WARNING}Port Scanner v2.5{Colors.CYAN}                                      ║
║  {Colors.WARNING}A multithreaded TCP port scanner with enhanced detection{Colors.CYAN}║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)

def save_results(results, filename, format="json"):
    """Save scan results to a file"""
    if format == "json":
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
    elif format == "txt":
        with open(filename, 'w') as f:
            f.write(f"Scan Results for {results['target']}\n")
            f.write(f"Scan Time: {results['scan_time']:.2f} seconds\n")
            f.write(f"Open Ports: {len(results['open_ports'])}\n\n")
            
            f.write("PORT\tSTATUS\tSERVICE\tVULNERABILITY\n")
            f.write("-" * 80 + "\n")
            
            for port in results['open_ports']:
                vuln = port.get('vulnerability', 'None')
                f.write(f"{port['port']}\t{port['status']}\t{port['service']}\t{vuln}\n")
                
                # Include banner if available
                if port.get('banner') and port['banner'] != "No banner available":
                    f.write(f"\tBanner: {port['banner']}\n")
            
    elif format == "csv":
        with open(filename, 'w') as f:
            # Write header
            headers = ["port", "status", "service"]
            
            # Add vulnerability and banner headers if needed
            if any(port.get('vulnerability') for port in results['open_ports']):
                headers.append("vulnerability")
            
            if any(port.get('banner') and port['banner'] != "No banner available" for port in results['open_ports']):
                headers.append("banner")
            
            f.write(",".join(headers) + "\n")
            
            # Write data
            for port in results['open_ports']:
                row = [
                    str(port['port']),
                    port['status'],
                    port['service']
                ]
                
                # Add vulnerability if in headers
                if "vulnerability" in headers:
                    row.append(port.get('vulnerability', ''))
                
                # Add banner if in headers
                if "banner" in headers and port.get('banner'):
                    banner_text = port['banner'].replace(',', ' ').replace('\n', ' ')
                    row.append(banner_text)
                elif "banner" in headers:
                    row.append("")
                
                f.write(",".join(row) + "\n")
    
    print(f"\n{Colors.GREEN}Results saved to {filename}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced TCP Port Scanner CLI Tool")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 20-80) or comma-separated list")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    parser.add_argument("-o", "--output", help="Save results to file (specify filename)")
    parser.add_argument("-f", "--format", choices=["json", "txt", "csv"], default="json", help="Output format (json, txt, or csv)")
    parser.add_argument("--vuln", action="store_true", help="Check for common vulnerabilities")
    parser.add_argument("--banner", action="store_true", help="Attempt to grab service banners")
    parser.add_argument("--top-ports", action="store_true", help="Scan only the most common ports")
    parser.add_argument("--no-banner", action="store_true", help="Don't display the banner")
    parser.add_argument("--resolve", action="store_true", help="Resolve hostname of the target IP")

    args = parser.parse_args()
    
    # Validate IP address
    if not is_valid_ip(args.ip):
        print(f"{Colors.FAIL}Error: Invalid IP address. Please enter a valid IP.{Colors.ENDC}")
        sys.exit(1)
    
    if not args.no_banner:
        print_banner()
    
    # Resolve hostname if requested
    if args.resolve:
        hostname = get_hostname(args.ip)
        if hostname:
            print(f"{Colors.CYAN}Hostname: {hostname}{Colors.ENDC}")
    
    # Handle top ports option
    if args.top_ports:
        top_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 
                     1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        ports_to_scan = top_ports
        print(f"\n{Colors.CYAN}🔍 Scanning {args.ip} for top {len(top_ports)} common ports...{Colors.ENDC}\n")
    else:
        # Parse port range
        try:
            if "-" in args.ports:
                start_port, end_port = map(int, args.ports.split("-"))
                ports_to_scan = list(range(start_port, end_port + 1))
            elif "," in args.ports:
                ports_to_scan = [int(p) for p in args.ports.split(",")]
            else:
                ports_to_scan = [int(args.ports)]
                
            print(f"\n{Colors.CYAN}🔍 Scanning {args.ip} for {len(ports_to_scan)} ports...{Colors.ENDC}\n")
        except ValueError:
            print(f"{Colors.FAIL}Error: Invalid port range format. Use start-end (e.g., 20-80) or comma-separated values.{Colors.ENDC}")
            sys.exit(1)
    
    open_ports = []
    start_time = time.time()
    
    # Show a progress bar if not in verbose mode
    if not args.verbose:
        total_ports = len(ports_to_scan)
        scanned = 0
        
    with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
        futures = [executor.submit(scan_port, args.ip, port, DEFAULT_TIMEOUT, args.banner, args.vuln) for port in ports_to_scan]
        
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
                if args.verbose:
                    port_info = result
                    banner_info = f" - {Colors.BLUE}Banner: {port_info['banner']}{Colors.ENDC}" if port_info.get('banner') and port_info['banner'] != "No banner available" else ""
                    vuln_info = f" - {Colors.WARNING}{port_info['vulnerability']}{Colors.ENDC}" if port_info.get('vulnerability') and port_info['vulnerability'] != "Not checked" else ""
                    print(f"{Colors.GREEN}[+] Port {port_info['port']}/tcp open - {port_info['service']}{Colors.ENDC}{banner_info}{vuln_info}")
            
            # Update progress bar if not in verbose mode
            if not args.verbose:
                scanned += 1
                progress = int(50 * scanned / total_ports)
                sys.stdout.write(f"\r[{'#' * progress}{' ' * (50 - progress)}] {scanned}/{total_ports} ports")
                sys.stdout.flush()
    
    scan_time = time.time() - start_time
    
    # Clear the progress bar line
    if not args.verbose:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
    
    # Sort open ports by port number
    open_ports.sort(key=lambda x: x["port"])
    
    if open_ports:
        print(f"\n\n{Colors.GREEN}✅ Found {len(open_ports)} open ports on {args.ip} in {scan_time:.2f} seconds:{Colors.ENDC}")
        
        # Print table header
        headers = ["PORT", "STATUS", "SERVICE"]
        if args.vuln:
            headers.append("VULNERABILITY")
        if args.banner:
            headers.append("BANNER")
        
        print(f"\n{Colors.BOLD}{headers[0]:<10}{headers[1]:<10}{headers[2]:<20}", end="")
        if args.vuln:
            print(f"{headers[3]:<30}", end="")
        if args.banner:
            print(f"{headers[4]}", end="")
        print(f"{Colors.ENDC}")
        
        print("-" * (40 + (30 if args.vuln else 0) + (30 if args.banner else 0)))
        
        # Print each open port
        for port_info in open_ports:
            print(f"{port_info['port']:<10}{port_info['status']:<10}{port_info['service']:<20}", end="")
            
            if args.vuln:
                vuln_text = port_info.get('vulnerability', '')
                if len(vuln_text) > 27:
                    vuln_text = vuln_text[:24] + "..."
                print(f"{vuln_text:<30}", end="")
                
            if args.banner:
                banner_text = port_info.get('banner', '')
                if banner_text == "No banner available":
                    banner_text = ""
                elif len(banner_text) > 30:
                    banner_text = banner_text[:27] + "..."
                print(f"{banner_text}", end="")
                
            print()
    else:
        print(f"\n\n{Colors.FAIL}❌ No open ports found on {args.ip} in {scan_time:.2f} seconds.{Colors.ENDC}")
    
    # Save results if output file specified
    if args.output:
        results = {
            "target": args.ip,
            "scan_time": scan_time,
            "open_ports": open_ports
        }
        save_results(results, args.output, args.format)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.FAIL}Scan interrupted by user.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n{Colors.FAIL}An error occurred: {str(e)}{Colors.ENDC}")
        sys.exit(1)

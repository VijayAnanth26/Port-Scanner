import streamlit as st
import socket
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import time
import plotly.graph_objects as go
from fpdf import FPDF
import datetime
import ipaddress
import re

# Import common functions from Scanner.py
from Scanner import (
    get_enhanced_service_name,
    grab_banner,
    check_vulnerability,
    is_valid_ip,
    get_hostname,
    DEFAULT_TIMEOUT,
    DEFAULT_THREADS
)

# Default values for timeout and threads
DEFAULT_TIMEOUT = 1.0
DEFAULT_THREADS = 100

st.set_page_config(
    page_title="Network Port Scanner",
    page_icon="🔍",
    layout="wide",
)

# Custom CSS to improve the appearance
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #424242;
    }
    .info-box {
        background-color: #E3F2FD;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .success-box {
        background-color: #E8F5E9;
        padding: 1rem;
        border-radius: 0.5rem;
    }
    .warning-box {
        background-color: #FFF8E1;
        padding: 1rem;
        border-radius: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

def scan_port(ip, port, timeout=DEFAULT_TIMEOUT):
    """Scan a single port and return details if open"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                # Enhanced service detection
                service = get_enhanced_service_name(port)
                
                # Perform banner grabbing if deep scan is enabled
                banner = grab_banner(ip, port, timeout) if deep_scan else None
                
                # Check for common vulnerabilities
                vulnerability = check_vulnerability(port, service)
                
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

def get_common_ports_info():
    """Return information about common ports"""
    return {
        20: "FTP (Data)",
        21: "FTP (Control)",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MS SQL Server",
        3306: "MySQL/MariaDB",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
        27017: "MongoDB"
    }

def get_port_details(port):
    """Get detailed information about a specific port"""
    port_details = {
        21: {
            "service": "FTP (File Transfer Protocol)",
            "description": "Used for transferring files between a client and server.",
            "common_usage": "File uploads/downloads, website management",
            "security_notes": "Often vulnerable to brute force attacks and anonymous access."
        },
        22: {
            "service": "SSH (Secure Shell)",
            "description": "Encrypted protocol for secure remote login and command execution.",
            "common_usage": "Remote server administration, secure file transfers",
            "security_notes": "More secure than telnet, but can be targeted by brute force attacks."
        },
        23: {
            "service": "Telnet",
            "description": "Unencrypted protocol for remote terminal connections.",
            "common_usage": "Legacy remote administration",
            "security_notes": "Highly insecure as it transmits data in plaintext."
        },
        25: {
            "service": "SMTP (Simple Mail Transfer Protocol)",
            "description": "Protocol for sending email across networks.",
            "common_usage": "Email delivery",
            "security_notes": "Can be abused for spam if not properly secured."
        },
        53: {
            "service": "DNS (Domain Name System)",
            "description": "Translates domain names to IP addresses.",
            "common_usage": "Domain name resolution",
            "security_notes": "Can be vulnerable to cache poisoning and amplification attacks."
        },
        80: {
            "service": "HTTP",
            "description": "Protocol for transmitting web pages.",
            "common_usage": "Web browsing",
            "security_notes": "Unencrypted web traffic can be intercepted."
        },
        443: {
            "service": "HTTPS",
            "description": "Secure version of HTTP using TLS/SSL encryption.",
            "common_usage": "Secure web browsing, online banking, e-commerce",
            "security_notes": "Much more secure than HTTP, but can have SSL/TLS vulnerabilities."
        },
        445: {
            "service": "SMB (Server Message Block)",
            "description": "Protocol for sharing files, printers, and other resources.",
            "common_usage": "Windows file sharing, network drives",
            "security_notes": "Has been the target of major exploits like EternalBlue."
        },
        3306: {
            "service": "MySQL/MariaDB",
            "description": "Popular open-source database management system.",
            "common_usage": "Database for web applications",
            "security_notes": "Should not be exposed to the internet without proper security."
        },
        3389: {
            "service": "RDP (Remote Desktop Protocol)",
            "description": "Microsoft's protocol for remote desktop connections.",
            "common_usage": "Remote desktop access to Windows systems",
            "security_notes": "Target of numerous exploits including BlueKeep."
        },
        5432: {
            "service": "PostgreSQL",
            "description": "Advanced open-source relational database.",
            "common_usage": "Database for applications requiring complex queries and data integrity",
            "security_notes": "Should be configured with proper authentication and not exposed publicly."
        },
        8080: {
            "service": "HTTP Alternate",
            "description": "Alternative port for web servers, often used for proxies or development.",
            "common_usage": "Web applications, development servers, proxies",
            "security_notes": "May have the same vulnerabilities as regular HTTP services."
        },
        8501: {
            "service": "Streamlit",
            "description": "Port used by Streamlit web applications.",
            "common_usage": "Data science and machine learning web applications",
            "security_notes": "Should be properly secured if exposed beyond localhost."
        }
    }
    
    return port_details.get(port, {
        "service": "Unknown",
        "description": "Information not available",
        "common_usage": "Varies",
        "security_notes": "Unknown"
    })

def create_pdf_report(ip_address, scan_results, scan_time, timestamp):
    """Create a PDF report of scan results"""
    pdf = FPDF()
    pdf.add_page()
    
    # Set up the PDF
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Network Port Scanner - Scan Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Scan Date: {timestamp}", ln=True)
    pdf.cell(0, 10, f"Target IP: {ip_address}", ln=True)
    
    # Try to get hostname
    hostname = get_hostname(ip_address)
    if hostname:
        pdf.cell(0, 10, f"Hostname: {hostname}", ln=True)
    
    pdf.cell(0, 10, f"Scan Duration: {scan_time:.2f} seconds", ln=True)
    pdf.cell(0, 10, f"Open Ports Found: {len(scan_results)}", ln=True)
    
    # Add scan results table
    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(20, 10, "Port", 1)
    pdf.cell(40, 10, "Service", 1)
    pdf.cell(0, 10, "Vulnerability", 1, ln=True)
    
    pdf.set_font("Arial", "", 10)
    for result in scan_results:
        pdf.cell(20, 10, str(result["port"]), 1)
        pdf.cell(40, 10, result["service"], 1)
        
        # Handle long vulnerability text
        vulnerability_text = result["vulnerability"]
        if len(vulnerability_text) > 80:
            chunks = [vulnerability_text[i:i+80] for i in range(0, len(vulnerability_text), 80)]
            pdf.cell(0, 10, chunks[0], 1, ln=True)
            for chunk in chunks[1:]:
                pdf.cell(60, 10, "", 0)  # Empty cells for alignment
                pdf.cell(0, 10, chunk, 1, ln=True)
        else:
            pdf.cell(0, 10, vulnerability_text, 1, ln=True)
    
    # Add banner information if available
    has_banners = any(result.get("banner") for result in scan_results)
    if has_banners:
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Service Banners", ln=True)
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(20, 10, "Port", 1)
        pdf.cell(0, 10, "Banner", 1, ln=True)
        
        pdf.set_font("Arial", "", 10)
        for result in scan_results:
            if result.get("banner"):
                pdf.cell(20, 10, str(result["port"]), 1)
                banner_text = result["banner"]
                if len(banner_text) > 100:
                    banner_text = banner_text[:97] + "..."
                pdf.cell(0, 10, banner_text, 1, ln=True)
    
    # Add port details for open ports
    if scan_results:
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Detailed Port Information", ln=True)
        
        for result in scan_results:
            port = result["port"]
            details = get_port_details(port)
            
            pdf.ln(5)
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, f"Port {port} - {details['service']}", ln=True)
            
            pdf.set_font("Arial", "", 10)
            pdf.multi_cell(0, 10, f"Description: {details['description']}")
            pdf.multi_cell(0, 10, f"Common Usage: {details['common_usage']}")
            pdf.multi_cell(0, 10, f"Security Notes: {details['security_notes']}")
    
    # Add recommendations
    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Security Recommendations", ln=True)
    
    pdf.set_font("Arial", "", 10)
    recommendations = [
        "Close unnecessary ports to reduce attack surface",
        "Use firewalls to restrict access to essential services only",
        "Keep all services updated with security patches",
        "Use strong authentication for all network services",
        "Consider implementing intrusion detection systems",
        "Regularly scan for vulnerabilities and monitor logs"
    ]
    
    for rec in recommendations:
        pdf.cell(10, 10, "-", 0)  # Using hyphen instead of bullet point
        pdf.cell(0, 10, rec, 0, ln=True)
    
    # Add footer
    pdf.ln(10)
    pdf.set_font("Arial", "I", 8)
    pdf.cell(0, 10, "This report is for informational purposes only. Always consult with a security professional.", ln=True, align="C")
    
    return pdf.output(dest='S').encode('latin1')

def main():
    st.markdown('<h1 class="main-header">🔍 Network Port Scanner</h1>', unsafe_allow_html=True)
    st.markdown('<h2 class="sub-header">Scan for open TCP ports on any IP address</h2>', unsafe_allow_html=True)
    
    tabs = st.tabs(["Scanner", "Port Information", "About"])
    
    with tabs[0]:  # Scanner tab
        ip_address = st.text_input("Target IP Address", value="127.0.0.1")
        
        col_port1, col_port2 = st.columns(2)
        with col_port1:
            start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
        with col_port2:
            end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024)
        
        # Advanced options
        with st.expander("Advanced Options"):
            global deep_scan
            deep_scan = st.checkbox("Deep Scan (Banner Grabbing)", value=False, 
                                  help="Attempts to identify services by grabbing banners. May increase scan time.")
            resolve_hostname = st.checkbox("Resolve Hostname", value=True,
                                        help="Attempts to resolve the hostname of the target IP.")
        
        scan_button = st.button("Start Scan", type="primary")
        
        if scan_button:
            # Validate IP address
            if not is_valid_ip(ip_address):
                st.error("Invalid IP address. Please enter a valid IP.")
            elif end_port < start_port:
                st.error("End port must be greater than or equal to start port")
            else:
                # Show hostname if enabled
                if resolve_hostname:
                    hostname = get_hostname(ip_address)
                    if hostname:
                        st.info(f"Hostname: {hostname}")
                
                # Create progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Create placeholder for results
                results_placeholder = st.empty()
                chart_placeholder = st.empty()
                
                start_time = time.time()
                ports_to_scan = list(range(start_port, end_port + 1))
                total_ports = len(ports_to_scan)
                
                # Show scanning message
                status_text.text(f"🔍 Scanning {ip_address} from port {start_port} to {end_port}...")
                
                # Initialize results
                open_ports = []
                
                # Create a counter for progress updates
                scanned_ports = 0
                
                # Scan ports with ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
                    # Submit all scanning tasks
                    futures = [executor.submit(scan_port, ip_address, port) for port in ports_to_scan]
                    
                    # Process results as they complete
                    for future in futures:
                        result = future.result()
                        if result:
                            open_ports.append(result)
                        
                        # Update progress
                        scanned_ports += 1
                        progress_percentage = scanned_ports / total_ports
                        progress_bar.progress(progress_percentage)
                        
                        # Update status text occasionally (not every port to avoid slowdown)
                        if scanned_ports % max(10, int(total_ports/100)) == 0 or scanned_ports == total_ports:
                            status_text.text(f"🔍 Scanning: {scanned_ports}/{total_ports} ports checked... Found {len(open_ports)} open ports")
                
                # Calculate scan time
                scan_time = time.time() - start_time
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                # Show results
                if open_ports:
                    # Convert to DataFrame for display
                    df = pd.DataFrame(open_ports)
                    
                    # Create visualization
                    fig = go.Figure()
                    
                    # Add bar chart for open ports
                    fig.add_trace(go.Bar(
                        x=df["port"],
                        y=[1] * len(df),
                        text=df["service"],
                        hoverinfo="text",
                        name="Open Ports",
                        marker_color="green"
                    ))
                    
                    fig.update_layout(
                        title=f"Open Ports on {ip_address}",
                        xaxis_title="Port Number",
                        yaxis_title="Status",
                        yaxis=dict(visible=False),
                        height=400
                    )
                    
                    chart_placeholder.plotly_chart(fig)
                    
                    # Display results table with vulnerability info
                    display_columns = ["port", "status", "service", "vulnerability"]
                    if deep_scan:
                        display_columns.append("banner")
                    
                    results_placeholder.dataframe(
                        df[display_columns],
                        column_config={
                            "port": st.column_config.NumberColumn("Port"),
                            "status": st.column_config.TextColumn("Status"),
                            "service": st.column_config.TextColumn("Service"),
                            "vulnerability": st.column_config.TextColumn("Potential Vulnerability"),
                            "banner": st.column_config.TextColumn("Service Banner"),
                        },
                        hide_index=True,
                    )
                    
                    # Show summary
                    st.success(f"✅ Found {len(open_ports)} open ports on {ip_address} in {scan_time:.2f} seconds")
                    
                    # Export options
                    st.subheader("Export Results")
                    col_exp1, col_exp2 = st.columns(2)
                    
                    with col_exp1:
                        # Generate PDF report
                        pdf_data = create_pdf_report(ip_address, open_ports, scan_time, timestamp)
                        
                        # Create download button for PDF
                        st.download_button(
                            label="📄 Download PDF Report",
                            data=pdf_data,
                            file_name=f"port_scan_{ip_address}_{timestamp.replace(':', '-')}.pdf",
                            mime="application/pdf",
                        )
                    
                    with col_exp2:
                        # CSV export
                        csv = df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="📊 Download CSV Data",
                            data=csv,
                            file_name=f"port_scan_{ip_address}_{timestamp.replace(':', '-')}.csv",
                            mime="text/csv",
                        )
                    
                    # Show detailed information for each open port
                    st.subheader("Detailed Port Information")
                    for port_info in open_ports:
                        port = port_info["port"]
                        service = port_info["service"]
                        details = get_port_details(port)
                        
                        with st.expander(f"Port {port} - {service}"):
                            st.markdown(f"**Description:** {details['description']}")
                            st.markdown(f"**Common Usage:** {details['common_usage']}")
                            st.markdown(f"**Security Notes:** {details['security_notes']}")
                            st.markdown(f"**Potential Vulnerability:** {port_info['vulnerability']}")
                            
                            # Show banner if available
                            if deep_scan and port_info.get("banner"):
                                st.markdown("**Service Banner:**")
                                st.code(port_info["banner"])
                    
                    # Security recommendations
                    with st.expander("Security Recommendations"):
                        st.markdown("""
                        ### General Security Recommendations
                        * Close unnecessary ports to reduce attack surface
                        * Use firewalls to restrict access to essential services only
                        * Keep all services updated with security patches
                        * Use strong authentication for all network services
                        * Consider implementing intrusion detection systems
                        * Regularly scan for vulnerabilities and monitor logs
                        """)
                else:
                    results_placeholder.info("❌ No open ports found")
                    st.info(f"Scan completed in {scan_time:.2f} seconds")
    
    with tabs[1]:  # Port Information tab
        st.subheader("Common Network Ports")
        
        # Create a searchable table of common ports
        common_ports = get_common_ports_info()
        port_data = [{"Port": port, "Service": service} for port, service in common_ports.items()]
        
        # Add search functionality
        search_term = st.text_input("Search for port or service:")
        if search_term:
            filtered_data = [item for item in port_data if 
                            search_term.lower() in str(item["Port"]).lower() or 
                            search_term.lower() in item["Service"].lower()]
            st.table(pd.DataFrame(filtered_data))
        else:
            st.table(pd.DataFrame(port_data))
        
        # Port categories
        st.subheader("Port Categories")
        st.markdown("""
        * **Well-known ports** (1-1023): Assigned by IANA for common protocols
        * **Registered ports** (1024-49151): Registered with IANA but can be used by regular applications
        * **Dynamic/Private ports** (49152-65535): Used for temporary connections
        """)
        
        # Service detection information
        st.subheader("Service Detection")
        st.markdown("""
        This scanner uses multiple methods to identify services running on open ports:
        
        1. **Standard service database** - Uses your system's service database to identify well-known services
        2. **Custom service mapping** - Uses our built-in database of common services
        3. **Banner grabbing** (when Deep Scan is enabled) - Attempts to communicate with the service to identify it
        
        For best results, enable Deep Scan when you need detailed service identification.
        """)
        
    with tabs[2]:  # About tab
        st.subheader("About Network Port Scanner")
        st.markdown("""
        This application is a multithreaded TCP port scanner with both CLI and web interfaces.
        
        ### Features
        * Scan any IP address with custom port ranges
        * Multithreaded scanning for speed
        * Enhanced service identification
        * Banner grabbing for service detection
        * Vulnerability assessment
        * PDF and CSV report generation
        * Detailed port information
        
        ### Usage Notes
        * For best results, use reasonable port ranges (scanning all 65535 ports can take time)
        * Deep Scan provides better service identification but takes longer
        
        ### Ethical Usage
        This tool is for educational purposes and network diagnostics only. 
        Only scan networks and systems you own or have explicit permission to scan.
        Unauthorized port scanning may be illegal in some jurisdictions.
        """)

if __name__ == "__main__":
    main() 
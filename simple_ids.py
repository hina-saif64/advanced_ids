#!/usr/bin/env python3
"""
Advanced Python Intrusion Detection System (IDS)
Features:
- Network packet sniffing and analysis
- Suspicious activity logging to CSV
- Automatic IP blocking after threshold
- GeoIP lookup for source IPs
- Email notifications for blocked IPs
- Firewall integration (iptables)
"""

import ipaddress
import logging
import os
import smtplib
import subprocess
import sys
from datetime import datetime
from email.message import EmailMessage

import pandas as pd
import requests
from scapy.all import sniff
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def env_flag(name, default=False):
    """Read a boolean environment variable using common truthy values."""
    fallback = "true" if default else "false"
    return os.getenv(name, fallback).strip().lower() in {
        "1", "true", "yes", "on"
    }

# ---------------------------
# CONFIGURATION
# ---------------------------
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 139, 135]  # SSH, Telnet, RDP, SMB, NetBIOS
ALERT_CSV = "alerts.csv"
BLOCK_THRESHOLD = 3
EMAIL_ALERTS = env_flag("IDS_EMAIL_ALERTS")
EMAIL_FROM = os.getenv("IDS_EMAIL_FROM", "")
EMAIL_TO = os.getenv("IDS_EMAIL_TO", "")
SMTP_SERVER = os.getenv("IDS_SMTP_SERVER", "smtp.gmail.com")
SMTP_PASS = os.getenv("IDS_SMTP_PASSWORD", "")
FIREWALL_BLOCKING = env_flag("IDS_FIREWALL_BLOCKING")

try:
    SMTP_PORT = int(os.getenv("IDS_SMTP_PORT", "587"))
except ValueError:
    logger.warning("Invalid IDS_SMTP_PORT; falling back to port 587")
    SMTP_PORT = 587

blocked_ips = {}
geoip_cache = {}  # Cache GeoIP lookups to reduce API calls

# ---------------------------
# INITIALIZE CSV
# ---------------------------
def initialize_csv():
    """Create alerts CSV file if it doesn't exist"""
    if not os.path.exists(ALERT_CSV):
        df = pd.DataFrame(columns=[
            "timestamp",
            "src_ip",
            "dst_port",
            "attack_type",
            "severity",
            "location",
            "blocked",
            "attempt_count"
        ])
        df.to_csv(ALERT_CSV, index=False)
        logger.info(f"Created new alerts file: {ALERT_CSV}")

# ---------------------------
# GEOIP LOOKUP
# ---------------------------
def get_geo(ip):
    """
    Get geographical location of IP address
    Uses caching to reduce API calls
    """
    if ip in geoip_cache:
        return geoip_cache[ip]

    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        logger.warning("GeoIP lookup skipped for invalid IP address: %s", ip)
        return "Unknown"

    if not parsed_ip.is_global:
        geoip_cache[ip] = "Private or reserved network"
        return geoip_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            location = f"{data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}"
            geoip_cache[ip] = location
            return location
        logger.warning("GeoIP provider returned no location for %s", ip)
    except requests.Timeout:
        logger.warning("GeoIP lookup timed out for %s", ip)
    except (requests.RequestException, ValueError) as error:
        logger.warning("GeoIP lookup failed for %s: %s", ip, error)

    return "Unknown"

# ---------------------------
# EMAIL NOTIFICATIONS
# ---------------------------
def send_email_alert(ip, location):
    """Send email notification when IP is blocked"""
    if not EMAIL_ALERTS:
        return False

    required_settings = {
        "IDS_EMAIL_FROM": EMAIL_FROM,
        "IDS_EMAIL_TO": EMAIL_TO,
        "IDS_SMTP_PASSWORD": SMTP_PASS,
    }
    missing = [name for name, value in required_settings.items() if not value]
    if missing:
        logger.error(
            "Email alerts are enabled but required settings are missing: %s",
            ", ".join(missing),
        )
        return False

    try:
        msg = EmailMessage()
        msg.set_content(
            f"Alert: Suspicious IP has been blocked!\n\n"
            f"IP Address: {ip}\n"
            f"Location: {location}\n"
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Reason: Multiple suspicious connection attempts detected"
        )
        msg['Subject'] = f"IDS Alert - Blocked IP: {ip}"
        msg['From'] = EMAIL_FROM
        msg['To'] = EMAIL_TO
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, SMTP_PASS)
            server.send_message(msg)

        logger.info("Email alert sent for blocked IP: %s", ip)
        return True
    except (OSError, smtplib.SMTPException, ValueError) as error:
        logger.error("Failed to send email alert for %s: %s", ip, error)
        return False

# ---------------------------
# FIREWALL BLOCKING
# ---------------------------
def block_ip_firewall(ip):
    """Block IP at OS level using iptables (Linux only)"""
    if not FIREWALL_BLOCKING:
        return False

    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        logger.error("Firewall blocking rejected invalid IP address: %s", ip)
        return False

    if os.geteuid() != 0:
        logger.warning("Cannot block %s - requires root privileges", ip)
        return False

    firewall_command = "iptables" if parsed_ip.version == 4 else "ip6tables"
    rule = ["INPUT", "-s", str(parsed_ip), "-j", "DROP"]

    try:
        existing_rule = subprocess.run(
            [firewall_command, "-C", *rule],
            check=False,
            capture_output=True,
            text=True,
        )
        if existing_rule.returncode == 0:
            logger.info("Firewall rule already exists for: %s", ip)
            return True

        subprocess.run(
            [firewall_command, "-A", *rule],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Firewall rule added to block: %s", ip)
        return True
    except FileNotFoundError:
        logger.error("%s is not installed or not available on PATH", firewall_command)
    except subprocess.CalledProcessError as error:
        logger.error(
            "Firewall blocking failed for %s: %s",
            ip,
            error.stderr.strip() if error.stderr else error,
        )

    return False

# ---------------------------
# ATTACK TYPE DETECTION
# ---------------------------

ip_port_history = {}
ip_syn_counter = {}

def detect_attack_type(ip, port, packet):
    """Detect attack type and severity"""

    if ip not in ip_port_history:
        ip_port_history[ip] = set()

    ip_port_history[ip].add(port)

    # Port Scan
    if len(ip_port_history[ip]) >= 5:
        return "Port Scan", "High"

    # SSH
    if port == 22:
        attempts = blocked_ips.get(ip, {}).get("count", 0)

        if attempts >= BLOCK_THRESHOLD:
            return "SSH Brute Force", "Critical"

        return "SSH Login Attempt", "Medium"

    # Telnet
    if port == 23:
        return "Telnet Login Attempt", "High"

    # SMB
    if port in [139, 445]:
        return "SMB Enumeration", "High"

    # RPC
    if port == 135:
        return "RPC Enumeration", "Medium"

    # RDP
    if port == 3389:
        return "RDP Brute Force", "Critical"

    # SYN Flood
    if packet.haslayer(TCP):

        flags = packet[TCP].flags

        if flags == "S":

            ip_syn_counter[ip] = ip_syn_counter.get(ip, 0) + 1

            if ip_syn_counter[ip] >= 20:
                return "SYN Flood", "Critical"

    return "Unknown Suspicious Activity", "Low"

# ---------------------------
# PACKET DETECTION
# ---------------------------

def detect_suspicious_packet(packet):
    """Detect suspicious packets and classify attack type"""

    try:

        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Ignore already blocked IPs
        if src_ip in blocked_ips:
            if blocked_ips[src_ip]["status"] == "blocked":
                return

        # Ignore non-suspicious ports
        if dst_port not in SUSPICIOUS_PORTS:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        location = get_geo(src_ip)

        # Create entry if first time seen
        if src_ip not in blocked_ips:

            blocked_ips[src_ip] = {
                "count": 0,
                "status": "monitoring",
                "first_seen": timestamp
            }

        # Increase attempt counter
        blocked_ips[src_ip]["count"] += 1

        attempt_count = blocked_ips[src_ip]["count"]

        # Detect attack type
        attack_type, severity = detect_attack_type(
            src_ip,
            dst_port,
            packet
        )

        blocked = attempt_count >= BLOCK_THRESHOLD

        if blocked:
            blocked_ips[src_ip]["status"] = "blocked"

        logger.info(
            f"[ALERT] "
            f"{src_ip} "
            f"-> Port {dst_port} "
            f"| {attack_type} "
            f"| Severity: {severity} "
            f"| Attempt #{attempt_count}"
        )

        # Save exactly one alert for each suspicious packet. The threshold
        # event is recorded as blocked instead of producing a duplicate row.
        alert = pd.DataFrame([[
            timestamp,
            src_ip,
            dst_port,
            attack_type,
            severity,
            location,
            blocked,
            attempt_count
        ]],
        columns=[
            "timestamp",
            "src_ip",
            "dst_port",
            "attack_type",
            "severity",
            "location",
            "blocked",
            "attempt_count"
        ])

        alert.to_csv(
            ALERT_CSV,
            mode="a",
            header=False,
            index=False
        )

        # Block attacker
        if blocked:
            logger.warning(
                f"[BLOCK] "
                f"{src_ip} "
                f"blocked after "
                f"{attempt_count} attempts"
            )

            block_ip_firewall(src_ip)

            send_email_alert(
                src_ip,
                location
            )

    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        logger.error("Error processing packet: %s", error)

# ---------------------------
# STATISTICS
# ---------------------------
def print_statistics():
    """Print current IDS statistics"""
    try:
        if os.path.exists(ALERT_CSV):
            df = pd.read_csv(ALERT_CSV)
            total_alerts = len(df)
            blocked_count = df[df["blocked"] == True]["src_ip"].nunique()
            unique_ips = df['src_ip'].nunique() if 'src_ip' in df.columns else 0
            
            logger.info(f"\n=== IDS Statistics ===")
            logger.info(f"Total Alerts: {total_alerts}")
            logger.info(f"Blocked IPs: {blocked_count}")
            logger.info(f"Unique Source IPs: {unique_ips}")
            logger.info(f"========================\n")
    except (KeyError, OSError, ValueError, pd.errors.ParserError) as error:
        logger.error("Error printing statistics: %s", error)

# ---------------------------
# MAIN
# ---------------------------
def main():
    """Start the IDS"""
    initialize_csv()
    
    logger.info("=" * 50)
    logger.info("Advanced Python IDS Starting...")
    logger.info("=" * 50)
    logger.info(f"Monitoring ports: {SUSPICIOUS_PORTS}")
    logger.info(f"Block threshold: {BLOCK_THRESHOLD} attempts")
    logger.info(f"Email alerts: {'Enabled' if EMAIL_ALERTS else 'Disabled'}")
    logger.info(f"Firewall blocking: {'Enabled' if FIREWALL_BLOCKING else 'Disabled'}")
    logger.info("Press Ctrl+C to stop")
    logger.info("=" * 50 + "\n")
    
    try:
        sniff(prn=detect_suspicious_packet, filter="tcp", store=0)
    except KeyboardInterrupt:
        logger.info("\nIDS stopped by user")
        print_statistics()
        sys.exit(0)
    except (OSError, PermissionError, Scapy_Exception) as error:
        logger.error("Fatal error: %s", error)
        sys.exit(1)

if __name__ == "__main__":
    main()

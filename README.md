# Advanced Python Intrusion Detection System (IDS)

**A professional-grade Intrusion Detection System (IDS) built in Python that monitors network traffic, detects suspicious activity, classifies attacks using rule-based heuristics, logs alerts, and provides real-time visualization through an interactive web dashboard.**

## 🎯 Features

### Core Functionality
- **Real-time Network Monitoring**: Captures and analyzes TCP packets on suspicious ports
- **Attack Type Detection**: Classifies suspicious traffic into common attack categories using rule-based heuristics
- **Severity Classification**: Labels alerts as Low, Medium, High, or Critical based on detected activity
- **Suspicious Activity Detection**: Identifies connection attempts to common attack vectors (SSH, Telnet, RDP, SMB, and RPC services)
- **CSV Logging**:  Comprehensive logging with timestamp, source IP, destination port, attack type, severity, location, block status, and attempt count
- **Automatic IP Blocking**: Blocks IPs after configurable threshold of suspicious attempts
- **GeoIP Lookup**: Identifies geographical location of source IPs
- **Email Notifications**: Sends alerts when IPs are blocked
- **Firewall Integration**: Automatic iptables rules for OS-level IP blocking (Linux)

### Dashboard Features
- **Live Alerts Table**: Real-time table of all detected suspicious activity
- **Top Suspicious IPs**: Bar chart showing most active threat sources
- **Port Distribution**: Pie chart of targeted ports
- **Alerts Timeline**: Line chart showing alert frequency over time
- **Location Analysis**: Geographic distribution of threats
- **Attack Type Distribution**: Pie chart showing detected attack categories
- **Severity Distribution**: Bar chart showing alert severity levels
- **Statistics Cards**: Quick overview of total alerts, blocked IPs, and unique sources
- **Auto-refresh**: Dashboard updates every 5 seconds
- Advanced Python IDS was designed with a modular, deployment-friendly architecture that prioritises operational simplicity, code clarity, and maintainability. Its accessible implementation enables students, early-career    security engineers, and cybersecurity practitioners to examine, configure, test, and extend intrusion detection capabilities for authorised network monitoring and defensive security applications.

## 📋 Requirements

- **Python**: 3.9 or higher
- **Operating System**: Linux (for full firewall functionality)
- **Privileges**: Root/sudo access required for packet sniffing and firewall rules
- **Dependencies**: See `requirements.txt`

### System Requirements
```bash
# Ubuntu/Debian
sudo apt-get install python3-pip libpcap-dev

# Fedora/RHEL
sudo dnf install python3-pip libpcap-devel
```

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/hina-saif64/advanced_ids.git
cd advanced_ids
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configuration (Optional)

Runtime secrets and deployment-specific settings are read from environment
variables instead of being stored in source code. Copy the included template,
fill in local values, and load it into your shell:

```bash
cp .env.example .env
# Edit .env locally. Never commit this file.
set -a
source .env
set +a
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `IDS_EMAIL_ALERTS` | `false` | Enable blocked-IP email notifications |
| `IDS_EMAIL_FROM` | Empty | Authenticated sender address |
| `IDS_EMAIL_TO` | Empty | Alert recipient address |
| `IDS_SMTP_SERVER` | `smtp.gmail.com` | SMTP host |
| `IDS_SMTP_PORT` | `587` | SMTP STARTTLS port |
| `IDS_SMTP_PASSWORD` | Empty | SMTP or app-specific password |
| `IDS_FIREWALL_BLOCKING` | `false` | Enable OS-level blocking |

The monitored ports and block threshold remain simple constants near the top
of `simple_ids.py` for educational customization.

## 📖 Usage

### Step 1: Start the IDS
```bash
# Run with sudo (required for packet sniffing)
sudo python3 simple_ids.py
```

You should see:
```
==================================================
Advanced Python IDS Starting...
==================================================
Monitoring ports: [22, 23, 3389, 445, 139, 135]
Block threshold: 3 attempts
Email alerts: Disabled
Firewall blocking: Disabled
Press Ctrl+C to stop
==================================================
```

### Step 2: Start the Dashboard (in another terminal)
```bash
python3 dashboard.py
```

You should see:
```
Starting Advanced IDS Dashboard...
Open http://127.0.0.1:8050/ in your browser
```

### Step 3: Access the Dashboard
Open your web browser and navigate to:
```
http://127.0.0.1:8050/
```

### Step 4: Monitor Activity
The dashboard will automatically update every 5 seconds with:
- New alerts
- Updated statistics
- Real-time charts and visualizations

### Stop the IDS
Press `Ctrl+C` in the terminal running `simple_ids.py`

### Run the Tests

```bash
python -m unittest discover -s tests -v
```

The regression suite covers secure firewall command construction,
environment-based configuration, GeoIP input handling, email configuration,
and threshold alert logging. GitHub Actions runs the same suite on supported
Python versions for every pull request.

## 📊 Output Files

### alerts.csv
CSV file containing all detected alerts:

```csv
timestamp,src_ip,dst_port,attack_type,severity,location,blocked,attempt_count
2026-07-14 10:30:45,192.168.1.100,22,SSH Login Attempt,Medium,"United States, New York",False,1
2026-07-14 10:31:12,192.168.1.100,22,SSH Brute Force,Critical,"United States, New York",True,3
2026-07-14 10:32:02,192.168.1.101,445,SMB Enumeration,High,"United Kingdom, London",False,1
```

### ids.log
Log file with detailed system information:
```
2024-01-18 10:30:45,123 - INFO - Advanced Python IDS Starting...
2024-01-18 10:30:45,456 - INFO - [ALERT] 2024-01-18 10:30:45 - 192.168.1.100 (United States, New York) -> Port 22 (Attempt #1)
2024-01-18 10:31:45,789 - WARNING - [BLOCK] 192.168.1.100 blocked after 3 suspicious attempts
```

## 🔧 Advanced Configuration

### Enable Email Notifications

1. **For Gmail**:
   - Enable 2-Factor Authentication
   - Generate App Password: https://myaccount.google.com/apppasswords
   - Store the settings in your local `.env` file:
   ```bash
   IDS_EMAIL_ALERTS=true
   IDS_EMAIL_FROM=your_email@gmail.com
   IDS_EMAIL_TO=recipient@example.com
   IDS_SMTP_SERVER=smtp.gmail.com
   IDS_SMTP_PORT=587
   IDS_SMTP_PASSWORD=your_16_character_app_password
   ```

2. **For Other Email Providers**:
   - Update `IDS_SMTP_SERVER` and `IDS_SMTP_PORT` accordingly
   - Use app-specific passwords if available

### Enable Firewall Blocking

```bash
export IDS_FIREWALL_BLOCKING=true
```

Then run with sudo:
```bash
sudo python3 simple_ids.py
```

**Note**: This adds validated, duplicate-checked `iptables` or `ip6tables`
rules at the OS level. The IDS must run as root when firewall blocking is
enabled.

### Add Custom Ports

Edit the `SUSPICIOUS_PORTS` list in `simple_ids.py`:
```python
SUSPICIOUS_PORTS = [22, 23, 3389, 445, 139, 135, 8080, 9000]  # Add your ports

```

## 🛡️ Security Best Practices

1. **Run with appropriate privileges**: Use `sudo` only when necessary
2. **Secure email credentials**: Keep SMTP secrets in a local `.env` file or secret manager; `.env` is ignored by Git
3. **Monitor logs regularly**: Check `ids.log` for suspicious patterns
4. **Update dependencies**: Regularly run `pip install --upgrade -r requirements.txt`
5. **Firewall rules**: Periodically review and clean up old iptables rules
6. **Network isolation**: Run on a dedicated monitoring interface when possible

## 🐛 Troubleshooting

### "Permission denied" error
```bash
# Solution: Run with sudo
sudo python3 simple_ids.py
```

### "No module named 'scapy'" error
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

### Dashboard not updating
- Ensure `simple_ids.py` is running
- Check that `alerts.csv` exists and is being written to
- Verify port 8050 is not in use: `lsof -i :8050`

### GeoIP lookups are slow
- GeoIP cache is enabled to reduce API calls
- First lookup for each IP may take 2-3 seconds
- Subsequent lookups are instant

### Email alerts not sending
- Verify SMTP credentials are correct
- Check firewall allows outbound SMTP connections
- Review `ids.log` for error messages
- Test with a simple Python script first

## 📈 Performance Considerations

- **Memory Usage**: Minimal (~50-100 MB)
- **CPU Usage**: Low (~1-5% depending on traffic)
- **Disk Usage**: CSV file grows ~1-2 KB per alert
- **Network Overhead**: Negligible (read-only sniffing)

For high-traffic networks, consider:
- Filtering specific interfaces: `sniff(iface='eth0', ...)`
- Adjusting block threshold
- Archiving old CSV files regularly
- 
## Attack Classification

The IDS performs lightweight rule-based attack classification using observed network behaviour.

| Attack Type                 | Description                                         | Severity |
| --------------------------- | --------------------------------------------------- | -------- |
| SSH Login Attempt           | Connection attempts to SSH (Port 22)                | Medium   |
| SSH Brute Force             | Multiple repeated SSH attempts                      | Critical |
| Telnet Login Attempt        | Connections targeting Telnet (Port 23)              | High     |
| SMB Enumeration             | Access attempts to SMB services (Ports 139/445)     | High     |
| RPC Enumeration             | Access attempts to RPC Endpoint Mapper (Port 135)   | Medium   |
| RDP Brute Force             | Remote Desktop access attempts (Port 3389)          | Critical |
| Port Scan                   | Connections targeting multiple monitored ports      | High     |
| SYN Flood                   | Excessive TCP SYN packets detected                  | Critical |
| Unknown Suspicious Activity | Suspicious traffic that does not match a known rule | Low      |

Attack classification is based on predefined heuristics and is intended for educational and learning purposes rather than full signature-based intrusion detection.


## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Machine learning-based anomaly detection
- Additional attack signatures
- Database backend instead of CSV
- Web UI improvements
- Multi-interface monitoring
- IPv6 support
- Advanced threat intelligence integration

## 📝 License

This project is open-source and available for educational, personal, and voluntary work purposes.

## ⚠️ Disclaimer

Advanced Python IDS is intended solely for authorized network security
monitoring, deployments, defensive testing, and educational purposes.

You must have explicit permission from the network owner or authorized
administrator before deploying or testing this tool on any system or network.

Users are responsible for ensuring that their use of this software complies
with all applicable laws, regulations, and organizational security policies.

This project is provided "as is", without warranties of any kind. The
developer assumes no responsibility for misuse, unauthorized deployment,
or any damage resulting from the use of this software.

Use this tool responsibly and only within environments you are authorized
to monitor.

## 📞 Support

For issues, questions, or suggestions:
1. Check the Troubleshooting section above
2. Review `ids.log` for error messages
3. Open an issue on GitHub with detailed information

## 🎓 Learning Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Dash Documentation](https://dash.plotly.com/)
- [Network Security Basics](https://www.cisco.com/c/en/us/support/docs/security/)
- [IDS/IPS Concepts](https://www.paloaltonetworks.com/cyberpedia/what-is-ids-ips)

---

**Created with ❤️ for cybersecurity enthusiasts and professionals**

Last Updated: July 2026

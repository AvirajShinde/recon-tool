#  Recon Scanner

A powerful **Website Reconnaissance & Vulnerability Scanner** built in Python for Linux environments.
This tool automates information gathering, threat intelligence, and vulnerability detection into a single workflow.

---

##  Features

*  Domain & IP Resolution
*  DNS Enumeration (A, MX, NS, TXT, AAAA, CNAME)
*  WHOIS Lookup
*  SSL/TLS Certificate Analysis
*  Port Scanning (Top 50 ports using Nmap)
*  HTTP Header Inspection
*  Website Metadata Extraction
*  Vulnerability Detection (OWASP-based checks)
*  Threat Intelligence:

  * VirusTotal integration
  * Shodan integration
  * DNSDumpster (subdomain enumeration)
*  PDF Report Generation
*  Multi-threaded scanning for performance

---

##  Installation

### 1️ Clone the Repository

```bash
git clone https://github.com/AvirajShinde/recon-tool.git
cd recon-scanner
```

### 2️ Install Dependencies

```bash
pip install -r requirements.txt
```

OR (recommended)

```bash
pip install .
```

---

##  Usage

```bash
recon-scanner
```

Then enter the target domain when prompted:

```bash
Enter target domain: example.com
```

---

##  Requirements

* Python 3.8+
* Linux OS (recommended)
* Nmap installed

Install Nmap:

```bash
sudo apt install nmap
```

---

##  API Configuration

Edit API keys inside the code:

```python
API_KEYS = {
    "virustotal": "YOUR_VIRUSTOTAL_API_KEY",
    "shodan": "YOUR_SHODAN_API_KEY",
    "dnsdumpster": "OPTIONAL_API_KEY"
}
```

> ⚠ If keys are not provided, those modules will be skipped.

---

##  Project Structure

```
recon-scanner/
│
├── recon_scanner/
│   ├── main.py
│   ├── scanner.py
│
├── logs/
├── reports/
├── requirements.txt
├── setup.cfg
├── README.md
```

---

##  Output

* CLI-based results
* Vulnerability summary with severity levels
* Detailed **PDF report** saved in `/reports`

---

##  Vulnerability Coverage

Includes checks for:

* Missing security headers (CSP, HSTS, X-Frame, etc.)
* SSL issues (expired, weak protocols, self-signed)
* Open dangerous ports (FTP, Telnet, RDP, SMB, etc.)
* Email security (SPF, DMARC)
* Cookie security (Secure, HttpOnly)
* Server information disclosure
* Threat intelligence flags (VirusTotal, Shodan CVEs)

---

##  Disclaimer

This tool is intended for:

* Educational purposes
* Authorized penetration testing
* Security research

 Do NOT use this tool on systems without permission.

---

##  Author

**Aviraj Shinde**

---

##  Support

If you like this project:

*  Star the repository
*  Fork it
*  Contribute improvements

---

##  License

MIT License

# 🔍 Recon Scanner

CLI-based Website Reconnaissance & Vulnerability Scanner. A powerful Python tool to perform automated reconnaissance and identify security misconfigurations. Recon Scanner is an automated cybersecurity reconnaissance tool that collects essential target information such as open ports, DNS records, WHOIS details, HTTP headers, and webpage metadata. It is designed to assist in footprinting and enumeration phases of security testing with a clean and easy-to-use CLI interface.



---

## 🚀 Features

* 🌐 Domain & IP Resolution
* 📡 DNS Enumeration
* 🧾 WHOIS Lookup
* 🔐 SSL/TLS Analysis
* 🛰 Port Scanning (Nmap)
* 📑 HTTP Header Analysis
* 🧠 Metadata Extraction
* 🛡 Vulnerability Detection (OWASP-based)
* 🔎 Threat Intelligence:

  * VirusTotal
  * Shodan
  * DNSDumpster
* 📄 PDF Report Generation
* ⚡ Multi-threaded scanning

---

## 🛠 Installation

### 1️⃣ Clone Repository

```bash
git clone https://github.com/AvirajShinde/recon-scanner.git
cd recon-scanner
```

---

### 2️⃣ Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶ Usage

Run the tool:

```bash
python recon-scanner.py
```

Then enter target:

```bash
Enter target domain: example.com
```

---

## ⚙ Requirements

* Python 3.8+
* Linux OS (recommended)
* Nmap installed

Install Nmap:

```bash
sudo apt install nmap
```

---

## 🔑 API Configuration

Edit API keys inside the script:

```python
API_KEYS = {
    "virustotal": "YOUR_KEY",
    "shodan": "YOUR_KEY",
    "dnsdumpster": "OPTIONAL"
}
```

---

## 📂 Project Structure

```bash
recon-scanner/
│
├── recon-scanner.py   ✅ (main tool)
├── .env
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── setup.py
```

---

## 📊 Output

* CLI scan results
* Vulnerability summary
* PDF report saved in `/reports`

---

## ⚠ Disclaimer

This tool is for:

* Educational purposes
* Authorized security testing

❌ Do NOT scan systems without permission.

---

## 👨‍💻 Author

**Aviraj Shinde**

---

## ⭐ Support

* Star ⭐ the repo
* Fork 🍴 it
* Contribute 🛠

---

## 📜 License

MIT License

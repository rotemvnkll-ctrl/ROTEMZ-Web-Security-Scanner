# ROTEMZ Web Security Scanner v5.0 🛡️

The **Modular Arsenal Edition**. A professional GUI-based Recon & Vulnerability Scanner for Kali Linux.
Now featuring a **Modular Checkbox Interface**, **Cloud Bucket Enumeration**, and **Threat Intelligence**.

## 🔥 New Features in v5.0
* **🎛️ Modular Interface:** Select specific tools to run via checkboxes (or use "Select All" for a full audit).
* **☁️ Cloud Bucket Hunter:** Detects public S3/Google Cloud buckets associated with the domain.
* **🌍 Whois & GeoIP:** Reveals physical server location, ISP, and registrar details.
* **🛡️ Security Headers:** Analyzes missing HTTP security headers (HSTS, CSP, X-Frame).
* **🔗 Broken Link Hijacking:** Scans for broken external links that allow account takeovers.
* **💣 Exploit Correlation:** Auto-maps service versions to Exploit-DB CVEs.

## 🛠️ Installation
```bash
# 1. Clone the repo
git clone [https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git](https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git)
cd ROTEMZ-Web-Security-Scanner

# 2. Install System Tools (Kali Linux)
sudo apt update
sudo apt install nmap nikto gobuster wafw00f wpscan whatweb sublist3r exploitdb -y

# 3. Install Python Dependencies
sudo pip3 install -r requirements.txt --break-system-packages

# 4. Run (Root required for Nmap)
sudo python3 rotemz_scanner.py

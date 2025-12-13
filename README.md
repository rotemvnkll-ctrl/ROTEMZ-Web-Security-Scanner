# ROTEMZ Web Security Scanner v4.0 🛡️

The **Ultimate Intelligence Edition**. A GUI-based Recon & Vulnerability Scanner for Kali Linux.
Now powered with **Exploit-DB correlation**, **Subdomain Enumeration**, and **CMS Fingerprinting**.

## 🔥 New Features in v4.0
* **💣 Exploit-DB Integration:** Automatically correlates service versions with known CVEs/Exploits using `searchsploit`.
* **🌐 Subdomain Enumeration:** Discovers hidden subdomains using `sublist3r`.
* **🕵️‍♂️ Deep Fingerprinting:** Identifies tech stacks (CMS, JS Frameworks, Server versions) using `whatweb`.
* **🥷 Stealth Mode:** Bypass WAF/IDS with fragmented packets and slow timing.
* **📂 WordPress & Robots:** Auto-detects WP users and extracts robots.txt/sitemaps.
* **📄 HTML Reporting:** Generates a full styled report.

## 🛠️ Installation
```bash
# 1. Clone the repo
git clone [https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git](https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git)
cd ROTEMZ-Web-Security-Scanner

# 2. Install System Tools (Kali Linux)
sudo apt update
sudo apt install nmap nikto gobuster wafw00f wpscan whatweb sublist3r exploitdb -y

# 3. Install Python Deps
sudo pip3 install -r requirements.txt

# 4. Run (Must use Sudo)
sudo python3 rotemz_scanner.py

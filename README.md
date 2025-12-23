# ROTEMZ Web Security Scanner v6.5 (AI Edition) 🤖

The **Ultimate Autonomous Intelligence Tool**. A modular GUI-based Scanner for Kali Linux.
Now featuring **Hexstrike-AI Integration** and **Visual Network Mapping**.

## 🔥 Top Features
* **🤖 Hexstrike-AI Agent:** Dedicated sidebar toggle to launch an autonomous MCP Agent for AI-driven offensive tasks.
* **🔑 Secrets & API Hunter:** Scans JS files to find leaked AWS, Google, and Stripe keys.
* **🕸️ Visual Attack Map:** Generates a network topology graph of the target's attack surface.
* **☁️ Cloud Bucket Hunter:** Detects public S3/Google Cloud buckets.
* **🎛️ Modular Dashboard:** Select specific tools (Whois, WAF, Exploits) via checkboxes.

## 🛠️ Installation
```bash
# 1. Clone the repo
git clone [https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git](https://github.com/rotemvnkll-ctrl/ROTEMZ-Web-Security-Scanner.git)
cd ROTEMZ-Web-Security-Scanner

# 2. Install Kali Tools & Hexstrike
sudo apt update
sudo apt install nmap nikto gobuster wafw00f wpscan whatweb sublist3r exploitdb hexstrike-ai -y

# 3. Install Python Dependencies
sudo pip3 install -r requirements.txt --break-system-packages

# 4. Run (Root required)
sudo python3 rotemz_scanner.py

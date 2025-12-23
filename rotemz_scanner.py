
import customtkinter as ctk
import subprocess
import threading
import os
import sys
import socket
import datetime
import shutil
import requests
import time
import re
from tkinter import messagebox, filedialog
import json
from urllib.parse import urljoin

# Optional Imports
try:
    import whois
except ImportError:
    whois = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class RotemzScanner(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Root Check
        if os.geteuid() != 0:
            messagebox.showwarning("Root Required", "Run as root (sudo) for full features (Nmap/Stealth).")
        
        self.title("ROTEMZ Web Security Scanner v6.0 (The Modular Arsenal)")
        self.geometry("1400x900")
        
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Left Panel) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(4, weight=1) # List expands

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="ROTEMZ\nARSENAL v6.0", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        # Target Input
        self.target_label = ctk.CTkLabel(self.sidebar_frame, text="Target URL:", anchor="w")
        self.target_label.grid(row=1, column=0, padx=20, pady=(10, 0))
        self.url_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="http://example.com")
        self.url_entry.grid(row=2, column=0, padx=20, pady=(5, 10))

        # Stealth Mode Switch
        self.stealth_var = ctk.BooleanVar(value=False)
        self.stealth_switch = ctk.CTkSwitch(self.sidebar_frame, text="Stealth Mode 🥷", variable=self.stealth_var)
        self.stealth_switch.grid(row=3, column=0, padx=20, pady=10, sticky="w")

        # Hexstrike AI Switch
        self.hexstrike_var = ctk.BooleanVar(value=False)
        self.hexstrike_switch = ctk.CTkSwitch(self.sidebar_frame, text="🤖 Activate Hexstrike AI", variable=self.hexstrike_var, progress_color="#8A2BE2")
        self.hexstrike_switch.grid(row=4, column=0, padx=20, pady=10, sticky="w")

        # --- Modular Scanning List ---
        self.modules_label = ctk.CTkLabel(self.sidebar_frame, text="Select Modules:", anchor="w", font=("default", 12, "bold"))
        self.modules_label.grid(row=5, column=0, padx=20, pady=(20, 5), sticky="w")

        self.modules_frame = ctk.CTkScrollableFrame(self.sidebar_frame, label_text="Available Engines")
        self.modules_frame.grid(row=6, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        # Module Checkboxes
        # Module Checkboxes
        self.check_vars = {}
        self.module_names = [
            "Nmap Port Scan",
            "Nikto Web Scan",
            "WAF Detection",
            "Subdomains Enum",
            "CMS/WP Scan",
            "Exploit Check",
            "Whois & GeoIP",
            "Cloud Buckets",
            "Security Headers",
            "Broken Links",
            "Secrets Hunter (JS)"
        ]

        # Loop to create the checkboxes based on self.module_names
        for mod in self.module_names:
            var = ctk.BooleanVar(value=True)
            chk = ctk.CTkCheckBox(self.modules_frame, text=mod, variable=var)
            chk.pack(anchor="w", pady=2, padx=5)
            self.check_vars[mod] = var

        # Select All
        self.select_all_var = ctk.BooleanVar(value=True)
        self.select_all_check = ctk.CTkCheckBox(self.sidebar_frame, text="Select All", variable=self.select_all_var, command=self.toggle_all)
        self.select_all_check.grid(row=7, column=0, padx=20, pady=5, sticky="w")

        # Start Button
        self.start_button = ctk.CTkButton(self.sidebar_frame, text=" START SCAN 🚀 ", command=self.start_scan_thread, fg_color="#db2e2e", hover_color="#a81f1f", height=40)
        self.start_button.grid(row=8, column=0, padx=20, pady=20)

        # Export Button
        self.export_button = ctk.CTkButton(self.sidebar_frame, text="Export Report 📄", command=self.generate_html_report, state="disabled")
        self.export_button.grid(row=9, column=0, padx=20, pady=(0, 20))

        # --- Main Content Area (Tabs) ---
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.grid(row=0, column=1, padx=20, pady=(10, 0), sticky="nsew")
        
        self.tab_dashboard = self.tab_view.add("Dashboard")
        self.tab_live = self.tab_view.add("Live Terminal")
        self.tab_raw = self.tab_view.add("Raw Data")

        # Tab 1: Dashboard
        self.tab_dashboard.grid_columnconfigure(0, weight=1)
        self.tab_dashboard.grid_rowconfigure(0, weight=1)
        self.dashboard_text = ctk.CTkTextbox(self.tab_dashboard, font=("Consolas", 14), state="disabled")
        self.dashboard_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Configure tags
        self.dashboard_text.tag_config("red", foreground="#ff4444")
        self.dashboard_text.tag_config("green", foreground="#00ff00")
        self.dashboard_text.tag_config("orange", foreground="#FFA500")
        self.dashboard_text.tag_config("blue", foreground="#4da6ff")
        self.dashboard_text.tag_config("purple", foreground="#8A2BE2")

        # Tab 2: Live
        self.live_text = ctk.CTkTextbox(self.tab_live, font=("Courier New", 12), text_color="#00ff00", fg_color="black")
        self.live_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tab_live.grid_columnconfigure(0, weight=1)
        self.tab_live.grid_rowconfigure(0, weight=1)

        # Tab 3: Raw
        self.raw_text = ctk.CTkTextbox(self.tab_raw, font=("Consolas", 12))
        self.raw_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tab_raw.grid_columnconfigure(0, weight=1)
        self.tab_raw.grid_rowconfigure(0, weight=1)

        # --- Footer ---
        self.status_label = ctk.CTkLabel(self, text="Status: Idle", anchor="w")
        self.status_label.grid(row=1, column=1, padx=20, pady=(0, 5), sticky="w")
        
        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.grid(row=2, column=1, padx=20, pady=(0, 20), sticky="ew")
        self.progress_bar.set(0)

        # Scan Data Structure
        self.init_scan_data()

    def init_scan_data(self):
        self.scan_results = {
            "target": "", "domain": "", "start_time": "",
            "whois": {}, "buckets": [], "headers": [], "broken_links": [], "threat_intel": "",
            "waf": "Not detected", "cms": "Unknown", "tech_stack": [], "subdomains": [],
            "wordpress_users": [], "open_ports": [], "exploits": [], "nikto": [], "secrets": []
        }

    def toggle_all(self):
        val = self.select_all_var.get()
        for key in self.check_vars:
            self.check_vars[key].set(val)

    def log_dashboard(self, message, tag=None):
        self.dashboard_text.configure(state="normal")
        self.dashboard_text.insert("end", message + "\n", tag)
        self.dashboard_text.see("end")
        self.dashboard_text.configure(state="disabled")

    def log_live(self, message):
        self.live_text.insert("end", message + "\n")
        self.live_text.see("end")

    def log_raw(self, message):
        self.raw_text.insert("end", message + "\n")
        self.raw_text.see("end")

    def update_status(self, text, progress=None):
        self.status_label.configure(text=f"Status: {text}")
        if progress is not None:
            self.progress_bar.set(progress)

    def start_scan_thread(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showwarning("Error", "Please enter a target URL.")
            return

        if not (target.startswith("http://") or target.startswith("https://")):
            target = "http://" + target

        # Get Selected Modules
        selected_modules = [k for k, v in self.check_vars.items() if v.get()]
        if not selected_modules:
            messagebox.showwarning("Error", "No modules selected!")
            return

        # UI Reset
        self.start_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.dashboard_text.configure(state="normal")
        self.dashboard_text.delete("1.0", "end")
        self.dashboard_text.configure(state="disabled")
        self.live_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")
        self.progress_bar.set(0)
        self.init_scan_data()

        # Start Thread
        thread = threading.Thread(target=self.run_modular_scan, args=(target, selected_modules))
        thread.daemon = True
        thread.start()

    def run_command_live(self, command):
        self.log_live(f"\n[EXEC] {command}")
        output = ""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(process.stdout.readline, ''):
                self.log_live(line.strip())
                output += line
            process.wait()
            return output
        except Exception as e:
            self.log_live(f"[ERROR] {e}")
            return ""

    def run_modular_scan(self, target, modules):
        try:
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            self.scan_results["target"] = target
            self.scan_results["domain"] = domain
            self.scan_results["start_time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            self.log_dashboard(f"--- ROTEMZ ARSENAL v6.0 STARTED ---", "blue")
            self.log_dashboard(f"Targets: {target}")
            self.log_dashboard(f"Modules: {len(modules)} selected\n")

            # Hexstrike AI Check
            if self.hexstrike_var.get():
                try:
                    subprocess.Popen(["x-terminal-emulator", "-e", "hexstrike_mcp"])
                    self.log_dashboard("[+] 🤖 Hexstrike-AI Agent launched in autonomous mode!", "purple")
                except Exception as e:
                    self.log_dashboard(f"[!] Hexstrike Launch Failed: {e}", "red")

            total_steps = len(modules)
            current_step = 0

            # --- EXECUTION LOOP ---

            # 1. Whois & GeoIP
            if "Whois & GeoIP" in modules:
                current_step += 1
                self.update_status("Running Whois & GeoIP...", current_step/total_steps)
                self.log_dashboard("[*] Fetching Whois & GeoIP...")
                
                # GeoIP
                try:
                    ip = socket.gethostbyname(domain)
                    self.log_dashboard(f"    drived IP: {ip}")
                    r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                    if r.status_code == 200:
                        data = r.json()
                        geo_str = f"{data.get('country')}, {data.get('city')} | ISP: {data.get('isp')}"
                        self.scan_results["whois"]["geo"] = geo_str
                        self.log_dashboard(f"    Location: {geo_str}", "green")
                except Exception as e:
                    self.log_dashboard(f"    GeoIP Failed: {e}", "red")

                # Whois Lib
                if whois:
                    try:
                        w = whois.whois(domain)
                        registrar = w.registrar
                        emails = w.emails
                        if isinstance(emails, list): emails = emails[0]
                        self.scan_results["whois"]["info"] = f"Registrar: {registrar} | Contact: {emails}"
                        self.log_dashboard(f"    Whois: {registrar}", "green")
                    except Exception as e:
                        self.log_dashboard(f"    Whois lookup failed: {e}")
                else:
                    self.log_dashboard("    [!] 'whois' library not installed.")

                # Threat Intel (Basic) inside here as requested or separate? Prompt listing: "Threat Intel" logic inside Whois section? 
                # Prompt said implement 5 modules. Threat Intel was #5. I'll put it later or here since we have IP. 
                # Doing it as separate 'basic module' logic, but maybe implicit? 
                # Prompt list: "Threat Intel (Basic)" check logic. I'll check if I missed a checkbox for it. 
                # I see I missed "Threat Intel" in self.module_names! Wait, the Prompt said 5 new engines, but the checkbox list in "1. GUI Overhaul"
                # only listed: "Nmap", "Nikto", "WAF", "Subdomains", "CMS", "Exploit", "Whois", "Buckets", "Headers", "Broken Links". 
                # It did NOT list "Threat Intel" as a checkbox item.
                # However, section 2 says "Implement these 5 new Python functions".
                # I will add "Threat Intel" to the Whois step or implicitly run it, OR add a checkbox. 
                # Re-reading: "Create checkboxes for EACH tool... <list>". Threat Intel is NOT in that GUI list. 
                # So I will run Threat Intel automatically with Whois/Geo or Nmap since it's basic. Let's do it with Whois.
                
                # Threat Intel Logic
                try:
                    # Mock check or VT link
                    vt_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
                    self.scan_results["threat_intel"] = vt_link
                    self.log_dashboard(f"    [Threat Intel] Check IP here: {vt_link}", "blue")
                except: pass

            # 2. WAF Detection
            if "WAF Detection" in modules:
                current_step += 1
                self.update_status("Checking WAF...", current_step/total_steps)
                self.log_dashboard("[*] Detecting WAF...")
                if shutil.which("wafw00f"):
                    out = self.run_command_live(f"wafw00f {target}")
                    if "is behind" in out:
                        for line in out.splitlines():
                            if "is behind" in line:
                                self.scan_results["waf"] = line.strip()
                                self.log_dashboard(f"[!] {line.strip()}", "red")
                    else:
                        self.log_dashboard("[-] No WAF detected.")
                else:
                    self.log_dashboard("[!] wafw00f missing.")

            # 3. Cloud Buckets
            if "Cloud Buckets" in modules:
                current_step += 1
                self.update_status("Enumerating Cloud Buckets...", current_step/total_steps)
                self.log_dashboard("[*] Checking Cloud Buckets...")
                # Simple check
                buckets = [
                    f"https://{domain.split('.')[0]}.s3.amazonaws.com",
                    f"https://{domain.replace('.','-')}.s3.amazonaws.com",
                    f"https://storage.googleapis.com/{domain}"
                ]
                found = False
                for b in buckets:
                    try:
                        r = requests.get(b, timeout=3)
                        if r.status_code == 200:
                            self.scan_results["buckets"].append(f"{b} [OPEN]")
                            self.log_dashboard(f"[!] OPEN BUCKET FOUND: {b}", "red")
                            found = True
                        elif r.status_code == 403:
                            self.scan_results["buckets"].append(f"{b} [PROTECTED]")
                    except: pass
                if not found:
                    self.log_dashboard("[-] No open buckets found.")

            # 4. Security Headers
            if "Security Headers" in modules:
                current_step += 1
                self.update_status("Analyzing Headers...", current_step/total_steps)
                self.log_dashboard("[*] Analyzing Security Headers...")
                try:
                    r = requests.get(target, timeout=5, verify=False)
                    headers = r.headers
                    required = ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]
                    missing = [h for h in required if h not in headers]
                    
                    if missing:
                        for m in missing:
                            self.scan_results["headers"].append(m)
                            self.log_dashboard(f"[!] Missing Header: {m}", "orange")
                    else:
                        self.log_dashboard("[+] All critical headers present.", "green")
                except Exception as e:
                    self.log_dashboard(f"[!] Header analysis failed: {e}")

            # 5. Subdomain Enum
            if "Subdomains Enum" in modules:
                current_step += 1
                self.update_status("Enumerating Subdomains...", current_step/total_steps)
                if shutil.which("sublist3r"):
                    self.log_dashboard("[*] Running Sublist3r...")
                    out = self.run_command_live(f"sublist3r -d {domain} -n -t 5") # Reduced threads for speed
                    subs = set()
                    for line in out.splitlines():
                        if line.strip().endswith(domain) and line.strip() != domain:
                            subs.add(line.strip())
                    self.scan_results["subdomains"] = list(subs)
                    self.log_dashboard(f"[+] Found {len(subs)} subdomains.")
                else:
                    self.log_dashboard("[!] sublist3r missing.")

            # 6. Broken Links
            if "Broken Links" in modules:
                current_step += 1
                self.update_status("Checking Broken Links...", current_step/total_steps)
                self.log_dashboard("[*] Checking Broken Links (Limit 20)...")
                if BeautifulSoup:
                    try:
                        r = requests.get(target, timeout=5, verify=False)
                        soup = BeautifulSoup(r.text, 'html.parser')
                        links = soup.find_all('a', href=True)
                        count = 0
                        broken_count = 0
                        for l in links:
                            href = l['href']
                            if href.startswith('http') and domain not in href:
                                if count >= 20: break
                                try:
                                    # Use Head for speed
                                    rh = requests.head(href, timeout=3, allow_redirects=True)
                                    if rh.status_code == 404:
                                        self.scan_results["broken_links"].append(href)
                                        self.log_dashboard(f"[!] BROKEN LINK: {href}", "red")
                                        broken_count += 1
                                    count += 1
                                except: pass
                        if broken_count == 0:
                            self.log_dashboard("[-] No broken external links found (in sample).")
                    except Exception as e:
                        self.log_dashboard(f"[!] Broken link check failed: {e}")
                else:
                    self.log_dashboard("[!] BeautifulSoup not installed.")

            # 7. CMS/WP Scan
            if "CMS/WP Scan" in modules:
                current_step += 1
                self.update_status("CMS Scan...", current_step/total_steps)
                self.log_dashboard("[*] CMS Detection...")
                # Same WP Logic + Tech Stack (WhatWeb) if checked essentially
                # Since Tech Stack wasn't a separate checkbox in the prompt list, I might merge it or skip.
                # Actually, I'll run WhatWeb here too if available as part of CMS.
                if shutil.which("whatweb"):
                    self.run_command_live(f"whatweb -a 1 {target}") # fast scan for live view
                
                # Check WP
                is_wp = False
                try:
                    if requests.get(f"{target}/wp-login.php", timeout=5, verify=False).status_code == 200:
                        is_wp = True
                except: pass
                
                if is_wp:
                    self.log_dashboard("[+] WordPress Detected.", "orange")
                    if shutil.which("wpscan"):
                        self.log_dashboard("[*] Running WPScan...")
                        out = self.run_command_live(f"wpscan --url {target} --enumerate u --no-banner --random-user-agent")
                        if "Identified the following" in out:
                            self.scan_results["wordpress_users"] = ["Users Found"]
                else:
                    self.log_dashboard("[-] No WordPress detected.")

            # 8. Nmap Port Scan
            nmap_services = [] # For exploits
            if "Nmap Port Scan" in modules:
                current_step += 1
                self.update_status("Running Nmap...", current_step/total_steps)
                self.log_dashboard("[*] Running Nmap...")
                if shutil.which("nmap"):
                    args = "-sV -F"
                    if self.stealth_var.get(): args = "-sV -sS -T2 -f"
                    out = self.run_command_live(f"nmap {args} {domain}")
                    for line in out.splitlines():
                        if "/tcp" in line and "open" in line:
                            parts = line.split()
                            svc = {'port': parts[0], 'service': parts[2], 'version': " ".join(parts[3:])}
                            nmap_services.append(svc)
                            self.scan_results["open_ports"].append(f"{svc['port']} {svc['service']} {svc['version']}")
                else:
                    self.log_dashboard("[!] Nmap missing.")

            # 9. Exploit Check
            if "Exploit Check" in modules:
                current_step += 1
                self.update_status("Checking Exploits...", current_step/total_steps)
                # Needs results from Nmap, or if Nmap wasn't run, we can't do much.
                if nmap_services and shutil.which("searchsploit"):
                    self.log_dashboard("[*] Checking SearchSploit...")
                    for s in nmap_services:
                        term = f"{s['service']} {s['version'].split('(')[0]}"
                        out = self.run_command_live(f"searchsploit {term}")
                        # Simple parse
                        if "Exploits: No Results" not in out:
                             self.scan_results["exploits"].append(f"Potential exploit for {term}")
                             self.log_dashboard(f"[!] Exploit data found for {term}", "red")
                elif not nmap_services:
                    self.log_dashboard("[-] Skipping exploits (No ports found or Nmap skipped).")

            # 10. Nikto Web Scan
            if "Nikto Web Scan" in modules:
                current_step += 1
                self.update_status("Running Nikto...", current_step/total_steps)
                self.log_dashboard("[*] Running Nikto...")
                if shutil.which("nikto"):
                    # Fast-ish nikto
                    cmd = f"nikto -h {target} -Tuning x 6 -nointeractive -maxtime 5m"
                    out = self.run_command_live(cmd)
                    # Don't parse too deep, just store present
                    self.scan_results["nikto"] = "Run complete. Check raw logs."
                else:
                    self.log_dashboard("[!] Nikto missing.")

            # 11. Secrets Hunter
            if "Secrets Hunter (JS)" in modules:
                current_step += 1
                self.update_status("Hunting Secrets...", current_step/total_steps)
                self.scan_secrets_logic(target, domain)

            # Finish
            self.update_status("Scan Complete", 1.0)
            self.log_dashboard("\n--- SCAN FINISHED ---", "green")
            self.start_button.configure(state="normal")
            self.export_button.configure(state="normal")
        
        except Exception as e:
            self.log_dashboard(f"\n[!] CRITICAL FAILURE: {e}", "red")
            self.start_button.configure(state="normal")

    def generate_html_report(self):
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")], initialfile="rotemz_v6_report.html")
        if not filename: return
        
        r = self.scan_results
        html = f"""
        <html>
        <head>
            <title>ROTEMZ v6.0 Report</title>
            <style>
                body {{ font-family: 'Segoe UI', sans-serif; background: #121212; color: #ddd; padding: 20px; }}
                h1 {{ color: #00ff00; border-bottom: 2px solid #333; }}
                h2 {{ color: #4da6ff; margin-top: 30px; background: #1e1e1e; padding: 10px; border-radius: 5px; }}
                .box {{ background: #1e1e1e; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
                .alert {{ color: #ff4444; font-weight: bold; }}
                pre {{ background: #000; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>ROTEMZ ARSENAL v6.0 Scan Report</h1>
            <p>Target: {r['target']} | Domain: {r['domain']}</p>
            <p>Date: {r['start_time']}</p>

            <h2>1. Reconnaissance & Intelligence</h2>
            <div class="box">
                <p><strong>GeoIP:</strong> {r['whois'].get('geo','N/A')}</p>
                <p><strong>Whois:</strong> {r['whois'].get('info','N/A')}</p>
                <p><strong>Threat Intel:</strong> <a href="{r.get('threat_intel','#')}" style="color:#00ff00">VirusTotal Link</a></p>
            </div>

            <h2>2. Infrastructure & Cloud</h2>
            <div class="box">
                <p><strong>WAF:</strong> {r['waf']}</p>
                <p><strong>Cloud Buckets ({len(r['buckets'])}):</strong></p>
                <ul>{''.join([f'<li class="alert">{b}</li>' for b in r['buckets']])}</ul>
                <p><strong>Subdomains ({len(r['subdomains'])}):</strong></p>
                <pre>{chr(10).join(r['subdomains'])[:1000]} ...</pre>
            </div>

            <h2>3. Web Application Security</h2>
            <div class="box">
                <p><strong>Missing Security Headers:</strong></p>
                <ul>{''.join([f'<li class="alert">{h}</li>' for h in r['headers']])}</ul>
                <p><strong>Broken External Links (Possible Hijacking):</strong></p>
                <ul>{''.join([f'<li class="alert">{l}</li>' for l in r['broken_links']])}</ul>
                <p><strong>CMS:</strong> {r['cms']}</p>
                <p><strong>WordPress Users:</strong> {r['wordpress_users']}</p>
            </div>

            <h2>4. Network & Vulnerabilities</h2>
            <div class="box">
                <p><strong>Open Ports:</strong></p>
                <ul>{''.join([f'<li>{p}</li>' for p in r['open_ports']])}</ul>
                <p><strong>Potential Exploits:</strong></p>
                <ul>{''.join([f'<li class="alert">{e}</li>' for e in r['exploits']])}</ul>
            </div>

            <h2>5. Leaked Secrets (CRITICAL)</h2>
            <div class="box">
                <p><strong>Sensitive Keys Found:</strong></p>
                <ul>{''.join([f'<li class="alert">{s}</li>' for s in r['secrets']])}</ul>
                <p><em>(If any keys found, rotate immediately!)</em></p>
            </div>
        </body>
        </html>
        """
        try:
            with open(filename, "w") as f: f.write(html)
            messagebox.showinfo("Report Saved", f"Saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def scan_secrets_logic(self, target, domain):
        self.log_dashboard("[*] Starting Secrets Hunter (Main + JS)...")
        secrets_found = []
        js_urls = set()
        
        # Regex Patterns
        patterns = {
            "Google API": r"AIza[0-9A-Za-z-_]{35}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Generic Secret": r"(api_key|apikey|secret|token)\s*[:=]\s*['\"][0-9a-zA-Z\-_]{20,}['\"]",
            "Private Key": r"-----BEGIN RSA PRIVATE KEY-----"
        }

        try:
            # Fetch Main HTML
            self.log_dashboard("[*] Crawling main page...")
            try:
                r = requests.get(target, timeout=10, verify=False)
                html_content = r.text
            except Exception as e:
                self.log_dashboard(f"[!] Failed to fetch {target}: {e}")
                return

            # Scan HTML content
            for name, pattern in patterns.items():
                for m in re.finditer(pattern, html_content):
                    val = m.group(0)
                    self.scan_results["secrets"].append(f"{val} (Source: Main Page)")
                    self.log_dashboard(f"[!] CRITICAL: Found {name} in Main Page!", "red")
                    self.log_live(f"[!] CRITICAL: Found {name}: {val}")

            # Extract JS Links
            if BeautifulSoup:
                soup = BeautifulSoup(html_content, 'html.parser')
                for script in soup.find_all('script', src=True):
                    src = urljoin(target, script['src'])
                    if domain in src:
                        js_urls.add(src)
            else:
                # Regex Fallback
                raw_links = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html_content)
                for link in raw_links:
                     src = urljoin(target, link)
                     if domain in src:
                        js_urls.add(src)

            # Limit to 10
            js_list = list(js_urls)[:10]
            self.log_dashboard(f"[*] Scanning {len(js_list)} JS files...")

            for i, js_url in enumerate(js_list):
                 try:
                     self.log_live(f"    Scanning JS ({i+1}): {js_url}")
                     js_r = requests.get(js_url, timeout=5, verify=False)
                     js_text = js_r.text
                     
                     for name, pattern in patterns.items():
                        for m in re.finditer(pattern, js_text):
                            val = m.group(0)
                            # Truncate if too long for log? Nah.
                            self.scan_results["secrets"].append(f"{val} (Source: {js_url.split('/')[-1]})")
                            self.log_dashboard(f"[!] CRITICAL: Found {name} in {js_url.split('/')[-1]}!", "red")
                            self.log_live(f"[!] CRITICAL: Found {name} in JS: {val}")
                 except Exception as e:
                     self.log_live(f"    [!] Error scanning JS: {e}")

        except Exception as e:
            self.log_dashboard(f"[!] Secrets Scan Error: {e}")
        
        if not self.scan_results["secrets"]:
            self.log_dashboard("[-] No secrets found.")

if __name__ == "__main__":
    app = RotemzScanner()
    app.mainloop()

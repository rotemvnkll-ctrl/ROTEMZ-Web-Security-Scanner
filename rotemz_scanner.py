
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

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class RotemzScanner(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Root Check
        if os.geteuid() != 0:
            messagebox.showwarning("Root Required", "Run as root (sudo) for full Nmap features.")
        
        self.title("ROTEMZ Web Security Scanner v4.0 (Intelligence Edition)")
        self.geometry("1200x850")
        
        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Left Panel) ---
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, rowspan=2, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="ROTEMZ\nSCANNER v4.0", font=ctk.CTkFont(size=20, weight="bold"))
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

        # Start Button
        self.start_button = ctk.CTkButton(self.sidebar_frame, text="START SCAN 🚀", command=self.start_scan_thread, fg_color="#db2e2e", hover_color="#a81f1f")
        self.start_button.grid(row=4, column=0, padx=20, pady=20)

        # Export Button
        self.export_button = ctk.CTkButton(self.sidebar_frame, text="Export HTML Report 📄", command=self.generate_html_report, state="disabled")
        self.export_button.grid(row=6, column=0, padx=20, pady=20)

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
        # Configure tags for colors
        self.dashboard_text.tag_config("red", foreground="#ff4444")
        self.dashboard_text.tag_config("green", foreground="#00ff00")
        self.dashboard_text.tag_config("orange", foreground="#FFA500")

        # Tab 2: Live Terminal
        self.live_text = ctk.CTkTextbox(self.tab_live, font=("Courier New", 12), text_color="#00ff00", fg_color="black")
        self.live_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.tab_live.grid_columnconfigure(0, weight=1)
        self.tab_live.grid_rowconfigure(0, weight=1)

        # Tab 3: Raw Data
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

        # Scan Data
        self.scan_results = {
            "target": "", "start_time": "", "waf": "Not detected", "cms": "Unknown", "tech_stack": [],
            "subdomains": [], "wordpress_users": [], "open_ports": [], "exploits": [], "robots_txt": "Not found"
        }

    def log_dashboard(self, message, tag=None):
        self.dashboard_text.configure(state="normal")
        if tag:
            self.dashboard_text.insert("end", message + "\n", tag)
        else:
            self.dashboard_text.insert("end", message + "\n")
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
        
        # Reset UI
        self.start_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.dashboard_text.configure(state="normal")
        self.dashboard_text.delete("1.0", "end")
        self.dashboard_text.configure(state="disabled")
        self.live_text.delete("1.0", "end")
        self.raw_text.delete("1.0", "end")
        self.progress_bar.set(0)
        
        # Start Thread
        thread = threading.Thread(target=self.run_scan_logic, args=(target,))
        thread.daemon = True
        thread.start()

    def run_command_live(self, command, env=None):
        self.log_live(f"\n[EXEC] {command}")
        output_buffer = ""
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env
            )
            for line in iter(process.stdout.readline, ''):
                self.log_live(line.strip())
                output_buffer += line
            process.wait()
            return output_buffer
        except Exception as e:
            self.log_live(f"[ERROR] {e}")
            return ""

    def run_scan_logic(self, target):
        try:
            domain = target.replace("http://", "").replace("https://", "").split("/")[0]
            self.scan_results = {
                "target": target, "start_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "waf": "Not detected", "cms": "Unknown", "tech_stack": [], "subdomains": [],
                "wordpress_users": [], "open_ports": [], "exploits": [], "robots_txt": "Not found"
            }

            self.log_dashboard(f"--- ROTEMZ SCANNER v4.0 STARTED: {self.scan_results['start_time']} ---")
            self.log_dashboard(f"Target: {target} ({domain})")
            
            # --- 1. WAF Detection ---
            self.update_status("Detecting WAF...", 0.1)
            self.log_dashboard("[*] Checking for WAF...")
            if shutil.which("wafw00f"):
                out = self.run_command_live(f"wafw00f {target}")
                if "is behind" in out:
                    for line in out.splitlines():
                        if "is behind" in line:
                            self.scan_results["waf"] = line.strip()
                            self.log_dashboard(f"[!] WAF DETECTED: {line.strip()}", "red")
                else:
                    self.log_dashboard("[-] No WAF detected.", "green")
            else:
                self.log_dashboard("[!] wafw00f not installed.")

            # --- 2. Subdomain Enumeration (NEW) ---
            self.update_status("Enumerating Subdomains (This may take time)...", 0.2)
            self.log_dashboard("\n[*] Enumerating Subdomains...")
            if shutil.which("sublist3r"):
                # Capturing output for raw tab
                cmd = f"sublist3r -d {domain} -n -t 10"
                out = self.run_command_live(cmd)
                
                # Parse
                found_subs = []
                for line in out.splitlines():
                    clean = line.strip()
                    # Sublist3r usually outputs domains at the end or cleanly. We look for domains ending in base domain.
                    if clean.endswith(domain) and clean != domain:
                         if clean not in found_subs: # avoid dupes
                            found_subs.append(clean)

                self.scan_results["subdomains"] = found_subs
                self.log_raw(f"\n--- Subdomains ---\n{chr(10).join(found_subs)}\n------------------")
                self.log_dashboard(f"[+] Found {len(found_subs)} unique subdomains (See 'Raw Data').")
            else:
                 self.log_dashboard("[!] sublist3r not installed.")

            # --- 3. Tech Stack Fingerprinting (NEW) ---
            self.update_status("Fingerprinting Tech Stack...", 0.35)
            self.log_dashboard("\n[*] Fingerprinting Tech Stack (WhatWeb)...")
            if shutil.which("whatweb"):
                out = self.run_command_live(f"whatweb --color=never --no-errors -a 3 {target}")
                # Parse output - WhatWeb output is usually one line per target with comma separated tags
                # Example: http://example.com [200 OK] Country[US], HTTPServer[ECS], IP[93.184.216.34], Title[Example Domain]
                
                # We want to extract key info
                techs = []
                # Simple regex or string split
                if "]" in out:
                     parts = out.split(", ")
                     for p in parts:
                         if "[" in p and "]" in p:
                             techs.append(p.strip())
                
                self.scan_results["tech_stack"] = techs
                if techs:
                     self.log_dashboard("[+] Tech Stack Identified:")
                     for t in techs:
                         self.log_dashboard(f"    - {t}")
            else:
                self.log_dashboard("[!] whatweb not installed.")

            # --- 4. CMS Detection (WordPress) ---
            self.update_status("Checking CMS...", 0.5)
            self.log_dashboard("\n[*] Checking for WordPress...")
            is_wp = False
            # Quick Check
            try:
                r = requests.get(f"{target}/wp-login.php", timeout=5, verify=False)
                if r.status_code == 200: is_wp = True
            except: pass
            
            if is_wp:
                self.scan_results["cms"] = "WordPress"
                self.log_dashboard("[+] WordPress Detected!", "orange")
                if shutil.which("wpscan"):
                    self.log_dashboard("    Running WPScan User Enum...")
                    out = self.run_command_live(f"wpscan --url {target} --enumerate u --no-banner --random-user-agent")
                    if "Identified the following" in out:
                        self.scan_results["wordpress_users"] = ["Users found (Check logs)"]
                        self.log_dashboard("[!] WordPress Users Found!", "red")
            else:
                self.log_dashboard("[-] No WordPress detected.")

            # --- 5. Nmap Scan (Service Detection) ---
            self.update_status("Running Nmap (Service Discovery)...", 0.65)
            self.log_dashboard("\n[*] Running Nmap Service Scan...")
            
            nmap_cmd = f"nmap -sV -F {domain}" # Added -sV for service version
            if self.stealth_var.get():
                nmap_cmd = f"nmap -sV -sS -T2 -f {domain}" # Stealth + Version
                
            services_found = [] # List of (port, service_name, version)
            
            if shutil.which("nmap"):
                out = self.run_command_live(nmap_cmd)
                
                # Parse Nmap Output for Services
                # Example: 21/tcp open ftp vsftpd 2.3.4
                for line in out.splitlines():
                    if "/tcp" in line and "open" in line:
                         parts = line.split()
                         port = parts[0]
                         service = parts[2]
                         version = " ".join(parts[3:]) # Grab rest of line as version
                         services_found.append({'port': port, 'service': service, 'version': version})
                         self.scan_results["open_ports"].append(f"{port}: {service} {version}")

                if not services_found:
                    self.log_dashboard("[-] No open ports found.")
            else:
                self.log_dashboard("[!] Nmap not installed.")

            # --- 6. Exploit Check (NEW) ---
            self.update_status("Checking for Exploits...", 0.85)
            self.log_dashboard("\n[*] Correlating Vulnerabilities (Exploit-DB)...")
            
            if shutil.which("searchsploit") and services_found:
                for svc in services_found:
                    s_name = svc['service']
                    s_ver = svc['version']
                    
                    if s_name == "unknown" or not s_ver: continue
                    
                    # Clean version for search (remove extra info inside parens usually)
                    # Simple heuristic: take first 2 words of version
                    search_term = f"{s_name} {s_ver.split('(')[0].strip()}"
                    
                    self.log_live(f"\n[SEARCH] Checking exploits for: {search_term}")
                    # Run searchsploit
                    # searchsploit --json is parsed easier, but simple text grep is fine for this UI
                    out = self.run_command_live(f"searchsploit {search_term}")
                    
                    if "Exploits: No Results" not in out and "Error" not in out and "not found" not in out.lower():
                        # Parse lines that look like exploits
                        lines = out.splitlines()
                        found_for_service = False
                        for line in lines:
                             if "|" in line and "Path" not in line and "Title" not in line: # Skip headers
                                 title = line.split("|")[0].strip()
                                 path = line.split("|")[1].strip()
                                 self.log_dashboard(f"[!] VULN FOUND: {title}", "red")
                                 self.scan_results["exploits"].append(f"Port {svc['port']} ({s_name}): {title}")
                                 found_for_service = True
                                 break # Just show one/first exploit to avoid spamming dashboard
                        if not found_for_service:
                             # It might have returned results but header-only or similar
                             pass
            elif not shutil.which("searchsploit"):
                self.log_dashboard("[!] searchsploit not installed.")
            
            # Robots/Sitemap (Fast)
            self.update_status("Finalizing...", 0.95)
            try:
                 if requests.get(f"{target}/robots.txt", timeout=3, verify=False).status_code == 200:
                     self.scan_results["robots_txt"] = "Found"
                 if requests.get(f"{target}/sitemap.xml", timeout=3, verify=False).status_code == 200:
                     self.log_raw("\nsitemap.xml found")
            except: pass

            self.update_status("Scan Complete", 1.0)
            self.log_dashboard("\n--- SCAN FINISHED ---", "green")
            self.start_button.configure(state="normal")
            self.export_button.configure(state="normal")

        except Exception as e:
            self.log_dashboard(f"\n[!] CRITICAL ERROR: {e}", "red")
            self.update_status("Error", 0)
            self.start_button.configure(state="normal")

    def generate_html_report(self):
        filename = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Files", "*.html")], initialfile="rotemz_v4_report.html")
        if not filename: return
        
        # Build HTML
        html = f"""
        <html>
        <head>
            <title>ROTEMZ v4.0 Report</title>
            <style>
                body {{ font-family: sans-serif; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
                h1, h2 {{ color: #00ff00; border-bottom: 1px solid #444; }}
                .alert {{ color: #ff5555; font-weight: bold; }}
                .box {{ background: #2b2b2b; padding: 15px; margin: 10px 0; border-radius: 5px; }}
            </style>
        </head>
        <body>
            <h1>ROTEMZ Web Security Scanner v4.0 Report</h1>
            <p>Target: {self.scan_results['target']} | Date: {self.scan_results['start_time']}</p>
            
            <h2>1. Intelligence Overview</h2>
            <div class="box">
                <p><strong>WAF:</strong> {self.scan_results['waf']}</p>
                <p><strong>CMS:</strong> {self.scan_results['cms']}</p>
                <p><strong>Tech Stack:</strong></p>
                <ul>{''.join([f'<li>{t}</li>' for t in self.scan_results['tech_stack']])}</ul>
            </div>

            <h2>2. Subdomains ({len(self.scan_results['subdomains'])})</h2>
            <div class="box">
                <pre>{chr(10).join(self.scan_results['subdomains']) if self.scan_results['subdomains'] else "No subdomains found."}</pre>
            </div>

            <h2>3. Critical Vulnerabilities</h2>
            <div class="box">
                {''.join([f'<p class="alert">{e}</p>' for e in self.scan_results['exploits']]) if self.scan_results['exploits'] else "<p>No direct exploits correlated.</p>"}
            </div>
            
            <h2>4. Open Ports & Services</h2>
            <div class="box">
                <ul>{''.join([f'<li>{p}</li>' for p in self.scan_results['open_ports']])}</ul>
            </div>
        </body>
        </html>
        """
        try:
            with open(filename, "w") as f: f.write(html)
            messagebox.showinfo("Success", f"Report saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = RotemzScanner()
    app.mainloop()

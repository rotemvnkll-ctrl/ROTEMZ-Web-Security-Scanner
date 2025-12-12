
import customtkinter as ctk
import subprocess
import threading
import os
import sys
import ssl
import socket
import datetime
from tkinter import messagebox, filedialog
import shutil

# --- Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")  # Hacker-ish green theme

class RotemzScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Root Check
        if os.geteuid() != 0:
            messagebox.showerror("Permission Denied", "This tool must be run as root!")
            print("Run as Root!")
            sys.exit(1)

        self.title("ROTEMZ Web Security Scanner")
        self.geometry("900x700")

        # Layout Configuration
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        self.header_label = ctk.CTkLabel(self, text="ROTEMZ Web Security Scanner", font=("Roboto Medium", 24))
        self.header_label.grid(row=0, column=0, pady=20, sticky="ew")

        # Input Frame
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter Target URL/Domain (e.g., scanme.nmap.org)")
        self.url_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.start_button = ctk.CTkButton(self.input_frame, text="Start Scan", command=self.start_scan_thread)
        self.start_button.grid(row=0, column=1, padx=10, pady=10)

        # Status Label
        self.status_label = ctk.CTkLabel(self, text="Status: Idle", text_color="gray")
        self.status_label.grid(row=3, column=0, pady=5, sticky="w", padx=20)

        # Results Area
        self.results_textbox = ctk.CTkTextbox(self, font=("Consolas", 12))
        self.results_textbox.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

        # Footer / Actions
        self.footer_frame = ctk.CTkFrame(self)
        self.footer_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        self.footer_frame.grid_columnconfigure(0, weight=1)
        
        self.export_button = ctk.CTkButton(self.footer_frame, text="Export Report", command=self.export_report)
        self.export_button.grid(row=0, column=1, padx=10, pady=10, sticky="e")


    def start_scan_thread(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target URL or Domain.")
            return

        self.start_button.configure(state="disabled")
        self.results_textbox.delete("1.0", "end")
        self.update_status("Starting scan on " + target + "...")
        
        # Start background thread
        thread = threading.Thread(target=self.run_scan_logic, args=(target,))
        thread.daemon = True
        thread.start()

    def update_status(self, message):
        self.status_label.configure(text=f"Status: {message}")
        self.update_idletasks()

    def append_output(self, text):
        self.results_textbox.insert("end", text + "\n")
        self.results_textbox.see("end")

    def run_scan_logic(self, target):
        try:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.append_output("--- ROTEMZ Web Security Scanner Report ---")
            self.append_output(f"Target: {target}")
            self.append_output(f"Date: {timestamp}\n")

            # Extract hostname from URL if needed
            hostname = target.replace("http://", "").replace("https://", "").split("/")[0]

            # 1. DNS Recon
            self.update_status(f"Running DNS Recon on {hostname}...")
            self.scan_dns(hostname)

            # 2. Ports (Nmap)
            self.update_status(f"Running Nmap on {hostname}...")
            self.scan_nmap(hostname)

            # 3. SSL Info
            self.update_status(f"Fetching SSL Info for {hostname}...")
            self.scan_ssl(hostname)

            # 4. Web Vulns (Nikto)
            self.update_status(f"Running Nikto on {target}...")
            self.scan_nikto(target)

            # 5. Directory Enum (Gobuster)
            self.update_status(f"Running Gobuster on {target}...")
            self.scan_gobuster(target)

            self.update_status("Scan Complete.")
            self.append_output("\n[+] Scan Finished Successfully.")
            
        except Exception as e:
            self.append_output(f"\n[!] Critical Error during scan: {str(e)}")
            self.update_status("Error occurred.")
        finally:
             self.start_button.configure(state="normal")

    # --- Scanning Modules ---

    def run_command(self, command):
        """Helper to run shell commands and return output, handling missing tools."""
        tool = command.split()[0]
        if not shutil.which(tool):
            return f"[!] Error: Tool '{tool}' not found on this system."
        
        try:
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate()
            if process.returncode != 0 and not stdout: # Some tools return non-zero on minor issues but still give output
                 return f"Error running {tool}: {stderr.strip()}"
            return stdout
        except Exception as e:
            return f"Exception running {tool}: {str(e)}"

    def scan_dns(self, hostname):
        self.append_output("[+] DNS Records")
        try:
            # Using 'host' command as it's common on Kali
            output = self.run_command(f"host {hostname}")
            if "not found" in output:
                self.append_output("   - Host not found or DNS resolution failed.")
            else:
                for line in output.splitlines():
                    if "has address" in line: # A record
                        self.append_output(f"   - A: {line.split()[-1]}")
                    elif "mail is handled by" in line: # MX record
                        self.append_output(f"   - MX: {line.split()[-1]}")
                    elif "name server" in line: # NS record
                         self.append_output(f"   - NS: {line.split()[-1]}")
        except Exception as e:
            self.append_output(f"   - Error fetching DNS: {e}")
        self.append_output("")

    def scan_nmap(self, hostname):
        self.append_output("[+] Network & Ports")
        cmd = f"nmap -F {hostname}"
        output = self.run_command(cmd)
        
        found_ports = False
        for line in output.splitlines():
            if "/tcp" in line and "open" in line:
                # Clean up format: "80/tcp open http" -> "Port 80: Open (http)"
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                self.append_output(f"   - Port {port}: Open ({service})")
                found_ports = True
        
        if not found_ports:
             self.append_output("   - No open ports found (top 100 fast scan).")
        self.append_output("")

    def scan_ssl(self, hostname):
        self.append_output("[+] SSL Details")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    org_name = issuer.get('organizationName') or issuer.get('commonName') or "Unknown"
                    self.append_output(f"   - Issuer: {org_name}")
                    
                    # Expiry
                    not_after = cert['notAfter']
                    # Parse date format: 'Dec 31 23:59:59 2025 GMT'
                    dt = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    self.append_output(f"   - Expires: {dt.strftime('%Y-%m-%d')}")
        except Exception as e:
             self.append_output(f"   - SSL Info unavailable or connection failed: {e}")
        self.append_output("")

    def scan_nikto(self, target):
        self.append_output("[+] Web Vulnerabilities (Nikto)")
        # -Tuning x 6 options for speed if desired, or standard. Command hint said -Tuning x 6
        cmd = f"nikto -h {target} -Tuning x6 -nointeractive" 
        output = self.run_command(cmd)
        
        count = 0
        for line in output.splitlines():
            if line.startswith("+"):
                # Clean up the output, maybe truncate long lines
                clean_line = line[1:].strip() # Remove leading +
                if len(clean_line) > 100:
                    clean_line = clean_line[:97] + "..."
                self.append_output(f"   - {clean_line}")
                count += 1
        
        if count == 0:
            self.append_output("   - No specific vulnerabilities found in fast scan.")
        self.append_output("")

    def scan_gobuster(self, target):
        self.append_output("[+] Directory Enum (Gobuster)")
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        
        if not os.path.exists(wordlist):
             self.append_output(f"   - Wordlist not found at {wordlist}. Skipping.")
             return

        # -b 404 to hide 404s, -q for quiet mode to make parsing easier (or just parse standard)
        # using -n (no status) might check flags. 
        # Hint said: Suppress 404.
        cmd = f"gobuster dir -u {target} -w {wordlist} -b 404 --no-error -t 20"
        
        # Gobuster relies on real-time output often, but for this simplified GUI we wait for process or read line by line.
        # For simplicity in this structure, we run it and wait, but it might take time.
        # Since we are in a thread, it won't freeze UI, but user sees nothing until done.
        # Optimization: Could use Popen and read stdout in loop to stream results, but requirements say "Capture output... CLEAN/PARSE ... before displaying".
        # So waiting is fine as long as we parse it well.
        
        output = self.run_command(cmd)
        
        for line in output.splitlines():
            if line.startswith("/"):
                # Format: /admin (Status: 301)
                # gobuster output usually looks like: /admin (Status: 301) [Size: 123]
                parts = line.split()
                path = parts[0]
                status = "Unknown"
                for part in parts:
                    if "Status:" in part: # newer gobuster
                        # Status: 301) -> catch parsing
                        pass
                
                # Simple parsing as gobuster output is fairly clean
                self.append_output(f"   - {line.strip()}")
        
        if not output.strip():
             self.append_output("   - No directories found or tool failed.")
        self.append_output("")

    def export_report(self):
        report_content = self.results_textbox.get("1.0", "end")
        if not report_content.strip():
            messagebox.showinfo("Export", "Nothing to export yet!")
            return
            
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if filename:
            try:
                with open(filename, "w") as f:
                    f.write(report_content)
                messagebox.showinfo("Export Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file: {e}")

if __name__ == "__main__":
    app = RotemzScannerApp()
    app.mainloop()

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Set the appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class WebScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Professional Web Vulnerability Scanner")
        self.geometry("1100x700")

        # --- Backend Logic Integration ---
        self.target_links = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security-Audit-Tool)"})
        self.is_scanning = False

        self.setup_ui()

    def setup_ui(self):
        # Configure grid layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- Sidebar (Configuration) ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="SCAN SETTINGS", font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))

        self.url_label = ctk.CTkLabel(self.sidebar, text="Target URL:")
        self.url_label.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        self.url_entry = ctk.CTkEntry(self.sidebar, placeholder_text="https://example.com", width=220)
        self.url_entry.grid(row=2, column=0, padx=20, pady=10)

        self.scan_btn = ctk.CTkButton(self.sidebar, text="Start Scan", command=self.start_scan_thread, fg_color="#2c8558", hover_color="#236b46")
        self.scan_btn.grid(row=3, column=0, padx=20, pady=20)

        self.clear_btn = ctk.CTkButton(self.sidebar, text="Clear Results", command=self.clear_results, fg_color="transparent", border_width=1)
        self.clear_btn.grid(row=4, column=0, padx=20, pady=10)

        self.status_label = ctk.CTkLabel(self.sidebar, text="Status: Ready", text_color="gray")
        self.status_label.grid(row=10, column=0, padx=20, pady=20, sticky="s")

        # --- Main Content Area ---
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Top Label
        self.dashboard_label = ctk.CTkLabel(self.main_frame, text="Vulnerability Dashboard", font=ctk.CTkFont(size=24, weight="bold"))
        self.dashboard_label.grid(row=0, column=0, padx=0, pady=(0, 20), sticky="w")

        # Findings Table (Treeview)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.map("Treeview", background=[('selected', '#1f538d')])

        self.tree_frame = tk.Frame(self.main_frame, bg="#2b2b2b")
        self.tree_frame.grid(row=1, column=0, sticky="nsew")

        self.tree = ttk.Treeview(self.tree_frame, columns=("Type", "Severity", "URL"), show='headings')
        self.tree.heading("Type", text="Vulnerability Type")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("URL", text="Resource URL")
        
        self.tree.column("Type", width=200)
        self.tree.column("Severity", width=100)
        self.tree.column("URL", width=400)
        
        self.tree.pack(side="left", fill="both", expand=True)

        # Log Terminal
        self.log_text = ctk.CTkTextbox(self.main_frame, height=200, font=("Courier New", 12))
        self.log_text.grid(row=2, column=0, pady=(20, 0), sticky="nsew")
        self.log_text.insert("0.0", "--- Activity Log ---\n")

    # --- Scanner Logic ---
    def log(self, message):
        self.log_text.insert("end", f"[*] {message}\n")
        self.log_text.see("end")

    def report_finding(self, vuln_type, severity, url):
        self.tree.insert("", "end", values=(vuln_type, severity, url))
        # Color coding severity would require complex tag handling in Treeview, 
        # so we keep it text-based for stability.

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.log_text.delete("1.0", "end")
        self.target_links.clear()

    def start_scan_thread(self):
        target = self.url_entry.get().strip()
        if not target.startswith("http"):
            messagebox.showerror("Error", "Please enter a valid URL (including http/https)")
            return
        
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Status: Scanning...", text_color="#3b8ed0")
        
        # Launching thread so GUI stays responsive
        thread = threading.Thread(target=self.run_scanner, args=(target,), daemon=True)
        thread.start()

    def run_scanner(self, target_url):
        try:
            self.log(f"Starting Scan on {target_url}")
            
            # 1. Header Check
            self.log("Checking security headers...")
            headers = self.session.get(target_url, timeout=5).headers
            for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                if h not in headers:
                    self.report_finding("Missing Header", "Medium", target_url)

            # 2. Directory Brute Force (Sample list)
            self.log("Checking sensitive directories...")
            wordlist = ["admin", "config", ".git", "backup", "phpinfo"]
            for path in wordlist:
                url = urljoin(target_url, path)
                try:
                    res = self.session.get(url, timeout=2)
                    if res.status_code == 200:
                        self.report_finding("Sensitive Directory", "Medium", url)
                except: pass

            # 3. Parameter Testing (XSS/SQLi)
            # For brevity in this UI code, we test the root; 
            # in a real app, you'd integrate your recursive crawl here.
            self.log("Auditing root parameters...")
            self.test_vulns(target_url)

            self.log("Scan Completed Successfully.")
            self.status_label.configure(text="Status: Finished", text_color="#2c8558")
        except Exception as e:
            self.log(f"Error: {str(e)}")
            self.status_label.configure(text="Status: Error", text_color="#dc3545")
        finally:
            self.is_scanning = False
            self.scan_btn.configure(state="normal", text="Start Scan")

    def test_vulns(self, url):
        # SQLi Test
        if "?" in url:
            test_url = url.replace("=", "='")
            res = self.session.get(test_url)
            if "sql syntax" in res.text.lower():
                self.report_finding("Potential SQLi", "High", url)
        
        # XSS Test
        payload = "<script>alert(1)</script>"
        if "?" in url:
            test_url = url.replace("=", f"={payload}")
            res = self.session.get(test_url)
            if payload in res.text:
                self.report_finding("Reflected XSS", "High", url)

if __name__ == "__main__":
    app = WebScannerGUI()
    app.mainloop()

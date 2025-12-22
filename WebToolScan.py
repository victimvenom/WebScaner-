# ==============================================================================#
#                                                                               #
#                                                                               #
#                                                                               #  
#                                                                               #
#                    [ P Y T H O N W E B A U D   I T O R ]                      #
#                       powred by ==>  venomvictim v.1                          #
#                            [XSS] [SQLi] [CRAWL]                               #
#                         [HEADERS] [DIRS] [REPORTS]                            #
# ==============================================================================# 
#                       LEGAL DISCLAIMER: FOR AUTHORIZED                        #
#                       please EDUCATIONAL TESTING ONLY.                        # 
# ==============================================================================#
import requests
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

class WebScanner:
    def __init__(self, target_url, wordlist=None):
        self.target_url = target_url
        self.target_links = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security-Audit-Tool)"})
        # Wordlist for directory brute-forcing
        self.wordlist = wordlist or ["admin", "login", "config", ".git", "backup", "db", "phpinfo"]
        # Vulnerability Findings
        self.vulnerabilities = []
    # --- CRAWLER ENGINE ---
    def crawl(self, url=None):
        """Discovers all internal links on the website."""
        if url is None:
            url = self.target_url
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.content, "html.parser")
            for link in soup.find_all("a"):
                path = link.get("href")
                if path:
                    full_url = urljoin(url, path)
                    # Stay within the target domain
                    if urlparse(self.target_url).netloc == urlparse(full_url).netloc:
                        if full_url not in self.target_links:
                            self.target_links.add(full_url)
                            self.crawl(full_url)
        except Exception as e:
            pass
    # --- VULNERABILITY MODULES ---
    def check_headers(self, url):
        """Checks for missing security headers."""
        headers = self.session.get(url).headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        for header in security_headers:
            if header not in headers:
                self.report(url, "Missing Security Header", f"Header '{header}' is not implemented.", "Medium")
    def test_xss(self, url):
        """Tests for Reflected XSS in URL parameters."""
        xss_payload = "<script>alert('XSS')</script>"
        if "?" in url:
            test_url = url.replace("=", f"={xss_payload}")
            res = self.session.get(test_url)
            if xss_payload in res.text:
                self.report(url, "Reflected XSS", f"Payload reflected in: {test_url}", "High")
    def test_sqli(self, url):
        """Tests for basic Error-based SQL Injection."""
        sqli_payload = "'"
        db_errors = ["sql syntax", "mysql_fetch", "native client", "ora-01756", "sqlite3.OperationalError", "PostgreSQL query failed"]
        if "?" in url:
            test_url = url.replace("=", f"={sqli_payload}")
            res = self.session.get(test_url)
            for error in db_errors:
                if error.lower() in res.text.lower():
                    self.report(url, "Potential SQL Injection", f"Found DB error trigger: {error}", "High")
    def brute_force_directories(self):
        """Checks for sensitive files using common naming patterns."""
        for path in self.wordlist:
            url = urljoin(self.target_url, path)
            try:
                res = self.session.get(url, timeout=3)
                if res.status_code == 200:
                    self.report(url, "Sensitive File/Directory Exposed", f"Accessible: {url}", "Medium")
            except:
                pass

    # --- UTILITIES ---
    def report(self, url, vuln_type, evidence, severity):
        """Stores findings for the final report."""
        finding = {"URL": url, "Type": vuln_type, "Evidence": evidence, "Severity": severity}
        self.vulnerabilities.append(finding)
        print(f"[!] {severity}: {vuln_type} found at {url}")
    def run(self):
        print(f"[*] Starting Scan: {self.target_url}\n" + "-"*50)
        print("[*] Phase 1: Checking Root Security Headers...")
        self.check_headers(self.target_url)
        print("[*] Phase 2: Brute-forcing Sensitive Directories...")
        self.brute_force_directories()
        print("[*] Phase 3: Crawling Site for Links & Parameters...")
        self.target_links.add(self.target_url)
        self.crawl()
        print(f"[+] Discovered {len(self.target_links)} internal links.")
        print("[*] Phase 4: Auditing Parameters for XSS & SQLi...")
        for link in self.target_links:
            self.test_xss(link)
            self.test_sqli(link)
        self.print_summary()

    def print_summary(self):
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        if not self.vulnerabilities:
            print("No vulnerabilities found.")
        else:
            for v in self.vulnerabilities:
                print(f"[{v['Severity']}] {v['Type']}\n URL: {v['URL']}\n Evidence: {v['Evidence']}\n")
        print("="*50)

if __name__ == "__main__":
    # Example Target: Use a site you have permission for!
    target = input("Enter the full URL (including http/https): ").strip()
    if target:
        scanner = WebScanner(target)
        scanner.run()

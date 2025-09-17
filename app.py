import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import urllib.parse
import datetime
import socket
import ssl

class URLSuspiciousnessChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("URL Suspiciousness Checker")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('Title.TLabel', background='#f0f0f0', font=('Arial', 16, 'bold'))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Checkbutton.TButton', background='#e1e1e1')
        self.style.configure('Risk.TLabel', font=('Arial', 12, 'bold'))
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="URL Suspiciousness Checker", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # URL input frame
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(input_frame, text="Enter URL to analyze:").pack(anchor=tk.W)
        
        url_frame = ttk.Frame(input_frame)
        url_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(url_frame, textvariable=self.url_var, font=('Arial', 11))
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        analyze_btn = ttk.Button(url_frame, text="Analyze", command=self.analyze_url)
        analyze_btn.pack(side=tk.RIGHT)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding=15)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Risk indicator
        risk_frame = ttk.Frame(results_frame)
        risk_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(risk_frame, text="Overall Risk:").pack(side=tk.LEFT)
        
        self.risk_label = ttk.Label(risk_frame, text="Not analyzed", style='Risk.TLabel')
        self.risk_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Results notebook
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Basic info tab
        basic_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(basic_frame, text="Basic Information")
        
        self.basic_text = scrolledtext.ScrolledText(basic_frame, wrap=tk.WORD, height=10, font=('Consolas', 9))
        self.basic_text.pack(fill=tk.BOTH, expand=True)
        
        # Domain info tab
        domain_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(domain_frame, text="Domain Information")
        
        self.domain_text = scrolledtext.ScrolledText(domain_frame, wrap=tk.WORD, height=10, font=('Consolas', 9))
        self.domain_text.pack(fill=tk.BOTH, expand=True)
        
        # Security indicators tab
        security_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(security_frame, text="Security Indicators")
        
        self.security_text = scrolledtext.ScrolledText(security_frame, wrap=tk.WORD, height=10, font=('Consolas', 9))
        self.security_text.pack(fill=tk.BOTH, expand=True)
        
        # Set initial state
        self.basic_text.config(state=tk.DISABLED)
        self.domain_text.config(state=tk.DISABLED)
        self.security_text.config(state=tk.DISABLED)
        
        # Bind Enter key to analyze button
        url_entry.bind('<Return>', lambda event: self.analyze_url())
        
    def safe_insert(self, text_widget, text):
        """Safely insert text into a disabled text widget"""
        text_widget.config(state=tk.NORMAL)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)
        
    def extract_domain_components(self, domain):
        """Extract domain components without external libraries"""
        # Simple domain parsing
        parts = domain.split('.')
        if len(parts) >= 2:
            suffix = '.'.join(parts[-2:])
            domain_name = parts[-2]
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            return subdomain, domain_name, suffix
        return '', domain, ''
    
    def analyze_url(self):
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL to analyze")
            return
            
        # Add http:// if no scheme is provided
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            # Clear previous results
            for text_widget in [self.basic_text, self.domain_text, self.security_text]:
                text_widget.config(state=tk.NORMAL)
                text_widget.delete(1.0, tk.END)
            
            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            # Basic URL analysis
            self.safe_insert(self.basic_text, f"URL: {url}\n")
            self.safe_insert(self.basic_text, f"Domain: {domain}\n")
            self.safe_insert(self.basic_text, f"Scheme: {parsed_url.scheme}\n")
            self.safe_insert(self.basic_text, f"Path: {parsed_url.path}\n")
            
            if parsed_url.query:
                self.safe_insert(self.basic_text, f"Query: {parsed_url.query}\n")
            
            # Check URL length
            url_length = len(url)
            self.safe_insert(self.basic_text, f"\nURL Length: {url_length} characters\n")
            
            if url_length > 75:
                self.safe_insert(self.security_text, "⚠️ Long URL (potential phishing attempt)\n")
            
            # Check for IP address in URL
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            if re.search(ip_pattern, domain):
                self.safe_insert(self.security_text, "⚠️ IP address used instead of domain name\n")
            
            # Check for suspicious characters
            suspicious_chars = ['@', '//']
            for char in suspicious_chars:
                if char in url:
                    self.safe_insert(self.security_text, f"⚠️ Suspicious character '{char}' in URL\n")
            
            # Check for multiple subdomains
            subdomain_count = domain.count('.')
            if subdomain_count > 2:
                self.safe_insert(self.security_text, f"⚠️ Multiple subdomains ({subdomain_count} dots)\n")
            
            # Extract domain components
            subdomain, domain_name, suffix = self.extract_domain_components(domain)
            self.safe_insert(self.domain_text, f"Subdomain: {subdomain}\n")
            self.safe_insert(self.domain_text, f"Domain: {domain_name}\n")
            self.safe_insert(self.domain_text, f"Suffix: {suffix}\n")
            
            # Check HTTPS
            if parsed_url.scheme == 'https':
                self.safe_insert(self.security_text, "✅ Using HTTPS (secure connection)\n")
                
                # Try to get SSL certificate info
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check certificate expiration
                            if 'notAfter' in cert:
                                exp_date_str = cert['notAfter']
                                # Parse the date string (format: 'MMM DD HH:MM:SS YYYY GMT')
                                try:
                                    exp_date = datetime.datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                                    days_until_exp = (exp_date - datetime.datetime.now()).days
                                    self.safe_insert(self.security_text, f"✅ SSL Certificate valid for {days_until_exp} more days\n")
                                except ValueError:
                                    self.safe_insert(self.security_text, f"✅ SSL Certificate expiration: {exp_date_str}\n")
                            
                except Exception as e:
                    self.safe_insert(self.security_text, f"❌ SSL Certificate error: {str(e)}\n")
            else:
                self.safe_insert(self.security_text, "❌ Not using HTTPS (insecure connection)\n")
            
            # Check for URL shortening services
            shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly']
            for shortener in shorteners:
                if shortener in domain:
                    self.safe_insert(self.security_text, f"⚠️ URL shortening service detected: {shortener}\n")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.xyz', '.top', '.club', '.loan', '.download', '.gq', '.ml', '.cf', '.tk']
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    self.safe_insert(self.security_text, f"⚠️ Suspicious TLD detected: {tld}\n")
            
            # Check for excessive special characters
            special_chars = re.findall(r'[^a-zA-Z0-9.-]', domain)
            if len(special_chars) > 3:
                self.safe_insert(self.security_text, f"⚠️ Excessive special characters in domain: {len(special_chars)}\n")
            
            # Calculate risk score based on findings
            risk_score = 0
            risk_factors = []
            
            if url_length > 75:
                risk_score += 1
                risk_factors.append("Long URL")
                
            if re.search(ip_pattern, domain):
                risk_score += 2
                risk_factors.append("IP address in domain")
                
            if subdomain_count > 2:
                risk_score += 1
                risk_factors.append("Multiple subdomains")
                
            if parsed_url.scheme != 'https':
                risk_score += 2
                risk_factors.append("No HTTPS")
                
            # Check for URL shorteners
            for shortener in shorteners:
                if shortener in domain:
                    risk_score += 1
                    risk_factors.append(f"URL shortener: {shortener}")
                    break
                    
            # Check for suspicious TLDs
            for tld in suspicious_tlds:
                if domain.endswith(tld):
                    risk_score += 1
                    risk_factors.append(f"Suspicious TLD: {tld}")
                    break
                    
            # Check for excessive special characters
            if len(special_chars) > 3:
                risk_score += 1
                risk_factors.append("Excessive special characters")
            
            # Determine risk level
            if risk_score == 0:
                risk_level = "Low Risk"
                color = "green"
            elif risk_score <= 2:
                risk_level = "Moderate Risk"
                color = "orange"
            elif risk_score <= 4:
                risk_level = "High Risk"
                color = "red"
            else:
                risk_level = "Very High Risk"
                color = "darkred"
                
            self.risk_label.config(text=risk_level, foreground=color)
            
            # Display risk factors
            if risk_factors:
                self.safe_insert(self.security_text, f"\nRisk Factors Detected ({risk_score}):\n")
                for factor in risk_factors:
                    self.safe_insert(self.security_text, f"• {factor}\n")
            
            # Add general security advice
            self.safe_insert(self.security_text, f"\nSecurity Advice:\n")
            if risk_score > 0:
                self.safe_insert(self.security_text, "• Be cautious when visiting this website\n")
                self.safe_insert(self.security_text, "• Don't enter personal information\n")
                self.safe_insert(self.security_text, "• Verify the website through other sources\n")
            else:
                self.safe_insert(self.security_text, "• No obvious red flags detected\n")
                self.safe_insert(self.security_text, "• Still exercise normal caution online\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze URL: {str(e)}")

def main():
    root = tk.Tk()
    app = URLSuspiciousnessChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()
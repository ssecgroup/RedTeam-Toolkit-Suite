import argparse
import json
import os
import re
import socket
import ssl
from datetime import datetime
from OpenSSL import SSL
import requests
from bs4 import BeautifulSoup

class ComplianceScanner:
    def __init__(self, target, args):
        self.target = target
        self.args = args
        self.findings = []
        self.session = requests.Session()
        self.wordlist_path = "./wordlists"

    # Core Scanning Methods
    def perform_scan(self):
        if self.args.gdpr:
            self.check_gdpr_compliance()
        if self.args.hipaa:
            self.check_hipaa_compliance()
        if self.args.pci:
            self.check_pci_dss_compliance()
        if self.args.ccpa:
            self.check_ccpa_compliance()
        if self.args.dsar:
            self.test_dsar_implementation()
        self.check_encryption_standards()

    # GDPR Implementation
    def check_gdpr_compliance(self):
        # ... (previous GDPR implementation)
        # Added Data Portability Check
        if not self.find_data_portability(response.text):
            self.log_finding("GDPR", "Missing data portability mechanism", "Medium")

    def find_data_portability(self, html):
        return bool(re.search(r'export data|download your data', html, re.I))

    # HIPAA Enhancements
    def check_hipaa_compliance(self):
        # ... (previous HIPAA checks)
        # Add Backup Integrity Check
        if not self.check_backup_headers():
            self.log_finding("HIPAA", "Missing backup integrity verification", "High")

    def check_backup_headers(self):
        response = self.session.head(urljoin(self.target, "/backups"))
        return 'X-Backup-Integrity' in response.headers

    # PCI-DSS Implementation
    def check_pci_dss_compliance(self):
        self.check_tls_version()  # TLS 1.2+ required
        self.check_cvv_handling()
        self.check_credit_card_leakage()

    def check_cvv_handling(self):
        response = self.session.get(urljoin(self.target, "/checkout"))
        if re.search(r'CVV|CVC', response.text) and not re.search(r'name="cvv" type="password"', response.text):
            self.log_finding("PCI-DSS", "CVV field not properly masked", "Critical")

    def check_credit_card_leakage(self):
        response = self.session.get(self.target)
        cc_pattern = r'\b(?:\d[ -]*?){13,16}\b'
        if re.search(cc_pattern, response.text):
            self.log_finding("PCI-DSS", "Potential credit card exposure", "Critical")

    # CCPA Implementation
    def check_ccpa_compliance(self):
        self.check_do_not_sell_link()
        self.verify_opt_out_mechanism()

    def check_do_not_sell_link(self):
        response = self.session.get(self.target)
        if not re.search(r'Do Not Sell My Personal Information', response.text, re.I):
            self.log_finding("CCPA", "Missing 'Do Not Sell' link", "High")

    def verify_opt_out_mechanism(self):
        opt_out_url = urljoin(self.target, "/opt-out")
        response = self.session.post(opt_out_url, data={"opt_out": "true"})
        if response.status_code != 200:
            self.log_finding("CCPA", "Opt-out mechanism not functional", "Critical")

    # DSAR Testing
    def test_dsar_implementation(self):
        dsar_endpoints = self.load_wordlist("dsar_paths.txt")
        for endpoint in dsar_endpoints:
            url = urljoin(self.target, endpoint)
            self.test_dsar_endpoint(url)

    def test_dsar_endpoint(self, url):
        try:
            # Test form submission
            response = self.session.post(url, data={
                "email": "test@example.com",
                "request_type": "data_access"
            })
            if "verification" not in response.text.lower():
                self.log_finding("DSAR", "Missing identity verification", "High")
        except Exception as e:
            self.log_finding("DSAR", f"DSAR endpoint unreachable: {url}", "High")

    # Encryption Detection
    def check_encryption_standards(self):
        self.check_tls_version()
        self.check_database_encryption()
        self.check_file_encryption()

    def check_database_encryption(self):
        response = self.session.get(urljoin(self.target, "/api/config"))
        if 'encryption' not in response.text.lower():
            self.log_finding("Encryption", "Database encryption not detected", "Medium")

    def check_file_encryption(self):
        response = self.session.get(urljoin(self.target, "/download/patient_data.zip"))
        if response.headers.get('Content-Encoding') != 'aes256':
            self.log_finding("Encryption", "File downloads unencrypted", "High")

    # Helper Methods
    def log_finding(self, regulation, issue, risk):
        self.findings.append({
            "timestamp": datetime.now().isoformat(),
            "regulation": regulation,
            "issue": issue,
            "risk": risk,
            "recommendation": self.generate_recommendation(regulation, issue)
        })

    def generate_recommendation(self, regulation, issue):
        recommendations = {
            "GDPR": "Implement proper consent management and data protection controls",
            "HIPAA": "Ensure PHI protection and access controls",
            "PCI-DSS": "Secure payment processing systems",
            "CCPA": "Provide consumer opt-out mechanisms",
            "DSAR": "Establish valid data subject request procedures"
        }
        return recommendations.get(regulation, "Consult compliance specialist")

    def generate_report(self):
        return {
            "target": self.target,
            "scan_date": datetime.now().isoformat(),
            "compliance_findings": self.findings
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Compliance Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--gdpr", action="store_true", help="Check GDPR compliance")
    parser.add_argument("--hipaa", action="store_true", help="Check HIPAA compliance")
    parser.add_argument("--pci", action="store_true", help="Check PCI-DSS compliance")
    parser.add_argument("--ccpa", action="store_true", help="Check CCPA compliance")
    parser.add_argument("--dsar", action="store_true", help="Test DSAR implementation")
    parser.add_argument("--encrypt", action="store_true", help="Check encryption standards")
    parser.add_argument("--consent", action="store_true", help="Legal consent flag")

    args = parser.parse_args()

    if not args.consent:
        print("Error: Compliance scanning requires explicit --consent")
        exit(1)

    scanner = ComplianceScanner(args.url, args)
    scanner.perform_scan()
    report = scanner.generate_report()

    with open("compliance_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"Scan complete. Findings: {len(report['compliance_findings']}")
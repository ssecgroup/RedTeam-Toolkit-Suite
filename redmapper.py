import argparse
import json
import os
import random
import re
import time
import jwt
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import Fore, Style

class RedMapper:
    def __init__(self, args):
        # ... (previous initialization code)
        self.xss_payloads = self.load_wordlist(args.xss_payloads, "xss")
        self.api_endpoints = self.load_wordlist(args.api_endpoints, "api")
        self.csrf_tokens = set()

    # ... (previous methods)

    def detect_jwt(self):
        """Check for JWT tokens in cookies/headers"""
        try:
            response = self.make_request(self.target)
            
            # Check cookies
            for cookie in response.cookies:
                if self.is_jwt(cookie.value):
                    self.analyze_jwt(cookie.value)
            
            # Check authorization headers
            auth_header = response.headers.get("Authorization", "")
            if "Bearer " in auth_header:
                token = auth_header.split("Bearer ")[1]
                if self.is_jwt(token):
                    self.analyze_jwt(token)
                    
        except Exception as e:
            self.log_error(f"JWT detection failed: {str(e)}")

    def is_jwt(self, token):
        return re.match(r'^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*$', token)

    def analyze_jwt(self, token):
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            findings = {
                "alg": decoded.get('alg'),
                "exp": decoded.get('exp'),
                "nbf": decoded.get('nbf')
            }
            
            vulns = []
            if decoded['alg'] in ['none', 'HS256']:
                vulns.append("Weak JWT algorithm")
            if not decoded.get('exp'):
                vulns.append("Missing expiration")
                
            if vulns:
                self.log_finding({
                    "type": "JWT",
                    "token": decoded,
                    "vulnerabilities": vulns
                })
                
        except Exception as e:
            self.log_error(f"JWT analysis failed: {str(e)}")

    def test_xss(self):
        """Test for reflected XSS vulnerabilities"""
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in self.xss_payloads:
                try:
                    test_params = {**params, param: [payload]}
                    response = self.make_request(self.target, params=test_params)
                    
                    if payload in response.text:
                        self.log_finding({
                            "type": "XSS",
                            "param": param,
                            "payload": payload,
                            "confidence": "Reflected"
                        })
                        
                except Exception as e:
                    self.log_error(f"XSS test failed: {str(e)}")

    def check_csrf(self):
        """Check for missing CSRF protections"""
        try:
            response = self.make_request(self.target)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                inputs = form.find_all('input')
                csrf_fields = [inp for inp in inputs if 
                              'csrf' in inp.get('name', '').lower() or
                              'token' in inp.get('name', '').lower()]
                
                if not csrf_fields:
                    self.log_finding({
                        "type": "CSRF",
                        "form": form.get('action'),
                        "risk": "No CSRF token found"
                    })
                else:
                    for field in csrf_fields:
                        self.analyze_csrf_token(field.get('value'))
                        
        except Exception as e:
            self.log_error(f"CSRF check failed: {str(e)}")

    def analyze_csrf_token(self, token):
        """Check token randomness using basic entropy analysis"""
        if len(token) < 16:
            self.log_finding({
                "type": "CSRF",
                "risk": f"Short token length ({len(token)} chars)"
            })
            
        if token in self.csrf_tokens:
            self.log_finding({
                "type": "CSRF", 
                "risk": "Token reuse detected"
            })
            
        self.csrf_tokens.add(token)

    def discover_api_endpoints(self):
        """Brute-force common API endpoints"""
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            for endpoint in self.api_endpoints:
                url = urljoin(self.target, endpoint)
                executor.submit(self.test_api_endpoint, url)

    def test_api_endpoint(self, url):
        """Test discovered API endpoints"""
        try:
            # Check CORS misconfigurations
            response = self.make_request(url, method="OPTIONS")
            if response.headers.get('Access-Control-Allow-Origin') == '*':
                self.log_finding({
                    "type": "API",
                    "endpoint": url,
                    "issue": "CORS misconfiguration (Allow-Origin: *)"
                })
            
            # Check authentication bypass
            auth_response = self.make_request(url)
            if auth_response.status_code == 200:
                self.log_finding({
                    "type": "API",
                    "endpoint": url,
                    "issue": "Unauthenticated access allowed"
                })
                
        except Exception as e:
            pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RedMapper Pro - Full OWASP Suite")
    # ... (previous arguments)
    parser.add_argument("--xss", action="store_true", help="Enable XSS testing")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF checks")
    parser.add_argument("--api", action="store_true", help="Discover API endpoints")
    parser.add_argument("--jwt", action="store_true", help="Detect JWT issues")
    parser.add_argument("--xss-payloads", help="Custom XSS payload list")
    parser.add_argument("--api-endpoints", help="Custom API endpoints list")
    
    args = parser.parse_args()
    
    scanner = RedMapper(args)
    
    try:
        scanner.check_security_headers()
        scanner.brute_subdomains()
        scanner.detect_sqli()
        
        if args.xss:
            scanner.test_xss()
        if args.csrf:
            scanner.check_csrf()
        if args.api:
            scanner.discover_api_endpoints()
        if args.jwt:
            scanner.detect_jwt()
            
        report = scanner.generate_report()
        
    except KeyboardInterrupt:
        scanner.generate_report()
import requests
import concurrent.futures
import socket
import json
import os
import sys
import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from tqdm import tqdm
import dns.resolver
import argparse

from configs.wordlists import ADMIN_PATHS, SUBDOMAINS

class TelegramAdminScanner:
    def __init__(self, target_domain, output_dir="output"):
        self.target_domain = target_domain
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.results = {
            "domain": self.target_domain,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "subdomains": [],
            "found_endpoints": [],
            "leaked_secrets": [],
            "errors": []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        })

    def resolve_subdomains(self):
        """Brute force common subdomains using DNS queries."""
        print(f"[*] Resolving subdomains for {self.target_domain}...")
        found_subs = []
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{self.target_domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception as e:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subs.append(result)
                    print(f"[+] Found subdomain: {result}")

        # Deduplicate and sort
        found_subs = sorted(list(set(found_subs)))
        self.results["subdomains"] = found_subs
        return found_subs

    def scan_url(self, url):
        """Scan a single URL for admin panels, secrets, and misconfigurations."""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=True, verify=False)
            status_code = response.status_code
            
            # Check for common admin indicators in status code and content
            is_admin = False
            indicators = []
            
            if status_code == 200:
                content = response.text
                
                # Check for admin keywords in content
                admin_keywords = ['admin', 'dashboard', 'login', 'sign in', 'password', 'api key', 'token', 'secret', 'config', 'debug', 'internal', 'private', 'backend', 'console', 'panel', 'staff', 'manage']
                for keyword in admin_keywords:
                    if keyword.lower() in content.lower():
                        indicators.append(keyword)
                
                # Check for specific file leaks
                if '.env' in url or url.endswith('.env'):
                    indicators.append('env_file')
                if '.git' in url:
                    indicators.append('git_leak')
                if 'swagger' in url or 'openapi' in url:
                    indicators.append('api_docs')
                
                if indicators:
                    is_admin = True
            
            # Check for redirects to admin
            if response.history:
                for r in response.history:
                    if 'admin' in r.url.lower() or 'login' in r.url.lower():
                        is_admin = True
                        indicators.append(f'redirect_to_{r.url}')

            if is_admin:
                self.results["found_endpoints"].append({
                    "url": url,
                    "status": status_code,
                    "indicators": indicators,
                    "final_url": response.url
                })
                print(f"[ADMIN] {url} (Status: {status_code}, Indicators: {indicators})")
                
        except requests.exceptions.RequestException as e:
            self.results["errors"].append(f"{url}: {str(e)}")
        except Exception as e:
            self.results["errors"].append(f"{url}: {str(e)}")

    def scan_base_domains(self):
        """Scan the main domain and subdomains for admin paths."""

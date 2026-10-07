#!/usr/bin/env python3
import sys
import dns.resolver
from datetime import datetime
from colorama import init, Fore, Style
import time

init(autoreset=True)

class DNSAuditor:
    def __init__(self, domain, verbose=False):
        self.domain = domain.rstrip(".")
        self.verbose = verbose
        self.results = {}
        self.score = 0
    
    def run_audit(self):
        print(f"\n{Fore.CYAN}{"="*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}DNS SECURITY AUDIT - {Fore.YELLOW}{self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{"="*60}{Style.RESET_ALL}\n")
        self.check_dnssec()
        self.check_spf()
        self.check_dmarc()
        self.check_nameservers()
        self.check_response_time()
        self.calculate_score()
        self.print_report()
    
    def check_dnssec(self):
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Checking DNSSEC...")
        try:
            # Use DNSSEC-validating resolvers
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            dnssec_found = False
            
            # Method 1: Try DS record (Delegation Signer) - more reliable
            try:
                answers = resolver.resolve(self.domain, "DS")
                if len(answers) > 0:
                    dnssec_found = True
            except:
                pass
            
            # Method 2: Try DNSKEY if DS not found
            if not dnssec_found:
                try:
                    answers = resolver.resolve(self.domain, "DNSKEY")
                    if len(answers) > 0:
                        dnssec_found = True
                except:
                    pass
            
            # Method 3: Check for RRSIG on A record (indicates DNSSEC)
            if not dnssec_found:
                try:
                    answers = resolver.resolve(self.domain, "A")
                    # Check if response has RRSIG
                    if answers.response and len(answers.response.rrset) > 0:
                        for rrset in answers.response.answer:
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                dnssec_found = True
                                break
                except:
                    pass
            
            if dnssec_found:
                self.results["dnssec"] = {"status": "pass", "message": "DNSSEC enabled"}
                self.score += 25
            else:
                self.results["dnssec"] = {"status": "fail", "message": "DNSSEC not enabled"}
        except Exception as e:
            self.results["dnssec"] = {"status": "warning", "message": f"Check failed: {str(e)[:40]}"}
    
    def check_spf(self):
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Checking SPF record...")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 5
            try:
                answers = resolver.resolve(self.domain, "TXT")
                spf_found = False
                for rdata in answers:
                    txt = str(rdata)
                    if "v=spf1" in txt:
                        spf_found = True
                        if "-all" in txt:
                            self.results["spf"] = {"status": "pass", "message": "SPF record (strict)"}
                            self.score += 15
                        elif "~all" in txt:
                            self.results["spf"] = {"status": "pass", "message": "SPF record (soft)"}
                            self.score += 10
                        else:
                            self.results["spf"] = {"status": "pass", "message": "SPF record (weak)"}
                            self.score += 5
                        break
                if not spf_found:
                    self.results["spf"] = {"status": "fail", "message": "No SPF record"}
            except dns.resolver.NoAnswer:
                self.results["spf"] = {"status": "fail", "message": "No SPF record"}
        except Exception as e:
            self.results["spf"] = {"status": "warning", "message": str(e)[:50]}
    
    def check_dmarc(self):
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Checking DMARC record...")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 5
            try:
                dmarc_domain = f"_dmarc.{self.domain}"
                answers = resolver.resolve(dmarc_domain, "TXT")
                dmarc_found = False
                for rdata in answers:
                    txt = str(rdata)
                    if "v=DMARC1" in txt:
                        dmarc_found = True
                        if "p=reject" in txt:
                            self.results["dmarc"] = {"status": "pass", "message": "DMARC (reject)"}
                            self.score += 15
                        elif "p=quarantine" in txt:
                            self.results["dmarc"] = {"status": "pass", "message": "DMARC (quarantine)"}
                            self.score += 10
                        else:
                            self.results["dmarc"] = {"status": "pass", "message": "DMARC (monitor)"}
                            self.score += 5
                        break
                if not dmarc_found:
                    self.results["dmarc"] = {"status": "fail", "message": "No DMARC record"}
            except dns.resolver.NoAnswer:
                self.results["dmarc"] = {"status": "fail", "message": "No DMARC record"}
            except dns.resolver.NXDOMAIN:
                self.results["dmarc"] = {"status": "fail", "message": "No DMARC record"}
        except Exception as e:
            self.results["dmarc"] = {"status": "warning", "message": str(e)[:50]}
    
    def check_nameservers(self):
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Checking nameservers...")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 5
            answers = resolver.resolve(self.domain, "NS")
            ns_count = len(answers)
            if ns_count >= 2:
                self.results["nameservers"] = {"status": "pass", "message": f"Good ({ns_count} servers)"}
                self.score += 15
            elif ns_count == 1:
                self.results["nameservers"] = {"status": "warning", "message": "Single nameserver"}
                self.score += 5
            else:
                self.results["nameservers"] = {"status": "fail", "message": "No nameservers"}
        except Exception as e:
            self.results["nameservers"] = {"status": "warning", "message": str(e)[:50]}
    
    def check_response_time(self):
        print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Measuring response time...")
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            resolver.timeout = 5
            start = time.time()
            resolver.resolve(self.domain, "A")
            end = time.time()
            ms = (end - start) * 1000
            if ms < 50:
                self.results["response_time"] = {"status": "pass", "message": f"Fast ({ms:.0f}ms)"}
                self.score += 15
            elif ms < 150:
                self.results["response_time"] = {"status": "pass", "message": f"Normal ({ms:.0f}ms)"}
                self.score += 10
            else:
                self.results["response_time"] = {"status": "warning", "message": f"Slow ({ms:.0f}ms)"}
                self.score += 5
        except Exception as e:
            self.results["response_time"] = {"status": "warning", "message": str(e)[:50]}
    
    def calculate_score(self):
        max_possible_score = 85  # 25 (DNSSEC) + 15 (SPF) + 15 (DMARC) + 15 (Nameservers) + 15 (Response Time)
        self.normalized_score = min(100, int((self.score / max_possible_score) * 100))
        if self.normalized_score >= 90:
            self.grade = "A"
        elif self.normalized_score >= 80:
            self.grade = "B"
        elif self.normalized_score >= 70:
            self.grade = "C"
        elif self.normalized_score >= 60:
            self.grade = "D"
        else:
            self.grade = "F"
    
    def print_report(self):
        print(f"\n{Fore.CYAN}{"="*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}| DNS SECURITY AUDIT REPORT{" "*31}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{"-"*58}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Style.RESET_ALL} Domain: {Fore.YELLOW}{self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Style.RESET_ALL} Time: {Fore.WHITE}{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{"="*60}{Style.RESET_ALL}\n")
        print(f"{Fore.WHITE}+{"-"*58}+{Style.RESET_ALL}")
        print(f"{Fore.WHITE}|{Style.RESET_ALL} SECURITY CHECKS")
        print(f"{Fore.WHITE}+{"-"*58}+{Style.RESET_ALL}")
        checks = [("dnssec", "DNSSEC"), ("spf", "SPF"), ("dmarc", "DMARC"), ("nameservers", "Nameservers"), ("response_time", "Response Time")]
        for key, name in checks:
            if key in self.results:
                r = self.results[key]
                icon = "[OK]" if r["status"] == "pass" else "[!]" if r["status"] == "warning" else "[X]"
                color = Fore.GREEN if r["status"] == "pass" else Fore.YELLOW if r["status"] == "warning" else Fore.RED
                print(f"{Fore.WHITE}|{Style.RESET_ALL} {icon} {name}: {color}{r["message"]}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}+{"-"*58}+{Style.RESET_ALL}")
        grade_color = Fore.GREEN if self.grade == "A" else Fore.CYAN if self.grade == "B" else Fore.YELLOW if self.grade == "C" else Fore.RED
        print(f"{Fore.WHITE}|{Style.RESET_ALL} SCORE: {grade_color}{self.normalized_score}/100 (Grade: {self.grade}){Style.RESET_ALL}")
        print(f"{Fore.WHITE}+{"-"*58}+{Style.RESET_ALL}\n")

def main():
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python dns_audit.py <domain>{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Example: python dns_audit.py google.com{Style.RESET_ALL}")
        sys.exit(1)
    domain = sys.argv[1]
    verbose = "-v" in sys.argv
    try:
        auditor = DNSAuditor(domain, verbose)
        auditor.run_audit()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Cancelled{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

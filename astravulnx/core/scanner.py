"""
Core Scanner for AstraVulnX v3.0.0
Author: Meheraz Hosen Siam
"""

import time
import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import re

from astravulnx.core.config import Config


@dataclass
class VulnerabilityFinding:
    """Single vulnerability finding"""
    module: str
    vulnerability_type: str
    url: str
    parameter: str = ""
    payload: str = ""
    method: str = "GET"
    severity: str = "Medium"
    cvss_score: float = 5.0
    confidence: float = 0.8
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    owasp: str = ""
    cwe: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    start_time: str
    end_time: str = ""
    duration: float = 0.0
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": f"{self.duration:.2f}s",
            "total_findings": len(self.findings),
            "statistics": self.statistics,
            "findings": [
                {
                    "module": f.module,
                    "vulnerability_type": f.vulnerability_type,
                    "url": f.url,
                    "parameter": f.parameter,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "evidence": f.evidence[:200] if f.evidence else "",
                    "owasp": f.owasp,
                    "cwe": f.cwe
                }
                for f in self.findings
            ]
        }


class Scanner:
    """
    Main Scanner Class for AstraVulnX v3.0.0
    
    Author: Meheraz Hosen Siam
    Role: Penetration Testing Learner
    """
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.findings: List[VulnerabilityFinding] = []
        self.visited_urls: set = set()
        self.forms: List[Dict] = []
        self.parameters: Dict[str, List[str]] = {}
        
    async def scan(self, target_url: str) -> ScanResult:
        """
        Perform vulnerability scan on target URL.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            ScanResult object with all findings
        """
        start_time = datetime.now()
        self.config.target_url = target_url
        
        result = ScanResult(
            target=target_url,
            start_time=start_time.isoformat()
        )
        
        print(f"\n{'='*60}")
        print(f"  AstraVulnX v3.0.0 - Web Vulnerability Scanner")
        print(f"  Author: Meheraz Hosen Siam")
        print(f"{'='*60}")
        print(f"\n  Target: {target_url}")
        print(f"  Profile: {self.config.scan_profile}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{'='*60}")
        
        try:
            # Phase 1: Initial reconnaissance
            print("\n[Phase 1] Reconnaissance...")
            await self._reconnaissance(target_url)
            
            # Phase 2: Security Headers Check
            print("[Phase 2] Security Headers Analysis...")
            await self._check_security_headers(target_url)
            
            # Phase 3: Vulnerability Detection
            print("[Phase 3] Vulnerability Detection...")
            await self._detect_vulnerabilities(target_url)
            
        except Exception as e:
            print(f"  [!] Error during scan: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result.end_time = end_time.isoformat()
        result.duration = duration
        result.findings = self.findings
        result.statistics = self._calculate_statistics()
        
        # Print summary
        self._print_summary(result)
        
        return result
    
    async def _reconnaissance(self, url: str):
        """Perform initial reconnaissance"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    timeout=self.config.timeout,
                    headers={"User-Agent": self.config.user_agent}
                ) as response:
                    self.visited_urls.add(url)
                    
                    # Extract forms and parameters
                    if response.status == 200:
                        html = await response.text()
                        self._extract_forms(html, url)
                        self._extract_parameters(html, url)
                        
                        print(f"  [*] Status: {response.status}")
                        print(f"  [*] Forms found: {len(self.forms)}")
                        print(f"  [*] Parameters found: {sum(len(p) for p in self.parameters.values())}")
                        
        except Exception as e:
            print(f"  [!] Reconnaissance error: {e}")
    
    def _extract_forms(self, html: str, base_url: str):
        """Extract forms from HTML"""
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(1)
            inputs = input_pattern.findall(form_html)
            if inputs:
                self.forms.append({
                    "url": base_url,
                    "inputs": inputs
                })
    
    def _extract_parameters(self, html: str, base_url: str):
        """Extract URL parameters"""
        param_pattern = re.compile(r'[?&]([a-zA-Z0-9_]+)=', re.IGNORECASE)
        params = param_pattern.findall(html)
        if params:
            self.parameters[base_url] = params
    
    async def _check_security_headers(self, url: str):
        """Check for missing security headers"""
        security_headers = {
            "X-Frame-Options": {"severity": "Medium", "owasp": "A05 - Security Misconfiguration", "cwe": "CWE-1021"},
            "Content-Security-Policy": {"severity": "Medium", "owasp": "A05 - Security Misconfiguration", "cwe": "CWE-1021"},
            "Strict-Transport-Security": {"severity": "Medium", "owasp": "A02 - Cryptographic Failures", "cwe": "CWE-319"},
            "X-Content-Type-Options": {"severity": "Low", "owasp": "A05 - Security Misconfiguration", "cwe": "CWE-693"},
            "X-XSS-Protection": {"severity": "Low", "owasp": "A03 - Injection", "cwe": "CWE-79"},
            "Referrer-Policy": {"severity": "Low", "owasp": "A01 - Broken Access Control", "cwe": "CWE-200"},
            "Permissions-Policy": {"severity": "Low", "owasp": "A05 - Security Misconfiguration", "cwe": "CWE-693"},
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    timeout=self.config.timeout,
                    headers={"User-Agent": self.config.user_agent}
                ) as response:
                    headers = dict(response.headers)
                    
                    for header, info in security_headers.items():
                        if header not in headers:
                            finding = VulnerabilityFinding(
                                module="security_headers",
                                vulnerability_type=f"Missing {header}",
                                url=url,
                                severity=info["severity"],
                                cvss_score=4.0 if info["severity"] == "Medium" else 3.0,
                                evidence=f"Header not present in response",
                                description=f"Security header {header} is missing",
                                owasp=info["owasp"],
                                cwe=info["cwe"]
                            )
                            self.findings.append(finding)
                            print(f"  [!] Missing: {header}")
                            
        except Exception as e:
            print(f"  [!] Header check error: {e}")
    
    async def _detect_vulnerabilities(self, url: str):
        """Run vulnerability detection modules"""
        
        # SQL Injection tests
        if "sql_injection" in self.config.enabled_modules:
            await self._test_sqli(url)
        
        # XSS tests
        if "xss" in self.config.enabled_modules:
            await self._test_xss(url)
        
        # Open Redirect tests
        if "open_redirect" in self.config.enabled_modules:
            await self._test_open_redirect(url)
        
        # Sensitive Data tests
        if "sensitive_data" in self.config.enabled_modules:
            await self._test_sensitive_data(url)
        
        # CORS tests
        if "cors" in self.config.enabled_modules:
            await self._test_cors(url)
        
        # Clickjacking tests
        if "clickjacking" in self.config.enabled_modules:
            self._test_clickjacking(url)
    
    async def _test_sqli(self, url: str):
        """Test for SQL Injection"""
        payloads = [
            "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
            "1' AND 1=1--", "1' AND 1=2--", "' AND SLEEP(1)--"
        ]
        
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
            r"ORA-\d{4,}", r"Microsoft OLE DB", r"sqlite3\.OperationalError",
            r"Unclosed quotation", r"Incorrect syntax near"
        ]
        
        print(f"  [*] Testing SQL Injection...")
        
        # Test URL parameters
        if '?' in url:
            base_url, query = url.split('?', 1)
            params = query.split('&')
            
            for param in params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    for payload in payloads[:3]:  # Limit payloads for quick scan
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    test_url,
                                    timeout=self.config.timeout,
                                    headers={"User-Agent": self.config.user_agent}
                                ) as response:
                                    html = await response.text()
                                    
                                    for pattern in error_patterns:
                                        if re.search(pattern, html, re.IGNORECASE):
                                            finding = VulnerabilityFinding(
                                                module="sql_injection",
                                                vulnerability_type="SQL Injection",
                                                url=test_url,
                                                parameter=param_name,
                                                payload=payload,
                                                severity="Critical",
                                                cvss_score=9.8,
                                                confidence=0.9,
                                                evidence=f"SQL error pattern detected",
                                                description="SQL injection vulnerability detected",
                                                owasp="A03 - Injection",
                                                cwe="CWE-89"
                                            )
                                            self.findings.append(finding)
                                            print(f"  [!!!] SQL Injection found: {param_name}")
                                            break
                                            
                        except Exception:
                            pass
    
    async def _test_xss(self, url: str):
        """Test for Cross-Site Scripting"""
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)"
        ]
        
        print(f"  [*] Testing XSS...")
        
        if '?' in url:
            base_url, query = url.split('?', 1)
            params = query.split('&')
            
            for param in params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    for payload in payloads[:2]:  # Limit payloads
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    test_url,
                                    timeout=self.config.timeout,
                                    headers={"User-Agent": self.config.user_agent}
                                ) as response:
                                    html = await response.text()
                                    
                                    if payload in html:
                                        finding = VulnerabilityFinding(
                                            module="xss",
                                            vulnerability_type="Cross-Site Scripting",
                                            url=test_url,
                                            parameter=param_name,
                                            payload=payload,
                                            severity="High",
                                            cvss_score=6.1,
                                            confidence=0.85,
                                            evidence="Payload reflected in response",
                                            description="XSS vulnerability detected",
                                            owasp="A03 - Injection",
                                            cwe="CWE-79"
                                        )
                                        self.findings.append(finding)
                                        print(f"  [!!] XSS found: {param_name}")
                                        break
                                        
                        except Exception:
                            pass
    
    async def _test_open_redirect(self, url: str):
        """Test for Open Redirect"""
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'rurl']
        payloads = ['//evil.com', 'https://evil.com', '//attacker.com']
        
        print(f"  [*] Testing Open Redirect...")
        
        for param in redirect_params:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=self.config.timeout,
                            headers={"User-Agent": self.config.user_agent},
                            allow_redirects=False
                        ) as response:
                            location = response.headers.get('Location', '')
                            if 'evil.com' in location or 'attacker.com' in location:
                                finding = VulnerabilityFinding(
                                    module="open_redirect",
                                    vulnerability_type="Open Redirect",
                                    url=test_url,
                                    parameter=param,
                                    payload=payload,
                                    severity="Medium",
                                    cvss_score=6.1,
                                    confidence=0.8,
                                    evidence=f"Redirects to: {location}",
                                    description="Open redirect vulnerability",
                                    owasp="A01 - Broken Access Control",
                                    cwe="CWE-601"
                                )
                                self.findings.append(finding)
                                print(f"  [!] Open Redirect found: {param}")
                                break
                                
                except Exception:
                    pass
    
    async def _test_sensitive_data(self, url: str):
        """Test for sensitive data exposure"""
        patterns = {
            "API Key": r'(AIza[0-9A-Za-z\-_]{35}|sk_live_[0-9a-zA-Z]{24}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16})',
            "Private Key": r'-----BEGIN.*PRIVATE KEY-----',
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "AWS Key": r'AKIA[0-9A-Z]{16}',
            "Password": r'password\s*[=:]\s*["\']?[^\s"\'>]+',
        }
        
        print(f"  [*] Testing Sensitive Data Exposure...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=self.config.timeout,
                    headers={"User-Agent": self.config.user_agent}
                ) as response:
                    html = await response.text()
                    
                    for name, pattern in patterns.items():
                        matches = re.findall(pattern, html)
                        if matches:
                            finding = VulnerabilityFinding(
                                module="sensitive_data",
                                vulnerability_type=f"Sensitive Data: {name}",
                                url=url,
                                severity="High",
                                cvss_score=7.5,
                                confidence=0.7,
                                evidence=f"Found {len(matches)} potential {name}(s)",
                                description=f"Potential {name} exposure",
                                owasp="A02 - Cryptographic Failures",
                                cwe="CWE-200"
                            )
                            self.findings.append(finding)
                            print(f"  [!] Sensitive data found: {name}")
                            
        except Exception:
            pass
    
    async def _test_cors(self, url: str):
        """Test for CORS misconfiguration"""
        print(f"  [*] Testing CORS...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.options(
                    url,
                    timeout=self.config.timeout,
                    headers={
                        "User-Agent": self.config.user_agent,
                        "Origin": "https://evil.com",
                        "Access-Control-Request-Method": "GET"
                    }
                ) as response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if acao == '*' or acao == 'https://evil.com':
                        finding = VulnerabilityFinding(
                            module="cors",
                            vulnerability_type="CORS Misconfiguration",
                            url=url,
                            severity="Medium",
                            cvss_score=6.5,
                            confidence=0.85,
                            evidence=f"ACAO: {acao}, Credentials: {allow_credentials}",
                            description="CORS misconfiguration detected",
                            owasp="A05 - Security Misconfiguration",
                            cwe="CWE-942"
                        )
                        self.findings.append(finding)
                        print(f"  [!] CORS misconfiguration found")
                        
        except Exception:
            pass
    
    def _test_clickjacking(self, url: str):
        """Check for clickjacking vulnerability (already done in headers)"""
        # This is checked in security headers
        pass
    
    def _calculate_statistics(self) -> Dict:
        """Calculate scan statistics"""
        severity_counts = {}
        module_counts = {}
        
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            module_counts[finding.module] = module_counts.get(finding.module, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "findings_by_severity": severity_counts,
            "findings_by_module": module_counts,
            "total_pages": len(self.visited_urls),
            "total_parameters": sum(len(p) for p in self.parameters.values()),
            "total_forms": len(self.forms)
        }
    
    def _print_summary(self, result: ScanResult):
        """Print scan summary"""
        print(f"\n{'='*60}")
        print("  SCAN COMPLETED")
        print(f"{'='*60}")
        print(f"\n  Target: {result.target}")
        print(f"  Duration: {result.duration:.2f} seconds")
        print(f"  Total Findings: {len(result.findings)}")
        
        stats = result.statistics
        if stats.get("findings_by_severity"):
            print(f"\n  Findings by Severity:")
            for sev, count in stats["findings_by_severity"].items():
                print(f"    - {sev}: {count}")
        
        if stats.get("findings_by_module"):
            print(f"\n  Findings by Module:")
            for mod, count in stats["findings_by_module"].items():
                print(f"    - {mod}: {count}")
        
        print(f"\n{'='*60}")
        print("  Author: Meheraz Hosen Siam | AstraVulnX v3.0.0")
        print(f"{'='*60}\n")

"""
Core Scanner for AstraVulnX v3.0.0
Author: Meheraz Hosen Siam
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
"""

import time
import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import re
import os

from astravulnx.core.config import Config


@dataclass
class VulnerabilityFinding:
    """
    Single vulnerability finding.
    
    Author: Meheraz Hosen Siam
    """
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
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "module": self.module,
            "vulnerability_type": self.vulnerability_type,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "confidence": self.confidence,
            "evidence": self.evidence[:200] if self.evidence else "",
            "owasp": self.owasp,
            "cwe": self.cwe,
            "timestamp": self.timestamp
        }


@dataclass
class ScanResult:
    """
    Complete scan result.
    
    Author: Meheraz Hosen Siam
    """
    target: str
    start_time: str
    end_time: str = ""
    duration: float = 0.0
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "scanner": "AstraVulnX v3.0.0",
            "author": "Meheraz Hosen Siam",
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": f"{self.duration:.2f}s",
            "total_findings": len(self.findings),
            "statistics": self.statistics,
            "findings": [f.to_dict() for f in self.findings]
        }
    
    def save_json(self, filepath: str):
        """Save results to JSON file"""
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


class Scanner:
    """
    Main Scanner Class for AstraVulnX v3.0.0
    
    Author: Meheraz Hosen Siam
    Role: Penetration Testing Learner
    Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
    """
    
    VERSION = "3.0.0"
    AUTHOR = "Meheraz Hosen Siam"
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.findings: List[VulnerabilityFinding] = []
        self.visited_urls: set = set()
        self.forms: List[Dict] = []
        self.parameters: Dict[str, List[str]] = {}
        self.response_cache: Dict[str, str] = {}
        
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
        
        self._print_banner(target_url, start_time)
        
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
            
            # Phase 4: Generate Report
            print("[Phase 4] Generating Report...")
            
        except Exception as e:
            print(f"  [!] Error during scan: {e}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        result.end_time = end_time.isoformat()
        result.duration = duration
        result.findings = self.findings
        result.statistics = self._calculate_statistics()
        
        self._print_summary(result)
        
        return result
    
    def _print_banner(self, target_url: str, start_time: datetime):
        """Print scan banner"""
        print(f"\n{'='*60}")
        print(f"  AstraVulnX v{self.VERSION} - Web Vulnerability Scanner")
        print(f"  Author: {self.AUTHOR}")
        print(f"{'='*60}")
        print(f"\n  Target: {target_url}")
        print(f"  Profile: {self.config.scan_profile}")
        print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{'='*60}")
    
    async def _reconnaissance(self, url: str):
        """Perform initial reconnaissance"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, 
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    headers=self.config.headers
                ) as response:
                    self.visited_urls.add(url)
                    
                    if response.status == 200:
                        html = await response.text()
                        self.response_cache[url] = html
                        self._extract_forms(html, url)
                        self._extract_parameters(html, url)
                        
                        print(f"  [*] Status: {response.status}")
                        print(f"  [*] Forms found: {len(self.forms)}")
                        print(f"  [*] Parameters found: {sum(len(p) for p in self.parameters.values())}")
                        print(f"  [*] Response size: {len(html)} bytes")
                        
        except Exception as e:
            print(f"  [!] Reconnaissance error: {e}")
    
    def _extract_forms(self, html: str, base_url: str):
        """Extract forms from HTML"""
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.IGNORECASE)
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(1)
            inputs = input_pattern.findall(form_html)
            action = action_pattern.findall(match.group(0))
            
            if inputs:
                self.forms.append({
                    "url": base_url,
                    "action": action[0] if action else base_url,
                    "inputs": inputs
                })
    
    def _extract_parameters(self, html: str, base_url: str):
        """Extract URL parameters"""
        param_pattern = re.compile(r'[?&]([a-zA-Z0-9_]+)=', re.IGNORECASE)
        params = param_pattern.findall(html)
        if params:
            self.parameters[base_url] = list(set(params))
    
    async def _check_security_headers(self, url: str):
        """Check for missing security headers"""
        security_headers = {
            "X-Frame-Options": {
                "severity": "Medium", 
                "owasp": "A05 - Security Misconfiguration", 
                "cwe": "CWE-1021",
                "description": "Missing X-Frame-Options header allows clickjacking attacks"
            },
            "Content-Security-Policy": {
                "severity": "Medium", 
                "owasp": "A05 - Security Misconfiguration", 
                "cwe": "CWE-1021",
                "description": "Missing CSP header increases XSS risk"
            },
            "Strict-Transport-Security": {
                "severity": "Medium", 
                "owasp": "A02 - Cryptographic Failures", 
                "cwe": "CWE-319",
                "description": "Missing HSTS header allows downgrade attacks"
            },
            "X-Content-Type-Options": {
                "severity": "Low", 
                "owasp": "A05 - Security Misconfiguration", 
                "cwe": "CWE-693",
                "description": "Missing X-Content-Type-Options allows MIME sniffing"
            },
            "X-XSS-Protection": {
                "severity": "Low", 
                "owasp": "A03 - Injection", 
                "cwe": "CWE-79",
                "description": "Missing X-XSS-Protection header"
            },
            "Referrer-Policy": {
                "severity": "Low", 
                "owasp": "A01 - Broken Access Control", 
                "cwe": "CWE-200",
                "description": "Missing Referrer-Policy may leak sensitive URLs"
            },
            "Permissions-Policy": {
                "severity": "Low", 
                "owasp": "A05 - Security Misconfiguration", 
                "cwe": "CWE-693",
                "description": "Missing Permissions-Policy allows all browser features"
            },
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                    headers=self.config.headers
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
                                description=info["description"],
                                owasp=info["owasp"],
                                cwe=info["cwe"]
                            )
                            self.findings.append(finding)
                            print(f"  [!] Missing: {header}")
                            
        except Exception as e:
            print(f"  [!] Header check error: {e}")
    
    async def _detect_vulnerabilities(self, url: str):
        """Run vulnerability detection modules"""
        
        if "sql_injection" in self.config.enabled_modules:
            await self._test_sqli(url)
        
        if "xss" in self.config.enabled_modules:
            await self._test_xss(url)
        
        if "ssrf" in self.config.enabled_modules:
            await self._test_ssrf(url)
        
        if "open_redirect" in self.config.enabled_modules:
            await self._test_open_redirect(url)
        
        if "sensitive_data" in self.config.enabled_modules:
            await self._test_sensitive_data(url)
        
        if "cors" in self.config.enabled_modules:
            await self._test_cors(url)
        
        if "directory_traversal" in self.config.enabled_modules:
            await self._test_directory_traversal(url)
    
    async def _test_sqli(self, url: str):
        """Test for SQL Injection"""
        payloads = [
            "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
            "1' AND 1=1--", "1' AND 1=2--", "' AND SLEEP(1)--",
            "1' ORDER BY 1--", "1' ORDER BY 10--", "' HAVING 1=1--"
        ]
        
        error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_", r"PostgreSQL.*ERROR",
            r"ORA-\d{4,}", r"Microsoft OLE DB", r"sqlite3\.OperationalError",
            r"Unclosed quotation", r"Incorrect syntax near", r"quoted string",
            r"mysql_fetch", r"pg_query", r"odbc_exec"
        ]
        
        print(f"  [*] Testing SQL Injection...")
        
        if '?' in url:
            base_url, query = url.split('?', 1)
            params = query.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=', 1)[0]
                    
                    for payload in payloads[:5]:
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    test_url,
                                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                                    headers=self.config.headers
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
                                                evidence=f"SQL error pattern detected: {pattern}",
                                                description="SQL injection vulnerability - user input not properly sanitized",
                                                remediation="Use parameterized queries/prepared statements",
                                                owasp="A03 - Injection",
                                                cwe="CWE-89"
                                            )
                                            self.findings.append(finding)
                                            print(f"  [!!!] SQL Injection found: {param_name}")
                                            break
                                            
                        except Exception:
                            pass
        
        # Test forms
        for form in self.forms:
            for input_name in form.get('inputs', []):
                for payload in payloads[:3]:
                    try:
                        data = {input_name: payload}
                        async with aiohttp.ClientSession() as session:
                            async with session.post(
                                form['url'],
                                data=data,
                                timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                                headers=self.config.headers
                            ) as response:
                                html = await response.text()
                                
                                for pattern in error_patterns:
                                    if re.search(pattern, html, re.IGNORECASE):
                                        finding = VulnerabilityFinding(
                                            module="sql_injection",
                                            vulnerability_type="SQL Injection",
                                            url=form['url'],
                                            parameter=input_name,
                                            payload=payload,
                                            method="POST",
                                            severity="Critical",
                                            cvss_score=9.8,
                                            confidence=0.9,
                                            evidence="SQL error pattern in form response",
                                            owasp="A03 - Injection",
                                            cwe="CWE-89"
                                        )
                                        self.findings.append(finding)
                                        print(f"  [!!!] SQL Injection in form: {input_name}")
                                        break
                    except Exception:
                        pass
    
    async def _test_xss(self, url: str):
        """Test for Cross-Site Scripting"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        print(f"  [*] Testing XSS...")
        
        if '?' in url:
            base_url, query = url.split('?', 1)
            params = query.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=', 1)[0]
                    
                    for payload in payloads[:4]:
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    test_url,
                                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                                    headers=self.config.headers
                                ) as response:
                                    html = await response.text()
                                    
                                    # Check for reflection
                                    if payload in html or "alert('XSS')" in html or "alert(1)" in html:
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
                                            description="XSS vulnerability - input reflected without encoding",
                                            remediation="Encode all user input before rendering",
                                            owasp="A03 - Injection",
                                            cwe="CWE-79"
                                        )
                                        self.findings.append(finding)
                                        print(f"  [!!] XSS found: {param_name}")
                                        break
                                        
                        except Exception:
                            pass
    
    async def _test_ssrf(self, url: str):
        """Test for Server-Side Request Forgery"""
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'link', 'src', 'domain']
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254",
            "http://127.0.0.1:22",
            "http://127.0.0.1:80"
        ]
        
        print(f"  [*] Testing SSRF...")
        
        for param in ssrf_params:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                            headers=self.config.headers
                        ) as response:
                            html = await response.text()
                            
                            # Check for internal responses
                            internal_indicators = [
                                "SSH-", "Apache", "nginx", "index of",
                                "root:", "etc/passwd", "metadata"
                            ]
                            
                            for indicator in internal_indicators:
                                if indicator.lower() in html.lower():
                                    finding = VulnerabilityFinding(
                                        module="ssrf",
                                        vulnerability_type="Server-Side Request Forgery",
                                        url=test_url,
                                        parameter=param,
                                        payload=payload,
                                        severity="High",
                                        cvss_score=7.5,
                                        confidence=0.75,
                                        evidence=f"Internal response indicator: {indicator}",
                                        description="Potential SSRF vulnerability",
                                        owasp="A10 - SSRF",
                                        cwe="CWE-918"
                                    )
                                    self.findings.append(finding)
                                    print(f"  [!!] Potential SSRF: {param}")
                                    break
                                    
                except Exception:
                    pass
    
    async def _test_open_redirect(self, url: str):
        """Test for Open Redirect"""
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'rurl', 'redirect_uri']
        payloads = ['//evil.com', 'https://evil.com', '//attacker.com', 'https://trusted.com@evil.com']
        
        print(f"  [*] Testing Open Redirect...")
        
        for param in redirect_params:
            for payload in payloads:
                test_url = f"{url}?{param}={payload}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                            headers=self.config.headers,
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
                                    confidence=0.85,
                                    evidence=f"Redirects to: {location}",
                                    description="Open redirect vulnerability - can be used for phishing",
                                    remediation="Implement URL allowlists for redirects",
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
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "Generic Secret": r'(?i)(password|secret|api_key|apikey)\s*[=:]\s*["\']?[^\s"\'>]{8,}',
            "Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "Phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "Credit Card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        }
        
        print(f"  [*] Testing Sensitive Data Exposure...")
        
        html = self.response_cache.get(url, "")
        
        if not html:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        headers=self.config.headers
                    ) as response:
                        html = await response.text()
            except Exception:
                return
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, html)
            if matches:
                # Filter common false positives for emails
                if name == "Email" and len(matches) > 50:
                    continue
                    
                finding = VulnerabilityFinding(
                    module="sensitive_data",
                    vulnerability_type=f"Sensitive Data: {name}",
                    url=url,
                    severity="High" if name in ["API Key", "Private Key", "AWS Access Key"] else "Medium",
                    cvss_score=7.5 if name in ["API Key", "Private Key"] else 5.0,
                    confidence=0.7,
                    evidence=f"Found {len(matches)} potential {name}(s)",
                    description=f"Potential {name} exposure in page source",
                    remediation="Remove sensitive data from client-side code",
                    owasp="A02 - Cryptographic Failures",
                    cwe="CWE-200"
                )
                self.findings.append(finding)
                print(f"  [!] Sensitive data found: {name} ({len(matches)} instances)")
    
    async def _test_cors(self, url: str):
        """Test for CORS misconfiguration"""
        print(f"  [*] Testing CORS...")
        
        test_origins = [
            "https://evil.com",
            "http://attacker.com",
            "null"
        ]
        
        for origin in test_origins:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.options(
                        url,
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                        headers={
                            **self.config.headers,
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET"
                        }
                    ) as response:
                        acao = response.headers.get('Access-Control-Allow-Origin', '')
                        allow_credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                        
                        if acao == '*' or acao == origin:
                            finding = VulnerabilityFinding(
                                module="cors",
                                vulnerability_type="CORS Misconfiguration",
                                url=url,
                                severity="Medium",
                                cvss_score=6.5,
                                confidence=0.85,
                                evidence=f"ACAO: {acao}, Credentials: {allow_credentials}",
                                description="CORS allows arbitrary origins",
                                remediation="Restrict CORS to trusted origins only",
                                owasp="A05 - Security Misconfiguration",
                                cwe="CWE-942"
                            )
                            self.findings.append(finding)
                            print(f"  [!] CORS misconfiguration found")
                            break
                            
            except Exception:
                pass
    
    async def _test_directory_traversal(self, url: str):
        """Test for Directory Traversal"""
        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam"
        ]
        
        indicators = ["root:", "[extensions]", "[boot loader]", "[fonts]"]
        
        print(f"  [*] Testing Directory Traversal...")
        
        if '?' in url:
            base_url, query = url.split('?', 1)
            params = query.split('&')
            
            for param in params:
                if '=' in param:
                    param_name = param.split('=', 1)[0]
                    
                    for payload in payloads:
                        test_url = f"{base_url}?{param_name}={payload}"
                        
                        try:
                            async with aiohttp.ClientSession() as session:
                                async with session.get(
                                    test_url,
                                    timeout=aiohttp.ClientTimeout(total=self.config.timeout),
                                    headers=self.config.headers
                                ) as response:
                                    html = await response.text()
                                    
                                    for indicator in indicators:
                                        if indicator in html:
                                            finding = VulnerabilityFinding(
                                                module="directory_traversal",
                                                vulnerability_type="Directory Traversal",
                                                url=test_url,
                                                parameter=param_name,
                                                payload=payload,
                                                severity="High",
                                                cvss_score=7.5,
                                                confidence=0.85,
                                                evidence=f"File content indicator: {indicator}",
                                                description="Directory traversal vulnerability",
                                                remediation="Validate and sanitize file path inputs",
                                                owasp="A01 - Broken Access Control",
                                                cwe="CWE-22"
                                            )
                                            self.findings.append(finding)
                                            print(f"  [!!] Directory Traversal found: {param_name}")
                                            break
                                            
                        except Exception:
                            pass
    
    def _calculate_statistics(self) -> Dict:
        """Calculate scan statistics"""
        severity_counts = {}
        module_counts = {}
        owasp_counts = {}
        
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            module_counts[finding.module] = module_counts.get(finding.module, 0) + 1
            if finding.owasp:
                owasp_counts[finding.owasp] = owasp_counts.get(finding.owasp, 0) + 1
        
        return {
            "total_findings": len(self.findings),
            "findings_by_severity": severity_counts,
            "findings_by_module": module_counts,
            "findings_by_owasp": owasp_counts,
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
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                if sev in stats["findings_by_severity"]:
                    print(f"    - {sev}: {stats['findings_by_severity'][sev]}")
        
        if stats.get("findings_by_module"):
            print(f"\n  Findings by Module:")
            for mod, count in stats["findings_by_module"].items():
                print(f"    - {mod}: {count}")
        
        print(f"\n{'='*60}")
        print(f"  Author: {self.AUTHOR} | AstraVulnX v{self.VERSION}")
        print(f"  Repo: https://github.com/meherazhosensiam/-AstraVulnX-Scan")
        print(f"{'='*60}\n")

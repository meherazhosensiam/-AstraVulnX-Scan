#!/usr/bin/env python3
"""
AstraVulnX v3.0.0 - AI-Powered Web Vulnerability Scanner
=========================================================

Author: Meheraz Hosen Siam
Role: Penetration Testing Learner
Version: 3.0.0

Usage:
    python main.py <target_url>

Example:
    python main.py http://testphp.vulnweb.com
"""

import sys
import os
import asyncio

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from astravulnx.core.scanner import Scanner
from astravulnx.core.config import Config


def print_banner():
    """Print scanner banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ███████╗ █████╗ ██╗     ███████╗██╗   ██╗███████╗ ║
    ║    ██╔══██╗██╔════╝██╔══██╗██║     ██╔════╝██║   ██║██╔════╝ ║
    ║    ███████║███████╗███████║██║     ███████╗██║   ██║█████╗   ║
    ║    ██╔══██║╚════██║██╔══██║██║     ╚════██║██║   ██║██╔══╝   ║
    ║    ██║  ██║███████║██║  ██║███████╗███████║╚██████╔╝███████╗ ║
    ║    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝ ║
    ║                                                               ║
    ║            v3.0.0 - AI-Powered Web Vulnerability Scanner      ║
    ║                                                               ║
    ║              Author: Meheraz Hosen Siam                       ║
    ║              Role: Penetration Testing Learner                ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def main():
    """Main entry point"""
    print_banner()
    
    if len(sys.argv) < 2:
        print("\n  Usage: python main.py <target_url>")
        print("\n  Example:")
        print("    python main.py http://testphp.vulnweb.com")
        print("    python main.py https://example.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        print("\n  [!] Error: URL must start with http:// or https://")
        sys.exit(1)
    
    print(f"\n  Target: {target_url}")
    print(f"  Author: Meheraz Hosen Siam")
    print(f"  Version: 3.0.0")
    
    # Create configuration
    config = Config(
        target_url=target_url,
        scan_profile="quick",
        timeout=30,
        verbose=True
    )
    
    # Run scanner
    scanner = Scanner(config)
    result = asyncio.run(scanner.scan(target_url))
    
    # Output results
    print("\n" + "="*60)
    print("  SCAN RESULTS")
    print("="*60)
    
    if result.findings:
        print(f"\n  Total Vulnerabilities Found: {len(result.findings)}")
        
        # Group by severity
        critical = [f for f in result.findings if f.severity == "Critical"]
        high = [f for f in result.findings if f.severity == "High"]
        medium = [f for f in result.findings if f.severity == "Medium"]
        low = [f for f in result.findings if f.severity == "Low"]
        
        print(f"\n  Severity Breakdown:")
        if critical:
            print(f"    [CRITICAL] {len(critical)} findings")
        if high:
            print(f"    [HIGH] {len(high)} findings")
        if medium:
            print(f"    [MEDIUM] {len(medium)} findings")
        if low:
            print(f"    [LOW] {len(low)} findings")
        
        print(f"\n  Detailed Findings:")
        for i, finding in enumerate(result.findings[:10], 1):
            print(f"\n  [{i}] {finding.vulnerability_type}")
            print(f"      Module: {finding.module}")
            print(f"      Severity: {finding.severity}")
            print(f"      OWASP: {finding.owasp}")
            print(f"      CWE: {finding.cwe}")
            if finding.parameter:
                print(f"      Parameter: {finding.parameter}")
            if finding.evidence:
                print(f"      Evidence: {finding.evidence[:100]}")
        
        if len(result.findings) > 10:
            print(f"\n  ... and {len(result.findings) - 10} more findings")
    else:
        print("\n  No vulnerabilities found.")
    
    print("\n" + "="*60)
    print("  AstraVulnX v3.0.0 | Author: Meheraz Hosen Siam")
    print("="*60 + "\n")
    
    return result


if __name__ == "__main__":
    main()

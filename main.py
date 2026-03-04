#!/usr/bin/env python3
"""
AstraVulnX v3.0.0 - AI-Powered Web Vulnerability Scanner
=========================================================

Author: Meheraz Hosen Siam
Role: Penetration Testing Learner
Repository: https://github.com/meherazhosensiam/-AstraVulnX-Scan
Version: 3.0.0

Usage:
    python main.py <target_url>

Example:
    python main.py http://testphp.vulnweb.com
"""

import sys
import os
import asyncio
import argparse
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from astravulnx.core.scanner import Scanner
from astravulnx.core.config import Config

__version__ = "3.0.0"
__author__ = "Meheraz Hosen Siam"
__repository__ = "https://github.com/meherazhosensiam/-AstraVulnX-Scan"


def print_banner():
    """Print scanner banner"""
    print(r"""
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
    ║              Repo: github.com/meherazhosensiam/-AstraVulnX-Scan║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"AstraVulnX v{__version__} - AI-Powered Web Vulnerability Scanner",
        epilog=f"Author: {__author__} | Repository: {__repository__}"
    )
    
    parser.add_argument(
        'target_url',
        nargs='?',
        help='Target URL to scan'
    )
    
    parser.add_argument(
        '-p', '--profile',
        choices=['quick', 'standard', 'deep'],
        default='quick',
        help='Scan profile (default: quick)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file path for results'
    )
    
    parser.add_argument(
        '--proxy',
        help='Proxy URL (e.g., http://127.0.0.1:8080)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'AstraVulnX v{__version__} by {__author__}'
    )
    
    return parser.parse_args()


async def run_scan(target_url: str, args) -> None:
    """Run the vulnerability scan"""
    
    # Create configuration
    config = Config(
        target_url=target_url,
        scan_profile=args.profile,
        timeout=args.timeout,
        verbose=True
    )
    
    if args.proxy:
        config.proxy = args.proxy
    
    # Run scanner
    scanner = Scanner(config)
    result = await scanner.scan(target_url)
    
    # Save results if output specified
    if args.output:
        result.save_json(args.output)
        print(f"\n  Results saved to: {args.output}")
    
    # Print detailed findings
    print_detailed_results(result)


def print_detailed_results(result):
    """Print detailed scan results"""
    print("\n" + "="*60)
    print("  DETAILED FINDINGS")
    print("="*60)
    
    if result.findings:
        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(
            result.findings,
            key=lambda x: severity_order.get(x.severity, 5)
        )
        
        for i, finding in enumerate(sorted_findings, 1):
            severity_color = {
                "Critical": "\033[91m",
                "High": "\033[93m",
                "Medium": "\033[94m",
                "Low": "\033[92m",
                "Info": "\033[90m"
            }.get(finding.severity, "\033[0m")
            
            reset = "\033[0m"
            
            print(f"\n  [{i}] {severity_color}[{finding.severity}]{reset} {finding.vulnerability_type}")
            print(f"      Module: {finding.module}")
            print(f"      OWASP: {finding.owasp}")
            print(f"      CWE: {finding.cwe}")
            print(f"      CVSS: {finding.cvss_score}")
            
            if finding.parameter:
                print(f"      Parameter: {finding.parameter}")
            if finding.payload:
                print(f"      Payload: {finding.payload[:50]}...")
            if finding.evidence:
                print(f"      Evidence: {finding.evidence[:80]}")
    else:
        print("\n  No vulnerabilities found.")
    
    print("\n" + "="*60)
    print(f"  AstraVulnX v{__version__} | Author: {__author__}")
    print(f"  Repository: {__repository__}")
    print("="*60 + "\n")


def main():
    """Main entry point"""
    print_banner()
    
    args = parse_arguments()
    
    if not args.target_url:
        print("\n  Usage: python main.py <target_url>")
        print("\n  Options:")
        print("    -p, --profile    Scan profile (quick/standard/deep)")
        print("    -o, --output     Output file for results")
        print("    --proxy          Proxy URL")
        print("    -t, --timeout    Request timeout")
        print("\n  Example:")
        print("    python main.py http://testphp.vulnweb.com")
        print("    python main.py https://example.com -p deep -o report.json")
        sys.exit(1)
    
    target_url = args.target_url
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        print("\n  [!] Error: URL must start with http:// or https://")
        print("  [!] Example: http://testphp.vulnweb.com")
        sys.exit(1)
    
    print(f"\n  Target: {target_url}")
    print(f"  Profile: {args.profile}")
    print(f"  Author: {__author__}")
    print(f"  Version: {__version__}")
    
    # Run async scan
    asyncio.run(run_scan(target_url, args))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SecretProbe — Web Misconfiguration & Secrets Scanner

A lightweight, modern tool for discovering exposed secrets,
misconfigurations, and security issues in web applications.

Usage:
    python secretprobe.py -u https://target.com
    python secretprobe.py -u https://target.com -o report.html
    python secretprobe.py -u https://target.com --checks headers,files,debug
    python secretprobe.py -u https://target.com --timeout 15 -v

Author: Your Name
License: MIT
"""

import argparse
import sys
import os

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from scanner.utils import ScanConfig
from scanner.engine import SecretProbeScanner
from scanner.checks import CHECK_REGISTRY


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="SecretProbe",
        description="SecretProbe - Web Misconfiguration & Secrets Scanner",
        epilog="Example: py secretprobe.py -u https://example.com -o report.html",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan (e.g., https://example.com)"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output HTML report file path (e.g., report.html)"
    )

    parser.add_argument(
        "-c", "--checks",
        default="all",
        help=f"Comma-separated list of checks to run. "
             f"Available: {', '.join(CHECK_REGISTRY.keys())}, all (default: all)"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        default=True,
        help="Disable SSL certificate verification (default: disabled)"
    )

    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        help="Custom User-Agent string"
    )

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Parse checks
    checks = [c.strip() for c in args.checks.split(",")]

    # Create config
    config = ScanConfig(
        target_url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        verify_ssl=not args.no_ssl_verify,
        threads=args.threads,
        verbose=args.verbose,
        checks=checks,
        output_file=args.output
    )

    # Run scanner
    scanner = SecretProbeScanner(config)
    findings = scanner.run()

    # Exit code based on findings
    critical_high = [f for f in findings
                     if f.severity.value in ("CRITICAL", "HIGH")]
    sys.exit(1 if critical_high else 0)


if __name__ == "__main__":
    main()

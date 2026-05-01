"""
Scanner Engine — orchestrates all security checks.
"""

import time
from typing import List, Optional
from .utils import Finding, ScanConfig, create_session, normalize_url
from .checks import CHECK_REGISTRY
from .reporter import (
    print_banner, print_scan_start, print_check_status,
    print_findings, print_summary, generate_html_report, console
)


class SecretProbeScanner:
    """Main scanner engine that orchestrates all security checks."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Finding] = []
        self.session = create_session(config)

    def run(self) -> List[Finding]:
        """Execute the full scan pipeline."""
        print_banner()

        # Normalize target URL
        try:
            self.config.target_url = normalize_url(self.config.target_url)
        except ValueError as e:
            console.print(f"[bold red]Error:[/] {e}")
            return []

        # Determine which checks to run
        if "all" in self.config.checks:
            checks_to_run = list(CHECK_REGISTRY.keys())
        else:
            checks_to_run = [c for c in self.config.checks if c in CHECK_REGISTRY]
            invalid = [c for c in self.config.checks if c not in CHECK_REGISTRY]
            if invalid:
                console.print(f"[yellow]Warning:[/] Unknown checks: {', '.join(invalid)}")

        if not checks_to_run:
            console.print("[bold red]Error:[/] No valid checks to run.")
            return []

        check_names = [CHECK_REGISTRY[c][0] for c in checks_to_run]
        print_scan_start(self.config.target_url, check_names)

        # Run checks
        start_time = time.time()

        for check_key in checks_to_run:
            check_name, check_func = CHECK_REGISTRY[check_key]
            print_check_status(check_name, "running")

            try:
                results = check_func(
                    target_url=self.config.target_url,
                    session=self.session,
                    timeout=self.config.timeout,
                    verbose=self.config.verbose
                )
                self.findings.extend(results)
                print_check_status(f"{check_name} — {len(results)} findings", "done")
            except Exception as e:
                console.print(f"  [red]✗[/] Error in {check_name}: {e}")

        duration = time.time() - start_time

        # Print results
        console.print()
        print_findings(self.findings)
        print_summary(self.findings, self.config.target_url, duration)

        # Generate HTML report if requested
        if self.config.output_file:
            generate_html_report(
                self.findings, self.config.target_url,
                duration, self.config.output_file
            )
            console.print(f"\n  [bold green]📄 HTML report saved:[/] {self.config.output_file}")

        console.print()
        return self.findings

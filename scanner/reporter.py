"""
Reporter module — beautiful terminal output + HTML report generation.
"""

import html
from datetime import datetime
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from .utils import Finding, Severity


console = Console()

BANNER = r"""
   _____                    __  ____             __       
  / ___/___  _____________/ /_/ __ \_________  / /_  ___ 
  \__ \/ _ \/ ___/ ___/ _ \/ __/ /_/ / ___/ __ \/ __ \/ _ \
 ___/ /  __/ /__/ /  /  __/ /_/ ____/ /  / /_/ / /_/ /  __/
/____/\___/\___/_/   \___/\__/_/   /_/   \____/_.___/\___/ 
                                                    v1.0.0
"""


def print_banner():
    """Print the SecretProbe banner."""
    console.print(BANNER, style="bold cyan")
    console.print("  Web Misconfiguration & Secrets Scanner", style="dim")
    console.print("  https://github.com/rubysy/SecretProbe\n", style="dim")


def print_scan_start(target_url: str, checks: list):
    """Print scan start info."""
    console.print(Panel(
        f"[bold white]Target:[/] {target_url}\n"
        f"[bold white]Checks:[/] {', '.join(checks)}\n"
        f"[bold white]Time:[/]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold cyan]🔍 Starting Scan[/]",
        border_style="cyan",
        box=box.ROUNDED
    ))
    console.print()


def print_check_status(check_name: str, status: str = "running"):
    """Print check status during scan."""
    if status == "running":
        console.print(f"  [cyan]⠿[/] Running: [bold]{check_name}[/]...", end="\r")
    elif status == "done":
        console.print(f"  [green]✓[/] Completed: [bold]{check_name}[/]   ")


def print_findings(findings: List[Finding]):
    """Print findings to terminal with rich formatting."""
    if not findings:
        console.print(Panel(
            "[bold green]No vulnerabilities found! 🎉[/]\n"
            "The target appears to be well-configured.",
            title="[bold green]✅ Clean Scan[/]",
            border_style="green",
            box=box.ROUNDED
        ))
        return

    # Group findings by severity
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                      Severity.LOW, Severity.INFO]

    for severity in severity_order:
        sev_findings = [f for f in findings if f.severity == severity]
        if not sev_findings:
            continue

        console.print(f"\n  {severity.emoji} [bold {severity.color}]"
                      f"{severity.value}[/] ({len(sev_findings)} findings)")
        console.print(f"  {'─' * 50}")

        for finding in sev_findings:
            console.print(f"  [bold {severity.color}]├──[/] {finding.title}")
            console.print(f"  [dim]│   {finding.description}[/]")
            if finding.evidence:
                for line in finding.evidence.split("\n"):
                    console.print(f"  [dim]│  [/] [italic]{line.strip()}[/]")
            console.print(f"  [dim]│[/]")


def print_summary(findings: List[Finding], target_url: str, duration: float):
    """Print scan summary with score."""
    total_deductions = sum(f.severity.score for f in findings)
    score = max(0, 100 - total_deductions)

    # Determine grade
    if score >= 90:
        grade, grade_color = "A+", "green"
    elif score >= 80:
        grade, grade_color = "A", "green"
    elif score >= 70:
        grade, grade_color = "B", "yellow"
    elif score >= 60:
        grade, grade_color = "C", "yellow"
    elif score >= 40:
        grade, grade_color = "D", "red"
    else:
        grade, grade_color = "F", "bright_red"

    # Count by severity
    counts = {}
    for sev in Severity:
        count = len([f for f in findings if f.severity == sev])
        if count > 0:
            counts[sev] = count

    console.print()
    summary_lines = [
        f"[bold white]Target:[/]    {target_url}",
        f"[bold white]Score:[/]     [bold {grade_color}]{score}/100 (Grade: {grade})[/]",
        f"[bold white]Findings:[/]  {len(findings)} total",
        f"[bold white]Duration:[/]  {duration:.1f}s",
        "",
    ]

    for sev, count in counts.items():
        summary_lines.append(f"  {sev.emoji} {sev.value}: {count}")

    console.print(Panel(
        "\n".join(summary_lines),
        title=f"[bold cyan]📊 Scan Summary[/]",
        border_style="cyan",
        box=box.DOUBLE
    ))


def generate_html_report(findings: List[Finding], target_url: str,
                         duration: float, output_path: str):
    """Generate a beautiful HTML report."""
    total_deductions = sum(f.severity.score for f in findings)
    score = max(0, 100 - total_deductions)

    if score >= 90: grade, grade_color = "A+", "#22c55e"
    elif score >= 80: grade, grade_color = "A", "#22c55e"
    elif score >= 70: grade, grade_color = "B", "#eab308"
    elif score >= 60: grade, grade_color = "C", "#eab308"
    elif score >= 40: grade, grade_color = "D", "#ef4444"
    else: grade, grade_color = "F", "#dc2626"

    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "INFO": "#6b7280",
    }

    # Build findings HTML
    findings_html = ""
    for finding in sorted(findings, key=lambda f: list(Severity).index(f.severity)):
        sev_color = severity_colors.get(finding.severity.value, "#6b7280")
        evidence_escaped = html.escape(finding.evidence) if finding.evidence else ""
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge" style="background:{sev_color}">
                    {finding.severity.value}
                </span>
                <span class="finding-title">{html.escape(finding.title)}</span>
                <span class="finding-category">{html.escape(finding.category)}</span>
            </div>
            <p class="finding-desc">{html.escape(finding.description)}</p>
            {'<pre class="finding-evidence">' + evidence_escaped + '</pre>' if evidence_escaped else ''}
            {'<p class="finding-fix">💡 ' + html.escape(finding.remediation) + '</p>' if finding.remediation else ''}
        </div>"""

    counts = {sev: len([f for f in findings if f.severity == sev]) for sev in Severity}

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecretProbe Report — {html.escape(target_url)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:900px;margin:0 auto;padding:2rem}}
.header{{text-align:center;padding:2rem 0;border-bottom:1px solid #1e293b;margin-bottom:2rem}}
.header h1{{font-size:2rem;background:linear-gradient(135deg,#06b6d4,#8b5cf6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}}
.header .target{{color:#94a3b8;font-size:1.1rem}}
.header .time{{color:#64748b;font-size:.85rem;margin-top:.5rem}}
.score-section{{display:flex;gap:2rem;margin-bottom:2rem;flex-wrap:wrap}}
.score-card{{background:#1e293b;border-radius:12px;padding:1.5rem;flex:1;min-width:200px;text-align:center}}
.score-big{{font-size:3rem;font-weight:800;color:{grade_color}}}
.score-label{{color:#94a3b8;font-size:.85rem;text-transform:uppercase;letter-spacing:.1em}}
.stats{{display:flex;gap:.75rem;justify-content:center;flex-wrap:wrap;margin-top:1rem}}
.stat{{padding:.4rem .8rem;border-radius:6px;font-size:.8rem;font-weight:600;color:white}}
.findings-section h2{{font-size:1.3rem;margin-bottom:1rem;color:#f1f5f9}}
.finding{{background:#1e293b;border-radius:10px;padding:1.2rem;margin-bottom:1rem;border-left:3px solid #334155}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem;flex-wrap:wrap}}
.severity-badge{{padding:.2rem .6rem;border-radius:4px;font-size:.7rem;font-weight:700;color:white;text-transform:uppercase;letter-spacing:.05em}}
.finding-title{{font-weight:600;color:#f1f5f9;font-size:1rem}}
.finding-category{{margin-left:auto;color:#64748b;font-size:.8rem}}
.finding-desc{{color:#94a3b8;font-size:.9rem;margin-bottom:.5rem}}
.finding-evidence{{background:#0f172a;padding:.8rem;border-radius:6px;font-size:.8rem;color:#7dd3fc;overflow-x:auto;white-space:pre;margin-bottom:.5rem}}
.finding-fix{{color:#86efac;font-size:.85rem;font-style:italic}}
.footer{{text-align:center;padding:2rem 0;margin-top:2rem;border-top:1px solid #1e293b;color:#475569;font-size:.8rem}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 SecretProbe Report</h1>
        <div class="target">{html.escape(target_url)}</div>
        <div class="time">Scanned on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Duration: {duration:.1f}s</div>
    </div>
    <div class="score-section">
        <div class="score-card">
            <div class="score-big">{score}</div>
            <div class="score-label">Security Score</div>
        </div>
        <div class="score-card">
            <div class="score-big" style="font-size:2.5rem">{grade}</div>
            <div class="score-label">Grade</div>
        </div>
        <div class="score-card">
            <div class="score-big" style="font-size:2.5rem">{len(findings)}</div>
            <div class="score-label">Total Findings</div>
            <div class="stats">
                {''.join(f'<span class="stat" style="background:{severity_colors[sev.value]}">{sev.value}: {counts[sev]}</span>' for sev in Severity if counts.get(sev, 0) > 0)}
            </div>
        </div>
    </div>
    <div class="findings-section">
        <h2>📋 Findings ({len(findings)})</h2>
        {findings_html if findings_html else '<p style="color:#64748b">No findings — target looks secure!</p>'}
    </div>
    <div class="footer">
        Generated by SecretProbe v1.0.0 · https://github.com/rubysy/SecretProbe
    </div>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

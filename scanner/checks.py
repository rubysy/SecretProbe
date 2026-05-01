"""
Security check modules for SecretProbe.
Each check function returns a list of Finding objects.
"""

import re
from typing import List
from urllib.parse import urljoin
from .utils import Finding, Severity, safe_request, build_url


# =============================================================================
# CHECK 1: Sensitive File Exposure
# =============================================================================

SENSITIVE_PATHS = [
    # Environment & Config
    (".env", "Environment file — may contain DB passwords, API keys"),
    (".env.backup", "Environment backup file"),
    (".env.local", "Local environment file"),
    (".env.production", "Production environment file"),
    (".env.example", "Environment example — may reveal variable names"),
    # Git
    (".git/config", "Git config — source code leak"),
    (".git/HEAD", "Git HEAD — confirms .git exposure"),
    # IDE & Editor
    (".vscode/settings.json", "VS Code settings exposed"),
    (".idea/workspace.xml", "IntelliJ IDEA config exposed"),
    # Backups
    ("backup.sql", "SQL backup file"),
    ("database.sql", "Database dump"),
    ("db.sql", "Database dump"),
    ("backup.zip", "Backup archive"),
    ("backup.tar.gz", "Backup archive"),
    ("site.tar.gz", "Site backup archive"),
    # Config files
    ("wp-config.php.bak", "WordPress config backup"),
    ("config.php.bak", "Config backup file"),
    ("web.config", "IIS web.config file"),
    (".htaccess", "Apache htaccess file"),
    ("nginx.conf", "Nginx configuration"),
    # Sensitive endpoints
    ("phpinfo.php", "PHP info page — leaks server config"),
    ("info.php", "PHP info page"),
    ("server-status", "Apache server status"),
    ("server-info", "Apache server info"),
    (".DS_Store", "macOS directory metadata"),
    ("thumbs.db", "Windows thumbnail cache"),
    ("crossdomain.xml", "Flash cross-domain policy"),
    ("sitemap.xml", "Sitemap — reveals URL structure"),
    ("robots.txt", "Robots.txt — may reveal hidden paths"),
    # Logs
    ("error.log", "Error log file"),
    ("access.log", "Access log file"),
    ("debug.log", "Debug log file"),
    ("laravel.log", "Laravel application log"),
    ("storage/logs/laravel.log", "Laravel log file"),
    # Package managers
    ("composer.json", "PHP Composer — reveals dependencies"),
    ("package.json", "Node.js package — reveals dependencies"),
    ("Gemfile", "Ruby dependencies"),
    ("requirements.txt", "Python dependencies"),
]

SECRET_PATTERNS = [
    (r'DB_PASSWORD\s*=\s*\S+', "Database password"),
    (r'DB_USERNAME\s*=\s*\S+', "Database username"),
    (r'APP_KEY\s*=\s*\S+', "Application key"),
    (r'API_KEY\s*=\s*\S+', "API key"),
    (r'SECRET_KEY\s*=\s*\S+', "Secret key"),
    (r'AWS_ACCESS_KEY_ID\s*=\s*\S+', "AWS access key"),
    (r'AWS_SECRET_ACCESS_KEY\s*=\s*\S+', "AWS secret key"),
    (r'MAIL_PASSWORD\s*=\s*\S+', "Mail password"),
    (r'REDIS_PASSWORD\s*=\s*\S+', "Redis password"),
    (r'DATABASE_URL\s*=\s*\S+', "Database URL"),
]


def check_sensitive_files(target_url: str, session, timeout: int = 10,
                          verbose: bool = False) -> List[Finding]:
    """Check for exposed sensitive files and directories."""
    findings = []

    for path, description in SENSITIVE_PATHS:
        url = build_url(target_url, path)
        resp = safe_request(session, url, timeout=timeout)

        if resp is None:
            continue

        if resp.status_code == 200:
            content_type = resp.headers.get("Content-Type", "").lower()
            body = resp.text[:5000]

            # Skip generic error/redirect pages
            if len(body) < 10:
                continue
            if "<title>404" in body.lower() or "not found" in body.lower()[:500]:
                continue

            severity = Severity.MEDIUM
            evidence_lines = []

            # Check for actual secrets in .env files
            if ".env" in path:
                secrets_found = []
                for pattern, secret_name in SECRET_PATTERNS:
                    matches = re.findall(pattern, body)
                    if matches:
                        secrets_found.append(secret_name)
                        # Mask the actual value
                        for m in matches:
                            key_part = m.split("=")[0] + "="
                            evidence_lines.append(f"  {key_part}[REDACTED]")

                if secrets_found:
                    severity = Severity.CRITICAL
                    description = f"Environment file with secrets: {', '.join(secrets_found)}"
                else:
                    severity = Severity.HIGH

            # .git exposure is critical
            elif ".git" in path:
                severity = Severity.CRITICAL
                if "repositoryformatversion" in body:
                    evidence_lines.append("  Git repository confirmed")

            # phpinfo is high
            elif "phpinfo" in path and "PHP Version" in body:
                severity = Severity.HIGH
                version_match = re.search(r'PHP Version\s*([\d.]+)', body)
                if version_match:
                    evidence_lines.append(f"  PHP Version: {version_match.group(1)}")

            # SQL dumps are critical
            elif path.endswith(".sql"):
                severity = Severity.CRITICAL
                if "CREATE TABLE" in body or "INSERT INTO" in body:
                    evidence_lines.append("  SQL statements confirmed")

            # Log files
            elif path.endswith(".log"):
                severity = Severity.HIGH
                evidence_lines.append(f"  Log file size: {len(body)} bytes")

            evidence = f"  URL: {url} (HTTP {resp.status_code})"
            if evidence_lines:
                evidence += "\n" + "\n".join(evidence_lines)

            findings.append(Finding(
                severity=severity,
                title=f"Exposed: {path}",
                description=description,
                evidence=evidence,
                remediation=f"Block access to '{path}' in your web server config. "
                            f"Add deny rules in .htaccess or nginx.conf.",
                url=url,
                category="Sensitive Files"
            ))

    return findings


# =============================================================================
# CHECK 2: Security Headers Analysis
# =============================================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "HSTS not set — vulnerable to SSL stripping attacks",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP not set — vulnerable to XSS and data injection",
        "remediation": "Add a Content-Security-Policy header to restrict resource loading"
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options not set — vulnerable to clickjacking",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "X-Content-Type-Options not set — MIME sniffing possible",
        "remediation": "Add header: X-Content-Type-Options: nosniff"
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection not set (legacy but still checked)",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy not set — referrer info may leak",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy not set — browser features unrestricted",
        "remediation": "Add a Permissions-Policy header to control browser features"
    },
}


def check_security_headers(target_url: str, session, timeout: int = 10,
                           verbose: bool = False) -> List[Finding]:
    """Analyze HTTP security headers."""
    findings = []
    resp = safe_request(session, target_url, timeout=timeout)

    if resp is None:
        return findings

    headers = resp.headers
    present_count = 0

    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in {k.lower() for k in headers.keys()}:
            findings.append(Finding(
                severity=info["severity"],
                title=f"Missing: {header_name}",
                description=info["description"],
                evidence=f"  Header '{header_name}' not found in response",
                remediation=info["remediation"],
                url=target_url,
                category="Security Headers"
            ))
        else:
            present_count += 1

    return findings


# =============================================================================
# CHECK 3: Debug Mode Detection
# =============================================================================

DEBUG_SIGNATURES = [
    # Laravel
    {"pattern": r"Whoops!.*looks like something went wrong", "framework": "Laravel",
     "indicator": "Laravel debug page (Whoops)"},
    {"pattern": r"laravel.*MethodNotAllowedHttpException", "framework": "Laravel",
     "indicator": "Laravel exception trace"},
    {"pattern": r"Ignition.*laravel", "framework": "Laravel",
     "indicator": "Laravel Ignition debug page"},
    # Django
    {"pattern": r"You're seeing this error because you have.*DEBUG\s*=\s*True",
     "framework": "Django", "indicator": "Django DEBUG=True"},
    {"pattern": r"DisallowedHost.*ALLOWED_HOSTS", "framework": "Django",
     "indicator": "Django ALLOWED_HOSTS misconfiguration"},
    # Express/Node.js
    {"pattern": r"Cannot\s+GET\s+/\w+.*at\s+Layer", "framework": "Express",
     "indicator": "Express.js stack trace"},
    # ASP.NET
    {"pattern": r"Server Error in.*Application", "framework": "ASP.NET",
     "indicator": "ASP.NET detailed error"},
    {"pattern": r"Stack Trace:.*at\s+System\.", "framework": "ASP.NET",
     "indicator": "ASP.NET stack trace"},
    # PHP
    {"pattern": r"Fatal error:.*on line \d+", "framework": "PHP",
     "indicator": "PHP fatal error with line number"},
    {"pattern": r"Parse error:.*syntax error", "framework": "PHP",
     "indicator": "PHP parse error"},
    {"pattern": r"Warning:.*on line \d+", "framework": "PHP",
     "indicator": "PHP warning with line number"},
    # Spring Boot
    {"pattern": r"Whitelabel Error Page.*There was an unexpected error",
     "framework": "Spring Boot", "indicator": "Spring Boot default error page"},
    # Ruby on Rails
    {"pattern": r"ActionController::RoutingError", "framework": "Rails",
     "indicator": "Rails routing error trace"},
]

DEBUG_PATHS = [
    ("/_debugbar/open", "Laravel Debugbar"),
    ("/__debug__/", "Django Debug Toolbar"),
    ("/elmah.axd", "ASP.NET ELMAH Error Log"),
    ("/trace.axd", "ASP.NET Trace"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/env", "Spring Boot Actuator Env"),
    ("/actuator/health", "Spring Boot Actuator Health"),
    ("/swagger-ui.html", "Swagger API Documentation"),
    ("/api-docs", "API Documentation"),
    ("/graphql", "GraphQL Endpoint"),
    ("/graphiql", "GraphiQL Interface"),
]


def check_debug_mode(target_url: str, session, timeout: int = 10,
                     verbose: bool = False) -> List[Finding]:
    """Detect debug mode and development artifacts."""
    findings = []

    # Check main page and a non-existent page for error traces
    test_urls = [
        target_url,
        build_url(target_url, "/asdkjh3k2j4h23kjh_nonexistent_secretprobe"),
        build_url(target_url, "/'+OR+1=1--"),
    ]

    for url in test_urls:
        resp = safe_request(session, url, timeout=timeout)
        if resp is None:
            continue

        body = resp.text[:10000]

        for sig in DEBUG_SIGNATURES:
            if re.search(sig["pattern"], body, re.IGNORECASE | re.DOTALL):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Debug Mode: {sig['framework']}",
                    description=f"{sig['indicator']} detected — may leak stack traces and internal paths",
                    evidence=f"  URL: {url}\n  Pattern matched: {sig['indicator']}",
                    remediation=f"Disable debug mode in {sig['framework']} production config.",
                    url=url,
                    category="Debug Mode"
                ))
                break  # One match per URL is enough

    # Check debug endpoints
    for path, name in DEBUG_PATHS:
        url = build_url(target_url, path)
        resp = safe_request(session, url, timeout=timeout)

        if resp and resp.status_code == 200:
            body = resp.text[:2000]
            if len(body) > 50 and "not found" not in body.lower()[:300]:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Debug Endpoint: {name}",
                    description=f"{name} is accessible — may expose internal data",
                    evidence=f"  URL: {url} (HTTP {resp.status_code})",
                    remediation=f"Disable or restrict access to {path} in production.",
                    url=url,
                    category="Debug Mode"
                ))

    return findings


# =============================================================================
# CHECK 4: Secrets in JavaScript
# =============================================================================

JS_SECRET_PATTERNS = [
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "API Key"),
    (r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Secret/Token"),
    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "Password"),
    (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key"),
    (r'(?:AKIA|ASIA)[0-9A-Z]{16}', "AWS Access Key"),
    (r'sk_live_[0-9a-zA-Z]{24,}', "Stripe Secret Key"),
    (r'pk_live_[0-9a-zA-Z]{24,}', "Stripe Publishable Key"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token"),
    (r'(?:firebase|supabase).*?["\']([a-zA-Z0-9_\-]{20,})["\']', "Firebase/Supabase Key"),
    (r'sq0atp-[0-9A-Za-z\-_]{22}', "Square Access Token"),
    (r'sk-[a-zA-Z0-9]{32,}', "OpenAI API Key"),
]


def check_js_secrets(target_url: str, session, timeout: int = 10,
                     verbose: bool = False) -> List[Finding]:
    """Scan JavaScript files for exposed secrets and API keys."""
    findings = []

    # First, get the main page and find JS files
    resp = safe_request(session, target_url, timeout=timeout)
    if resp is None:
        return findings

    body = resp.text
    # Find JS file references
    js_urls = set()
    js_patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js)[^"\']*["\']',
        r'["\']([^"\']+\.js\?[^"\']*)["\']',
    ]
    for pattern in js_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        for match in matches:
            if match.startswith(("http://", "https://")):
                js_urls.add(match)
            elif match.startswith("//"):
                js_urls.add("https:" + match)
            elif match.startswith("/"):
                js_urls.add(build_url(target_url, match))

    # Also check inline scripts
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body,
                                re.DOTALL | re.IGNORECASE)

    # Scan inline scripts
    for script in inline_scripts:
        for pattern, name in JS_SECRET_PATTERNS:
            matches = re.findall(pattern, script, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Secret in Inline JS: {name}",
                    description=f"{name} found in inline JavaScript on the page",
                    evidence=f"  Found in inline <script> tag\n  Type: {name}",
                    remediation="Move secrets to server-side environment variables. "
                                "Never expose secrets in client-side JavaScript.",
                    url=target_url,
                    category="JS Secrets"
                ))
                break

    # Scan external JS files (limit to 15)
    for js_url in list(js_urls)[:15]:
        resp = safe_request(session, js_url, timeout=timeout)
        if resp is None or resp.status_code != 200:
            continue

        content = resp.text[:50000]

        for pattern, name in JS_SECRET_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"Secret in JS: {name}",
                    description=f"{name} found in external JavaScript file",
                    evidence=f"  File: {js_url}\n  Type: {name}\n  Matches: {len(matches)}",
                    remediation="Remove secrets from JS files. Use server-side "
                                "proxying for API calls that need authentication.",
                    url=js_url,
                    category="JS Secrets"
                ))

    return findings


# =============================================================================
# CHECK 5: Cookie Security
# =============================================================================

def check_cookie_security(target_url: str, session, timeout: int = 10,
                          verbose: bool = False) -> List[Finding]:
    """Analyze cookie security flags."""
    findings = []
    resp = safe_request(session, target_url, timeout=timeout)

    if resp is None:
        return findings

    cookies = resp.cookies
    set_cookie_headers = resp.headers.get("Set-Cookie", "")

    if not cookies and not set_cookie_headers:
        return findings

    for cookie in resp.cookies:
        issues = []

        if not cookie.secure:
            issues.append("Missing 'Secure' flag")
        if "httponly" not in str(resp.headers.get("Set-Cookie", "")).lower():
            issues.append("Missing 'HttpOnly' flag")
        if "samesite" not in str(resp.headers.get("Set-Cookie", "")).lower():
            issues.append("Missing 'SameSite' attribute")

        if issues:
            severity = Severity.MEDIUM if "Secure" in str(issues) else Severity.LOW
            findings.append(Finding(
                severity=severity,
                title=f"Insecure Cookie: {cookie.name}",
                description="Cookie missing security attributes — risk of session hijacking",
                evidence=f"  Cookie: {cookie.name}\n  Issues: {', '.join(issues)}",
                remediation="Set Secure, HttpOnly, and SameSite attributes on all sensitive cookies.",
                url=target_url,
                category="Cookie Security"
            ))

    return findings


# =============================================================================
# CHECK 6: CORS Misconfiguration
# =============================================================================

def check_cors(target_url: str, session, timeout: int = 10,
               verbose: bool = False) -> List[Finding]:
    """Check for CORS misconfigurations."""
    findings = []

    # Test with a malicious Origin header
    test_origins = [
        "https://evil.com",
        "https://attacker.example.com",
        "null",
    ]

    for origin in test_origins:
        headers = {"Origin": origin}
        resp = safe_request(session, target_url, timeout=timeout, headers=headers)

        if resp is None:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if acao == "*":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="CORS: Wildcard Origin",
                description="Access-Control-Allow-Origin is set to '*' — any site can read responses",
                evidence=f"  Access-Control-Allow-Origin: *",
                remediation="Restrict CORS to specific trusted domains instead of using wildcard.",
                url=target_url,
                category="CORS"
            ))
            break

        elif acao == origin and origin != "null":
            severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
            findings.append(Finding(
                severity=severity,
                title="CORS: Origin Reflection",
                description=f"Server reflects arbitrary Origin header '{origin}' — "
                            f"any site can make cross-origin requests"
                            + (" WITH credentials!" if acac == "true" else ""),
                evidence=f"  Origin sent: {origin}\n  "
                         f"Access-Control-Allow-Origin: {acao}\n  "
                         f"Access-Control-Allow-Credentials: {acac or 'not set'}",
                remediation="Validate Origin against a whitelist. Never reflect arbitrary origins.",
                url=target_url,
                category="CORS"
            ))
            break

        elif acao == "null":
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="CORS: Null Origin Allowed",
                description="Server allows 'null' origin — can be exploited via sandboxed iframes",
                evidence=f"  Access-Control-Allow-Origin: null",
                remediation="Do not allow 'null' as a valid origin.",
                url=target_url,
                category="CORS"
            ))
            break

    return findings


# =============================================================================
# CHECK 7: Server Information Disclosure
# =============================================================================

def check_server_info(target_url: str, session, timeout: int = 10,
                      verbose: bool = False) -> List[Finding]:
    """Check for server information disclosure."""
    findings = []
    resp = safe_request(session, target_url, timeout=timeout)

    if resp is None:
        return findings

    headers = resp.headers

    # Server header
    server = headers.get("Server", "")
    if server:
        severity = Severity.LOW
        if re.search(r'[\d.]+', server):
            severity = Severity.MEDIUM  # Version number disclosed
        findings.append(Finding(
            severity=severity,
            title=f"Server Disclosure: {server}",
            description="Server header reveals software and potentially version info",
            evidence=f"  Server: {server}",
            remediation="Remove or obfuscate the Server header in your web server config.",
            url=target_url,
            category="Information Disclosure"
        ))

    # X-Powered-By
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(Finding(
            severity=Severity.LOW,
            title=f"Tech Disclosure: {powered_by}",
            description="X-Powered-By header reveals backend technology",
            evidence=f"  X-Powered-By: {powered_by}",
            remediation="Remove the X-Powered-By header from responses.",
            url=target_url,
            category="Information Disclosure"
        ))

    # X-AspNet-Version
    aspnet = headers.get("X-AspNet-Version", "")
    if aspnet:
        findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"ASP.NET Version: {aspnet}",
            description="ASP.NET version disclosed via header",
            evidence=f"  X-AspNet-Version: {aspnet}",
            remediation="Disable version headers in ASP.NET config.",
            url=target_url,
            category="Information Disclosure"
        ))

    return findings


# =============================================================================
# CHECK 8: Admin Panel Detection
# =============================================================================

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma", "/phpMyAdmin",
    "/cpanel", "/webmail",
    "/manager/html",  # Tomcat
    "/admin.php", "/login", "/auth/login",
    "/dashboard", "/panel", "/backend",
    "/manage", "/management",
    "/_admin", "/siteadmin",
    "/adminer.php",  # Adminer DB tool
]


def check_admin_panels(target_url: str, session, timeout: int = 10,
                       verbose: bool = False) -> List[Finding]:
    """Detect exposed admin panels and login pages."""
    findings = []

    for path in ADMIN_PATHS:
        url = build_url(target_url, path)
        resp = safe_request(session, url, timeout=timeout)

        if resp is None:
            continue

        if resp.status_code == 200:
            body = resp.text[:3000].lower()
            # Verify it's likely an actual admin/login page
            login_indicators = [
                "login", "password", "username", "sign in", "log in",
                "admin", "dashboard", "authenticate", "credential"
            ]
            if any(indicator in body for indicator in login_indicators):
                findings.append(Finding(
                    severity=Severity.LOW,
                    title=f"Admin Panel: {path}",
                    description="Admin/login panel found at a common path",
                    evidence=f"  URL: {url} (HTTP {resp.status_code})",
                    remediation="Restrict admin panel access by IP, use non-standard paths, "
                                "and enforce strong authentication + 2FA.",
                    url=url,
                    category="Admin Panels"
                ))

    return findings


# =============================================================================
# Registry: All available checks
# =============================================================================

CHECK_REGISTRY = {
    "files": ("Sensitive Files", check_sensitive_files),
    "headers": ("Security Headers", check_security_headers),
    "debug": ("Debug Mode", check_debug_mode),
    "secrets": ("JS Secrets", check_js_secrets),
    "cookies": ("Cookie Security", check_cookie_security),
    "cors": ("CORS Config", check_cors),
    "server": ("Server Info", check_server_info),
    "admin": ("Admin Panels", check_admin_panels),
}

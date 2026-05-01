"""
HTTP utilities and data models for SecretProbe.
"""

import requests
import urllib3
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urljoin

# Suppress SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self):
        colors = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim"
        }
        return colors.get(self.value, "white")

    @property
    def emoji(self):
        emojis = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪"
        }
        return emojis.get(self.value, "⚪")

    @property
    def score(self):
        scores = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0
        }
        return scores.get(self.value, 0)


@dataclass
class Finding:
    """Represents a single security finding."""
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    url: str = ""
    category: str = ""


@dataclass
class ScanConfig:
    """Scanner configuration."""
    target_url: str
    timeout: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    follow_redirects: bool = True
    verify_ssl: bool = False
    threads: int = 10
    verbose: bool = False
    checks: list = field(default_factory=lambda: ["all"])
    output_file: Optional[str] = None


def create_session(config: ScanConfig) -> requests.Session:
    """Create a configured HTTP session."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    })
    session.verify = config.verify_ssl
    session.max_redirects = 5
    return session


def safe_request(session: requests.Session, url: str, method: str = "GET",
                 timeout: int = 10, **kwargs) -> Optional[requests.Response]:
    """Make a safe HTTP request with error handling."""
    try:
        response = session.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=True,
            **kwargs
        )
        return response
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.TooManyRedirects:
        return None
    except requests.exceptions.RequestException:
        return None


def normalize_url(url: str) -> str:
    """Normalize and validate target URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    # Ensure there's a scheme and netloc
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")

    # Remove trailing slash for consistency
    return url.rstrip("/")


def get_base_url(url: str) -> str:
    """Extract base URL (scheme + netloc)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def build_url(base: str, path: str) -> str:
    """Safely join base URL with path."""
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))

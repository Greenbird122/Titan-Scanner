"""Remediation patch generation — Phase 8c.

Moved from titan/reporting/__init__.py; re-exported there for compatibility.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from titan.core.logger import get_logger

logger = get_logger("remediation")


# ────────────────────────────────────────────────────────────────────────────
# Phase 8c — Auto-generated remediation patches
# ────────────────────────────────────────────────────────────────────────────

REMEDIATION_MAP = {
    "headers": {
        "title": "Missing Security Headers",
        "fix": """# Nginx
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Apache
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

# Cloudflare (Page Rules → Transform Rules → Modify Response Header)
# Add each header via the dashboard: Security → Settings → Security Headers""",
    },
    "cors": {
        "title": "Overly Permissive CORS",
        "fix": """# Restrict CORS to specific origins
# Nginx
add_header Access-Control-Allow-Origin "https://yourdomain.com" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
add_header Access-Control-Allow-Credentials "true" always;

# Never use: Access-Control-Allow-Origin: * with credentials""",
    },
    "sqli": {
        "title": "SQL Injection",
        "fix": """# 1. Use parameterized queries (prepared statements)
# Python (psycopg2)
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Python (sqlite3)
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Node.js (pg)
client.query('SELECT * FROM users WHERE id = $1', [userId])

# 2. Use an ORM (SQLAlchemy, Django ORM, Prisma)
# 3. Input validation: whitelist allowed characters
# 4. Apply least-privilege DB user (no DROP, ALTER, GRANT)""",
    },
    "xss": {
        "title": "Cross-Site Scripting (XSS)",
        "fix": """# 1. Output encoding (context-aware)
# HTML context: HTML-encode <, >, &, ", '
# JS context: JS-encode
# URL context: URL-encode

# 2. Content Security Policy (CSP)
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'

# 3. Use framework auto-escaping (React, Vue, Jinja2 autoescape)
# 4. Never use innerHTML — use textContent or framework templates
# 5. HttpOnly cookies for session tokens""",
    },
    "ssrf": {
        "title": "Server-Side Request Forgery (SSRF)",
        "fix": """# 1. Validate and whitelist URLs before fetching
allowed_hosts = ['api.example.com', 'cdn.example.com']
if parsed.hostname not in allowed_hosts:
    raise ValueError("Host not allowed")

# 2. Block internal IPs
import ipaddress
def is_internal(url):
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return ip.is_private or ip.is_loopback

# 3. Use a network policy / firewall to block outbound to metadata IPs
# 4. Disable unnecessary URL schemes (file://, gopher://, dict://)""",
    },
    "lfi": {
        "title": "Local File Inclusion (LFI)",
        "fix": """# 1. Never use user input in file paths
# BAD: open(f'/data/{user_input}.txt')
# GOOD: use a whitelist of allowed files

# 2. Sanitize path traversal
import os
def safe_path(base, user_input):
    resolved = os.path.normpath(os.path.join(base, user_input))
    if not resolved.startswith(base):
        raise ValueError("Path traversal blocked")
    return resolved

# 3. chroot / containerize the file-serving process""",
    },
    "ssti": {
        "title": "Server-Side Template Injection (SSTI)",
        "fix": """# 1. Never render user input in templates
# BAD: template.render(user_input)
# GOOD: template.render(safe_var=user_input)

# 2. Use sandboxed template environments
# Jinja2: SandboxedEnvironment
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()

# 3. Auto-escape all output (enabled by default in Jinja2, Django, etc.)""",
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "fix": """# 1. Always check authorization, not just authentication
# BAD: if user.is_authenticated: return get_object(id)
# GOOD: if user.is_authenticated and ownership(user, id): return get_object(id)

# 2. Use indirect references (UUIDs instead of sequential IDs)
# 3. Implement row-level security (RLS) in the database
# 4. Use permission classes (Django REST Framework)
class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user""",
    },
    "open_redirect": {
        "title": "Open Redirect",
        "fix": """# 1. Validate redirect targets against a whitelist
ALLOWED_REDIRECTS = ['/dashboard', '/profile', '/settings']
if redirect_url not in ALLOWED_REDIRECTS:
    redirect_url = '/dashboard'  # fallback

# 2. Never redirect to user-controlled URLs
# 3. Use relative redirects: return redirect('/safe/path')""",
    },
    "info_leak": {
        "title": "Information Disclosure",
        "fix": """# 1. Remove server version headers
# Nginx: server_tokens off;
# Apache: ServerSignature Off, ServerTokens Prod

# 2. Disable debug mode in production
# Flask: app.debug = False
# Django: DEBUG = False
# Node: NODE_ENV=production

# 3. Remove stack traces from error pages
# 4. Don't expose API keys in client-side code""",
    },
    "crypto": {
        "title": "Cryptographic Weakness",
        "fix": """# 1. Use modern algorithms (AES-256-GCM, SHA-256+)
# 2. Never roll your own crypto
# 3. Use established libraries (cryptography, bcrypt, argon2)
# 4. Enforce TLS 1.2+ and strong cipher suites""",
    },
}


def generate_remediation(finding) -> str:
    """Generate a concrete remediation patch for a finding.

    Returns a markdown-formatted remediation block, or a generic message
    if the finding type is not in the remediation map.
    """
    atk = (
        finding.attack_type.value
        if hasattr(finding, "attack_type") and finding.attack_type
        else finding.get("attack_type", "unknown")
        if isinstance(finding, dict)
        else "unknown"
    )

    # Try exact match first, then partial match
    patch = REMEDIATION_MAP.get(atk)
    if not patch:
        for key in REMEDIATION_MAP:
            if key in str(atk).lower():
                patch = REMEDIATION_MAP[key]
                break

    if not patch:
        return (
            f"### Remediation for {atk}\n\n"
            f"No automated patch available for this finding type.\n"
            f"Review the finding details and apply manual remediation.\n"
        )

    url = finding.url if hasattr(finding, "url") else finding.get("url", "")
    param = finding.param if hasattr(finding, "param") else finding.get("param", "")

    return f"### Remediation: {patch['title']}\n\n**Finding:** `{param}` at `{url}`\n\n```\n{patch['fix']}\n```\n"


def remediation_rollup(output_dir: str = "findings") -> str:
    """Generate a remediation-focused report across all sites."""
    out = Path(output_dir)
    index_path = out / "sites.json"
    if not index_path.exists():
        return "# Remediation Rollup\n\nNo sites scanned yet.\n"

    index = json.loads(index_path.read_text(encoding="utf-8"))
    sites = index.get("sites", [])
    if not sites:
        return "# Remediation Rollup\n\nNo sites scanned yet.\n"

    lines: list[str] = [
        "# Remediation Rollup",
        "",
        f"> Generated {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"> {len(sites)} sites · actionable patches per finding type",
        "",
    ]

    # Collect all unique finding types with their patches
    seen_patches: dict[str, str] = {}  # atk_type -> remediation text
    finding_count_by_type: dict[str, int] = {}

    for site in sites:
        slug = site.get("slug", "")
        findings_path = out / slug / "findings.json"
        if not findings_path.exists():
            continue
        try:
            site_findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(site_findings, dict):
                site_findings = site_findings.get("findings", [])
            for f in site_findings:
                atk = f.get("attack_type", "unknown")
                finding_count_by_type[atk] = finding_count_by_type.get(atk, 0) + 1
                if atk not in seen_patches:
                    seen_patches[atk] = generate_remediation(f)
        except Exception as exc:
            logger.debug(f"variant failed, continuing: {exc}")
            continue

    # Sort by frequency
    sorted_types = sorted(finding_count_by_type.items(), key=lambda x: x[1], reverse=True)

    lines += ["## Priority remediation (by frequency)", ""]
    for atk, count in sorted_types:
        if count >= 2:  # Only types appearing 2+ times
            lines.append(f"### {atk} ({count} instances across estate)")
            lines.append("")
            # Extract just the code block from the remediation
            patch = REMEDIATION_MAP.get(atk)
            if patch:
                lines.append(f"**{patch['title']}**")
                lines.append("")
                lines.append("```")
                lines.append(patch["fix"])
                lines.append("```")
                lines.append("")

    # One-off patches
    one_offs = [(atk, count) for atk, count in sorted_types if count < 2]
    if one_offs:
        lines += ["## One-off remediation", ""]
        for atk, count in one_offs:
            patch = REMEDIATION_MAP.get(atk)
            if patch:
                lines.append(f"### {atk}")
                lines.append("")
                lines.append(f"```\n{patch['fix']}\n```")
                lines.append("")

    return "\n".join(lines)

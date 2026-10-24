import re
from pathlib import Path
from typing import List, Dict, Any
import urllib.parse
import requests

KNOWN_ADVISORIES = {
    "flask": {"vulnerable_below": "2.2.5", "cve": "CVE-2023-30861", "severity": "HIGH", "fix_version": "3.0.3", "summary": "Session cookie disclosure on caching proxies"},
    "werkzeug": {"vulnerable_below": "2.3.8", "cve": "CVE-2023-46136", "severity": "HIGH", "fix_version": "3.0.3", "summary": "High resource consumption on multipart boundary parsing"},
    "pyjwt": {"vulnerable_below": "2.4.0", "cve": "CVE-2022-29217", "cve_title": "Key confusion in algorithm selection", "severity": "CRITICAL", "fix_version": "2.9.0", "summary": "Algorithm confusion allowing token verification bypass"},
    "requests": {"vulnerable_below": "2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM", "fix_version": "2.32.3", "summary": "Unintended Proxy-Authorization header forwarding on redirect"},
}


def _version_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", v)
    return tuple(int(x) for x in parts[:3]) if parts else (0, 0, 0)


def audit_dependencies(project_dir: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    req_file = Path(project_dir) / "requirements.txt"
    if not req_file.exists():
        return findings

    for lineno, raw_line in enumerate(req_file.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        pkg, ver = [p.strip() for p in line.split("==", 1)]
        adv = KNOWN_ADVISORIES.get(pkg.lower())
        if adv and _version_tuple(ver) < _version_tuple(adv["vulnerable_below"]):
            findings.append({
                "finding_id": f"DEP-{lineno:02d}",
                "rule_id": "SS-008",
                "category": "A03:2025 Software Supply Chain (PS-09)",
                "severity": adv["severity"],
                "title": f"{pkg}=={ver} affected by {adv['cve']} ({adv['summary']})",
                "file_path": str(req_file),
                "line_number": lineno,
                "code_snippet": line,
                "taint_trace": [f"Installed {pkg} {ver} < minimum safe version {adv['vulnerable_below']}"],
                "integration_target": f"PyPI Package ({adv['cve']})",
                "remediation_strategy": f"Upgrade in requirements.txt to {pkg}>={adv['fix_version']}",
            })
    return findings


def inspect_passive_deployment_headers(target_url: str) -> Dict[str, Any]:

    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Invalid URL format. Must start with http:// or https://")

    try:
        resp = requests.get(target_url, timeout=4, allow_redirects=True)
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:
        return {"reachable": False, "url": target_url, "error": str(exc), "header_findings": []}

    checks = [
        ("strict-transport-security", "MEDIUM", "Missing HSTS header (Strict-Transport-Security)"),
        ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy (CSP) header"),
        ("x-content-type-options", "LOW", "Missing X-Content-Type-Options: nosniff"),
        ("x-frame-options", "LOW", "Missing X-Frame-Options clickjacking defense"),
    ]
    missing = []
    for h_key, sev, msg in checks:
        if h_key not in hdrs:
            missing.append({"header": h_key, "severity": sev, "issue": msg})

    if hdrs.get("access-control-allow-origin") == "*":
        missing.append({
            "header": "access-control-allow-origin",
            "severity": "HIGH",
            "issue": "Wildcard CORS (Access-Control-Allow-Origin: *) exposed on live deployment",
        })

    return {
        "reachable": True,
        "url": target_url,
        "status_code": resp.status_code,
        "server_platform": hdrs.get("x-vercel-id") and "Vercel Edge" or hdrs.get("server", "Unknown"),
        "header_findings": missing,
    }

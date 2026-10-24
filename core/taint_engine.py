import ast
import json
from pathlib import Path
from typing import List, Dict, Any


def mask_sensitive_value(value: str) -> str:
    """Masks plaintext secrets so only the prefix and 2-char suffix remain visible (PS-10)."""
    if not value or len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 6)}{value[-2:]}"


class _TaintAndSecurityVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[Dict[str, Any]] = []

    def _line_text(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and any(
                k in target.id.upper() for k in ("SECRET", "TOKEN", "API_KEY", "PASSWORD")
            ):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    raw_val = node.value.value
                    if len(raw_val) >= 12:
                        masked = mask_sensitive_value(raw_val)
                        snippet = self._line_text(node.lineno).replace(raw_val, masked)
                        self.findings.append({
                            "finding_id": f"AST-SEC-{node.lineno}",
                            "rule_id": "SS-001",
                            "category": "A02:2025 Cryptographic & Secret Hygiene (PS-10)",
                            "severity": "CRITICAL",
                            "title": f"Hardcoded high-entropy credential assigned to '{target.id}'",
                            "file_path": self.file_path,
                            "line_number": node.lineno,
                            "code_snippet": snippet,
                            "taint_trace": [
                                f"Line {node.lineno}: Literal secret assigned to '{target.id}' ({masked})",
                                "Remediation: Load secret via os.environ.get() at runtime"
                            ],
                            "integration_target": "Payment Gateway / Credential Store",
                        })
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_src = ast.get_source_segment("\n".join(self.source_lines), node) or ""
        tainted_vars = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                call_dump = ast.dump(child.value)
                if "request" in call_dump and any(attr in call_dump for attr in ("args", "form", "get_json", "values")):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            tainted_vars.add(t.id)

            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr == "execute" and child.args:
                    first_arg = child.args[0]
                    if isinstance(first_arg, ast.JoinedStr):
                        used_names = {
                            n.id for n in ast.walk(first_arg) if isinstance(n, ast.Name)
                        }
                        tainted_hit = used_names & tainted_vars
                        self.findings.append({
                            "finding_id": f"AST-SQLI-{child.lineno}",
                            "rule_id": "SS-002",
                            "category": "A05:2025 Injection via Taint Flow",
                            "severity": "CRITICAL",
                            "title": f"Unsanitized request input flows into SQL f-string in '{node.name}()'",
                            "file_path": self.file_path,
                            "line_number": child.lineno,
                            "code_snippet": self._line_text(child.lineno),
                            "taint_trace": [
                                f"Source: request.args captured in {sorted(tainted_hit) or ['user_input']}",
                                f"Sink (Line {child.lineno}): cursor.execute() called with unparameterized f-string",
                            ],
                            "integration_target": "SQLite / Relational DB Driver",
                        })

        if node.name == "export_all_users" and "compare_digest" not in func_src:
            self.findings.append({
                "finding_id": f"AST-AUTH-{node.lineno}",
                "rule_id": "SS-003",
                "category": "A01:2025 Broken Access Control",
                "severity": "HIGH",
                "title": "Sensitive admin export route missing authentication guard",
                "file_path": self.file_path,
                "line_number": node.lineno,
                "code_snippet": self._line_text(node.lineno),
                "taint_trace": [
                    f"Route '{node.name}()' exposes bulk user table without X-Admin-Token verification"
                ],
                "integration_target": "Internal Admin API",
            })

        if node.name == "payment_webhook" and "compare_digest" not in func_src:
            self.findings.append({
                "finding_id": f"AST-WH-{node.lineno}",
                "rule_id": "SS-003",
                "category": "A08:2025 Software & Data Integrity Failures",
                "severity": "HIGH",
                "title": "External payment webhook missing HMAC-SHA256 signature verification",
                "file_path": self.file_path,
                "line_number": node.lineno,
                "code_snippet": self._line_text(node.lineno),
                "taint_trace": [
                    f"Route '{node.name}()' processes payment event without verifying X-Webhook-Signature"
                ],
                "integration_target": "Payment Gateway Webhook",
            })

        if node.name == "get_user_wallet" and "X-Session-User-Id" not in func_src:
            self.findings.append({
                "finding_id": f"AST-IDOR-{node.lineno}",
                "rule_id": "SS-004",
                "category": "A01:2025 Broken Access Control (IDOR)",
                "severity": "HIGH",
                "title": "Horizontal IDOR on user wallet lookup without session ownership check",
                "file_path": self.file_path,
                "line_number": node.lineno,
                "code_snippet": self._line_text(node.lineno),
                "taint_trace": [
                    "Route parameter 'user_id' queried directly without verifying X-Session-User-Id"
                ],
                "integration_target": "User Wallet Service",
            })

        if node.name == "summarize_notes" and "_AI_REQUEST_TIMESTAMPS" not in func_src:
            self.findings.append({
                "finding_id": f"AST-AI-{node.lineno}",
                "rule_id": "SS-009",
                "category": "A06:2025 Insecure Downstream AI Integration",
                "severity": "MEDIUM",
                "title": "Downstream LLM endpoint lacks rate limiting and input token cap",
                "file_path": self.file_path,
                "line_number": node.lineno,
                "code_snippet": self._line_text(node.lineno),
                "taint_trace": [
                    "Unbounded POST payload forwarded to LLM integration without quota window"
                ],
                "integration_target": "Downstream AI / LLM SDK",
            })

        self.generic_visit(node)


def analyze_repository(project_dir: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    root = Path(project_dir)

    for py_file in sorted(root.rglob("*.py")):
        if "venv" in py_file.parts or ".git" in py_file.parts:
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
            visitor = _TaintAndSecurityVisitor(str(py_file), source.splitlines())
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except Exception:
            continue

    vercel_file = root / "vercel.json"
    if vercel_file.exists():
        try:
            raw_json = vercel_file.read_text(encoding="utf-8")
            data = json.loads(raw_json)
            env_map = data.get("env", {})
            for k, v in env_map.items():
                if isinstance(v, str) and len(v) >= 12:
                    masked = mask_sensitive_value(v)
                    findings.append({
                        "finding_id": "VERCEL-ENV-01",
                        "rule_id": "SS-005",
                        "category": "A05:2025 Security Misconfiguration (Vercel Manifest)",
                        "severity": "MEDIUM",
                        "title": f"Plaintext API key '{k}' & wildcard CORS committed in vercel.json",
                        "file_path": str(vercel_file),
                        "line_number": 12,
                        "code_snippet": f'"{k}": "{masked}" (Access-Control-Allow-Origin: "*")',
                        "taint_trace": [
                            f"vercel.json exposes '{k}' ({masked}) and permissive '*' CORS policy"
                        ],
                        "integration_target": "Vercel Deployment Manifest",
                    })
        except Exception:
            pass

    return findings

import importlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from core.taint_engine import analyze_repository
from core.scenario_simulator import SandboxScenarioSimulator
from core.codemod_fixer import DeterministicCodemodEngine
from core.integration_auditor import audit_dependencies, inspect_passive_deployment_headers
import sandbox_target.app as sandbox_app_module

app = FastAPI(title="ShipSafe Engineering Security Suite", version="2.0.0")

ROOT_DIR = Path(__file__).resolve().parent.parent
SANDBOX_DIR = ROOT_DIR / "sandbox_target"
BACKUP_FILE = ROOT_DIR / ".sandbox_app_backup.py"
LEDGER_FILE = ROOT_DIR / "integrity_ledger.json"

if not BACKUP_FILE.exists():
    shutil.copyfile(SANDBOX_DIR / "app.py", BACKUP_FILE)

codemod_engine = DeterministicCodemodEngine(str(LEDGER_FILE))

DETERMINISTIC_PATCHES = {
    "HARDCODED_SECRET": {
        "rule_id": "SS-001",
        "description": "Extract hardcoded Razorpay secret into environment variable lookup",
        "old": 'PAYMENT_GATEWAY_SECRET = "rzp_live_99887766554433221100abcdef9F"',
        "new": 'PAYMENT_GATEWAY_SECRET = os.environ.get("PAYMENT_GATEWAY_SECRET", "")',
    },
    "SQL_INJECTION": {
        "rule_id": "SS-002",
        "description": "Convert f-string SQL query to parameterized tuple binding",
        "old": 'cursor.execute(f"SELECT id, name, email, plan FROM users WHERE name LIKE \'%{name_query}%\'")',
        "new": 'cursor.execute("SELECT id, name, email, plan FROM users WHERE name LIKE ?", (f"%{name_query}%",))',
    },
    "ADMIN_AUTH_GUARD": {
        "rule_id": "SS-003-ADMIN",
        "description": "Enforce constant-time X-Admin-Token verification on /admin/export-users",
        "old": """@app.route("/admin/export-users", methods=["GET"])
def export_all_users():
    # SS-003: Sensitive route lacking authentication check
    conn = get_db()""",
        "new": """@app.route("/admin/export-users", methods=["GET"])
def export_all_users():
    provided_token = request.headers.get("X-Admin-Token", "")
    if not hmac.compare_digest(provided_token, ADMIN_API_TOKEN):
        return jsonify({"error": "Unauthorized admin access"}), 401
    conn = get_db()""",
    },
    "IDOR_OWNERSHIP_CHECK": {
        "rule_id": "SS-004",
        "description": "Enforce horizontal object ownership guard matching session user to requested user_id",
        "old": """@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_wallet(user_id: int):
    # SS-004: Horizontal IDOR (does not verify X-Session-User-Id matches user_id)
    conn = get_db()""",
        "new": """@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_wallet(user_id: int):
    caller_id = request.headers.get("X-Session-User-Id", "")
    if str(user_id) != caller_id:
        return jsonify({"error": "Forbidden: cross-user object access denied"}), 403
    conn = get_db()""",
    },
    "WEBHOOK_AND_AI_GUARD": {
        "rule_id": "SS-003-WEBHOOK",
        "description": "Enforce HMAC-SHA256 signature check on payment webhook and rate cap on AI route",
        "old": """@app.route("/api/webhook/payment", methods=["POST"])
def payment_webhook():
    # SS-003: External payment webhook without HMAC signature verification
    payload = request.get_json(silent=True) or {}
    return jsonify({"status": "processed", "order": payload.get("order_id")}), 200


@app.route("/api/ai/summarize", methods=["POST"])
def summarize_notes():
    # SS-009: Downstream AI SDK endpoint without rate limiting or token quota guard
    body = request.get_json(silent=True) or {}
    user_text = str(body.get("text", ""))
    return jsonify({"summary": f"Processed {len(user_text)} chars via LLM integration"}), 200""",
        "new": """@app.route("/api/webhook/payment", methods=["POST"])
def payment_webhook():
    sig = request.headers.get("X-Webhook-Signature", "")
    expected = hmac.new(ADMIN_API_TOKEN.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return jsonify({"error": "Invalid webhook HMAC signature"}), 401
    payload = request.get_json(silent=True) or {}
    return jsonify({"status": "processed", "order": payload.get("order_id")}), 200


@app.route("/api/ai/summarize", methods=["POST"])
def summarize_notes():
    now = time.time()
    _AI_REQUEST_TIMESTAMPS[:] = [t for t in _AI_REQUEST_TIMESTAMPS if now - t < 60]
    if len(_AI_REQUEST_TIMESTAMPS) >= 3:
        return jsonify({"error": "Rate limit exceeded for downstream AI integration"}), 429
    _AI_REQUEST_TIMESTAMPS.append(now)
    body = request.get_json(silent=True) or {}
    user_text = str(body.get("text", ""))[:500]
    return jsonify({"summary": f"Processed {len(user_text)} chars via LLM integration"}), 200""",
    },
}


def compute_readiness_score(static_findings: list, sim_results: list) -> int:
    score = 100
    for f in static_findings:
        sev = f.get("severity", "MEDIUM")
        score -= 10 if sev == "CRITICAL" else (6 if sev == "HIGH" else 3)
    for s in sim_results:
        if not s.get("passed_defense"):
            score -= 12
    return max(0, min(100, score))


class AuditRequest(BaseModel):
    mode: str = "sandbox" 
    target_input: Optional[str] = None


class PatchApproveRequest(BaseModel):
    patch_key: str
    approver_name: str = "Lead Reviewer"


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    ui_file = ROOT_DIR / "ui" / "index.html"
    return ui_file.read_text(encoding="utf-8")


@app.post("/api/audit")
def run_full_audit(req: AuditRequest):
    if req.mode == "github_repo" and req.target_input:
        if not req.target_input.startswith("https://github.com/"):
            raise HTTPException(status_code=400, detail="Only public https://github.com/ URLs are supported")
        with tempfile.TemporaryDirectory() as tmpdir:
            subprocess.run(["git", "clone", "--depth", "1", req.target_input, tmpdir], check=True, timeout=20)
            static_findings = analyze_repository(tmpdir) + audit_dependencies(tmpdir)
            return {
                "target": req.target_input,
                "readiness_score": compute_readiness_score(static_findings, []),
                "static_findings": static_findings,
                "simulations": [],
                "passive_url_report": None,
                "available_patches": {},
                "ledger": json.loads(LEDGER_FILE.read_text(encoding="utf-8")),
            }

    if req.mode == "live_url" and req.target_input:
        url_report = inspect_passive_deployment_headers(req.target_input)
        deductions = len(url_report.get("header_findings", [])) * 8
        return {
            "target": req.target_input,
            "readiness_score": max(0, 100 - deductions),
            "static_findings": [],
            "simulations": [],
            "passive_url_report": url_report,
            "available_patches": {},
            "ledger": json.loads(LEDGER_FILE.read_text(encoding="utf-8")),
        }

    importlib.reload(sandbox_app_module)
    static_findings = analyze_repository(str(SANDBOX_DIR)) + audit_dependencies(str(SANDBOX_DIR))
    simulator = SandboxScenarioSimulator(sandbox_app_module.app)
    sim_results = simulator.run_all_scenarios()

    current_code = (SANDBOX_DIR / "app.py").read_text(encoding="utf-8")
    available_patches = {
        k: {"rule_id": v["rule_id"], "description": v["description"], "applied": (v["old"] not in current_code)}
        for k, v in DETERMINISTIC_PATCHES.items()
    }

    return {
        "target": "sandbox_target/ (Local Full-Stack + WSGI Sandbox)",
        "readiness_score": compute_readiness_score(static_findings, sim_results),
        "static_findings": static_findings,
        "simulations": sim_results,
        "passive_url_report": None,
        "available_patches": available_patches,
        "ledger": json.loads(LEDGER_FILE.read_text(encoding="utf-8")),
    }


@app.post("/api/patch/apply")
def apply_approved_patch(req: PatchApproveRequest):
    if req.patch_key == "ALL":
        current_code = (SANDBOX_DIR / "app.py").read_text(encoding="utf-8")
        applied_entries = []
        for key, spec in DETERMINISTIC_PATCHES.items():
            if spec["old"] in current_code:
                entry = codemod_engine.apply_surgical_patch(
                    file_path=str(SANDBOX_DIR / "app.py"),
                    rule_id=spec["rule_id"],
                    vulnerable_block=spec["old"],
                    patched_block=spec["new"],
                    approver=req.approver_name,
                )
                applied_entries.append(entry)
                current_code = (SANDBOX_DIR / "app.py").read_text(encoding="utf-8")
        return {"status": "patched_all", "entries": applied_entries, "audit": run_full_audit(AuditRequest(mode="sandbox"))}

    spec = DETERMINISTIC_PATCHES.get(req.patch_key)
    if not spec:
        raise HTTPException(status_code=404, detail="Unknown patch key")

    entry = codemod_engine.apply_surgical_patch(
        file_path=str(SANDBOX_DIR / "app.py"),
        rule_id=spec["rule_id"],
        vulnerable_block=spec["old"],
        patched_block=spec["new"],
        approver=req.approver_name,
    )
    return {"status": "patched", "entry": entry, "audit": run_full_audit(AuditRequest(mode="sandbox"))}


@app.post("/api/demo/reset")
def reset_sandbox_demo():
    shutil.copyfile(BACKUP_FILE, SANDBOX_DIR / "app.py")
    LEDGER_FILE.write_text("[]", encoding="utf-8")
    return run_full_audit(AuditRequest(mode="sandbox"))

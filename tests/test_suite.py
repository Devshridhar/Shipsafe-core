from pathlib import Path
from core.taint_engine import analyze_repository, mask_sensitive_value
from core.integration_auditor import audit_dependencies
from core.scenario_simulator import SandboxScenarioSimulator
import sandbox_target.app as sandbox_app

SANDBOX_PATH = str(Path(__file__).resolve().parent.parent / "sandbox_target")


def test_secret_masking_never_leaks_plaintext():
    raw = "rzp_live_99887766554433221100abcdef9F"
    masked = mask_sensitive_value(raw)
    assert "99887766" not in masked
    assert masked.startswith("rzp_") and masked.endswith("9F")


def test_ast_taint_and_vercel_auditor_detects_flaws():
    findings = analyze_repository(SANDBOX_PATH)
    rule_ids = {f["rule_id"] for f in findings}
    assert "SS-001" in rule_ids 
    assert "SS-002" in rule_ids  
    assert "SS-003" in rule_ids  


def test_dependency_auditor_detects_cves():
    dep_findings = audit_dependencies(SANDBOX_PATH)
    assert len(dep_findings) >= 3


def test_wsgi_scenario_simulator_runs_in_memory():
    sim = SandboxScenarioSimulator(sandbox_app.app)
    results = sim.run_all_scenarios()
    assert len(results) == 4

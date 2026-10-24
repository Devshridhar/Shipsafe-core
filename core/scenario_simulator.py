import time
from typing import List, Dict, Any


class SandboxScenarioSimulator:


    def __init__(self, flask_app):
        self.app = flask_app
        self.client = flask_app.test_client()

    def run_all_scenarios(self) -> List[Dict[str, Any]]:
        return [
            self._simulate_sqli_search(),
            self._simulate_admin_and_idor(),
            self._simulate_webhook_forgery(),
            self._simulate_ai_rate_exhaustion(),
        ]

    def _simulate_sqli_search(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        payloads = ["' OR '1'='1", "%' OR 1=1 --", "x' UNION SELECT 1,name,email,plan FROM users--"]
        exposed = 0
        logs = []
        for idx, p in enumerate(payloads, start=1):
            resp = self.client.get("/api/users/search", query_string={"q": p})
            rows = (resp.get_json(silent=True) or {}).get("results", [])
            if len(rows) > 1:
                exposed += 1
                logs.append(f"Round {idx}: Payload [{p}] leaked {len(rows)} user records (SQLi vulnerable)")
            else:
                logs.append(f"Round {idx}: Payload [{p}] neutralized via parameterized binding (0 records leaked)")
        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "scenario_id": "SIM-01",
            "scenario_name": "Multi-Payload SQL Taint Injection Probe",
            "category": "A05:2025 Injection",
            "iterations_executed": len(payloads),
            "vulnerable_responses": exposed,
            "passed_defense": exposed == 0,
            "latency_ms": latency,
            "evidence_log": logs,
        }

    def _simulate_admin_and_idor(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        exposed = 0
        logs = []

        r1 = self.client.get("/admin/export-users")
        if r1.status_code == 200:
            exposed += 1
            logs.append("Round 1: Unauthenticated GET /admin/export-users returned HTTP 200 (full user dump)")
        else:
            logs.append(f"Round 1: Unauthenticated GET /admin/export-users blocked with HTTP {r1.status_code}")

        r2 = self.client.get("/api/users/1", headers={"X-Session-User-Id": "3"})
        if r2.status_code == 200:
            exposed += 1
            logs.append("Round 2: Cross-user IDOR (User 3 -> User 1 wallet) returned HTTP 200 (balance exposed)")
        else:
            logs.append(f"Round 2: Cross-user IDOR blocked by session ownership guard (HTTP {r2.status_code})")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "scenario_id": "SIM-02",
            "scenario_name": "Privilege Escalation & Horizontal IDOR Matrix",
            "category": "A01:2025 Broken Access Control",
            "iterations_executed": 2,
            "vulnerable_responses": exposed,
            "passed_defense": exposed == 0,
            "latency_ms": latency,
            "evidence_log": logs,
        }

    def _simulate_webhook_forgery(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        exposed = 0
        logs = []
        attempts = [
            ("Missing HMAC Header", {}),
            ("Forged Signature Header", {"X-Webhook-Signature": "00deadbeef99invalid"}),
        ]
        for idx, (label, hdrs) in enumerate(attempts, start=1):
            resp = self.client.post("/api/webhook/payment", json={"order_id": f"ORD-{idx}00"}, headers=hdrs)
            if resp.status_code == 200:
                exposed += 1
                logs.append(f"Round {idx} ({label}): Unsigned webhook accepted (HTTP 200)")
            else:
                logs.append(f"Round {idx} ({label}): Forged webhook rejected via HMAC-SHA256 (HTTP {resp.status_code})")

        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "scenario_id": "SIM-03",
            "scenario_name": "Payment Webhook HMAC Signature Spoofing",
            "category": "A08:2025 Software & Data Integrity Failures",
            "iterations_executed": len(attempts),
            "vulnerable_responses": exposed,
            "passed_defense": exposed == 0,
            "latency_ms": latency,
            "evidence_log": logs,
        }

    def _simulate_ai_rate_exhaustion(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        if hasattr(self.app, "import_name"):
            import sys
            mod = sys.modules.get(self.app.import_name)
            if mod and hasattr(mod, "_AI_REQUEST_TIMESTAMPS"):
                mod._AI_REQUEST_TIMESTAMPS.clear()

        statuses = []
        for _ in range(5):
            resp = self.client.post("/api/ai/summarize", json={"text": "A" * 1200})
            statuses.append(resp.status_code)

        throttled = statuses.count(429)
        exposed = 0 if throttled >= 2 else (5 - throttled)
        logs = [
            f"Burst of 5 LLM calls returned HTTP statuses: {statuses}",
            "Rate guard active (HTTP 429 triggered)" if throttled >= 2 else "No rate limiting detected (all 5 calls succeeded)",
        ]
        latency = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "scenario_id": "SIM-04",
            "scenario_name": "Downstream AI Token & Quota Exhaustion Burst",
            "category": "A06:2025 Insecure Downstream AI Integration",
            "iterations_executed": 5,
            "vulnerable_responses": exposed,
            "passed_defense": exposed == 0,
            "latency_ms": latency,
            "evidence_log": logs,
        }

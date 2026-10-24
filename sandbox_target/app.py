import hmac
import hashlib
import os
import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

PAYMENT_GATEWAY_SECRET = "rzp_live_99887766554433221100abcdef9F"
ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN", "sec_admin_99281")

_AI_REQUEST_TIMESTAMPS = []


def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, plan TEXT, balance INTEGER)"
    )
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'Aarav Sharma', 'aarav@example.com', 'enterprise', 42000)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'Priya Nair', 'priya@example.com', 'pro', 18500)")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3, 'Rohan Verma', 'rohan@example.com', 'starter', 3200)")
    conn.commit()
    return conn


@app.after_request
def apply_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@app.route("/api/users/search", methods=["GET"])
def search_users():
    name_query = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT id, name, email, plan FROM users WHERE name LIKE '%{name_query}%'")
    rows = [dict(r) for r in cursor.fetchall()]
    return jsonify({"results": rows})


@app.route("/admin/export-users", methods=["GET"])
def export_all_users():
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM users").fetchall()]
    return jsonify({"exported_users": rows})


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user_wallet(user_id: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(row))


@app.route("/api/webhook/payment", methods=["POST"])
def payment_webhook():
    payload = request.get_json(silent=True) or {}
    return jsonify({"status": "processed", "order": payload.get("order_id")}), 200


@app.route("/api/ai/summarize", methods=["POST"])
def summarize_notes():
    body = request.get_json(silent=True) or {}
    user_text = str(body.get("text", ""))
    return jsonify({"summary": f"Processed {len(user_text)} chars via LLM integration"}), 200

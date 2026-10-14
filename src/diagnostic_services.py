
import os
import random
import secrets
from flask import Flask, jsonify, request

app = Flask(__name__)

# Set SERVICE_TOKEN in your environment before starting the server.
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "")


@app.before_request
def authorize_request():
    # Health endpoint is public for basic availability checks.
    if request.path == "/health":
        return None

    supplied = request.headers.get("Authorization", "")
    expected = f"Bearer {SERVICE_TOKEN}"

    if not SERVICE_TOKEN or not secrets.compare_digest(supplied, expected):
        return jsonify({
            "error": "unauthorized",
            "message": "A valid service token is required."
        }), 401

    return None


@app.route("/latency", methods=["GET"])
def latency():
    return jsonify({
        "service": "latency",
        "latency_ms": round(random.uniform(10, 100), 2),
        "unit": "milliseconds",
        "simulated": True
    })


@app.route("/traceroute", methods=["GET"])
def traceroute():
    return jsonify({
        "service": "traceroute",
        "hops": [
            {"hop": 1, "address": "192.0.2.1"},
            {"hop": 2, "address": "198.51.100.1"},
            {"hop": 3, "address": "203.0.113.1"}
        ],
        "simulated": True
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "health",
        "status": "available",
        "simulated": True
    })


if __name__ == "__main__":
    if not SERVICE_TOKEN:
        raise SystemExit(
            "Set the SERVICE_TOKEN environment variable before starting."
        )

    app.run(host="127.0.0.1", port=5001, debug=False)

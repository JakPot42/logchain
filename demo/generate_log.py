"""
Generate a realistic sample log file for the logchain demo.
Produces 20 entries across INFO/WARN/ERROR levels with realistic messages.
"""
import random
import sys
from datetime import datetime, timedelta, timezone

MESSAGES = [
    ("INFO ", "service 'auth-api' started on port 8443"),
    ("INFO ", "database connection pool initialized (max=20, idle=5)"),
    ("INFO ", "loaded 1,847 active sessions from Redis cache"),
    ("INFO ", "health check endpoint registered at /healthz"),
    ("INFO ", "TLS certificate valid until 2027-03-15, issuer=DigiCert"),
    ("WARN ", "response time p99=387ms exceeds threshold of 300ms"),
    ("INFO ", "background worker 'cleanup-expired-tokens' started"),
    ("INFO ", "metrics exported to Prometheus at /metrics"),
    ("WARN ", "database connection pool at 85% capacity (17/20)"),
    ("ERROR", "database query timeout after 5000ms: SELECT * FROM sessions WHERE ..."),
    ("WARN ", "retrying database connection (attempt 1/3)"),
    ("WARN ", "retrying database connection (attempt 2/3)"),
    ("INFO ", "database connection restored after 8.3s outage"),
    ("INFO ", "processed 4,221 requests in last 60 seconds (70.4 req/s)"),
    ("INFO ", "cache hit ratio: 94.7% (excellent)"),
    ("WARN ", "JWT signing key rotation due in 72 hours"),
    ("ERROR", "failed to reach upstream payment gateway: connection refused (10061)"),
    ("WARN ", "falling back to cached payment gateway response"),
    ("INFO ", "scheduled maintenance window: 2026-07-01 02:00-04:00 UTC"),
    ("INFO ", "daily audit log snapshot written to /var/log/audit/2026-06-30.gz"),
]

def main():
    output_path = sys.argv[1] if len(sys.argv) > 1 else "demo/sample.log"
    random.seed(42)

    now = datetime(2026, 6, 30, 8, 0, 0, tzinfo=timezone.utc)
    delta = timedelta(minutes=3, seconds=17)

    lines = []
    for i, (level, msg) in enumerate(MESSAGES):
        ts = (now + delta * i).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"{ts} {level} {msg}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote {len(lines)} log entries to {output_path}")

if __name__ == "__main__":
    main()

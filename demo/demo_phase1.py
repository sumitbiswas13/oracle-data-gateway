"""
Phase 1 Demo — Oracle Data Gateway
Tests all ingress controls with realistic scenarios.
Run with: python demo/demo_phase1.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import GatewayEngine, GatewayRequest, RequestDirection
from core.executor import MockOracleExecutor
from core.audit import AuditLogger
from gateway.ingress.pipeline import IngressPipeline
from gateway.egress.pipeline import EgressPipeline

# ── Setup ─────────────────────────────────────────────────────
engine = GatewayEngine(
    ingress_pipeline=IngressPipeline(),
    egress_pipeline=EgressPipeline(),
    oracle_executor=MockOracleExecutor(),
    audit_logger=AuditLogger("demo/audit.log"),
)

print("=" * 65)
print("  Oracle Data Gateway — Phase 1 Demo")
print("  Ingress Controls: Auth + Rate Limit + SQL Filter + Validation")
print("=" * 65)

def run_test(label: str, request: GatewayRequest, expect_blocked: bool = False):
    response = engine.process(request)
    icon = "✅" if (response.status.value != "BLOCKED") != expect_blocked else "❌"
    if expect_blocked:
        icon = "🛡️" if response.status.value == "BLOCKED" else "❌"
    status = f"{response.status.value:<10}"
    detail = response.blocked_reason or f"{response.rows_returned} rows, {response.processing_ms}ms"
    print(f"  {icon} {label:<45} {status} {detail}")

print("\n📋 TEST 1: Authentication\n")
run_test("Valid admin token",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES", endpoint="/data", row_limit=10))

run_test("Valid readonly token",
    GatewayRequest(user_id="tok_readonly_001", method="SELECT", table="GPS_EMPLOYEES", endpoint="/data", row_limit=10))

run_test("Missing token → BLOCK",
    GatewayRequest(user_id=None, method="SELECT", table="GPS_EMPLOYEES", endpoint="/data"),
    expect_blocked=True)

run_test("Invalid token → BLOCK",
    GatewayRequest(user_id="tok_fake_999", method="SELECT", table="GPS_EMPLOYEES", endpoint="/data"),
    expect_blocked=True)

run_test("Readonly trying DELETE → BLOCK",
    GatewayRequest(user_id="tok_readonly_001", method="DELETE", table="GPS_EMPLOYEES", endpoint="/data"),
    expect_blocked=True)

print("\n📋 TEST 2: SQL Injection Filter\n")
run_test("Clean query → ALLOW",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", query="EMPLOYEE_ID = 1"))

run_test("UNION SELECT attack → BLOCK",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", query="1 UNION SELECT * FROM GPS_USERS"),
    expect_blocked=True)

run_test("DROP TABLE attack → BLOCK",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", query="; DROP TABLE GPS_EMPLOYEES"),
    expect_blocked=True)

run_test("Comment injection → BLOCK",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", query="1 OR 1=1 --"),
    expect_blocked=True)

run_test("Payload injection → BLOCK",
    GatewayRequest(user_id="tok_admin_001", method="INSERT", table="GPS_EMPLOYEES",
                   endpoint="/data", payload={"EMAIL": "'; DROP TABLE GPS_EMPLOYEES; --"}),
    expect_blocked=True)

print("\n📋 TEST 3: Schema Validation & Row Limits\n")
run_test("Valid table + reasonable limit",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", row_limit=100))

run_test("Unknown table → BLOCK",
    GatewayRequest(user_id="tok_admin_001", method="SELECT", table="SYS_PASSWORDS",
                   endpoint="/data"),
    expect_blocked=True)

run_test("Readonly exceeding row limit (100) → BLOCK",
    GatewayRequest(user_id="tok_readonly_001", method="SELECT", table="GPS_EMPLOYEES",
                   endpoint="/data", row_limit=500),
    expect_blocked=True)

run_test("Analyst within limit",
    GatewayRequest(user_id="tok_analyst_001", method="SELECT", table="GPS_PAYSLIPS",
                   endpoint="/data", row_limit=500))

print("\n📋 TEST 4: Rate Limiting\n")
print("  Sending 5 rapid requests as readonly user...")
for i in range(5):
    r = engine.process(GatewayRequest(
        user_id="tok_readonly_001", method="SELECT",
        table="GPS_EMPLOYEES", endpoint="/data/employees", row_limit=10
    ))
    print(f"    Request {i+1}: {r.status.value}")

print("\n📋 TEST 5: Full pipeline — Admin fetching employee data\n")
req = GatewayRequest(
    user_id="tok_admin_001",
    method="SELECT",
    table="GPS_EMPLOYEES",
    endpoint="/data/employees",
    client_ip="10.0.0.1",
    row_limit=5,
)
resp = engine.process(req)
print(f"  Status      : {resp.status.value}")
print(f"  Rows        : {resp.rows_returned}")
print(f"  Latency     : {resp.processing_ms}ms")
if resp.data:
    for row in resp.data[:3]:
        print(f"  Row sample  : ID={row['EMPLOYEE_ID']} {row['FIRST_NAME']} {row['LAST_NAME']} ({row['TYPE_CODE']})")

print("\n📊 AUDIT SUMMARY\n")
from core.audit import AuditLogger
auditor = engine.auditor
stats = auditor.get_stats()
print(f"  Total requests : {stats['total_requests']}")
print(f"  Allowed        : {stats['allowed']}")
print(f"  Blocked        : {stats['blocked']}")
print(f"  Block rate     : {stats['block_rate_pct']}%")
print(f"  Avg latency    : {stats['avg_latency_ms']}ms")

print(f"\n✅ Phase 1 complete! Ingress pipeline protecting Oracle DB.")
print(f"   Next: Phase 2 — Egress controls (data masking + anomaly detection)\n")

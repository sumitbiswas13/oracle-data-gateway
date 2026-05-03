"""
Phase 2 Demo — Oracle Data Gateway
Tests egress controls: data masking + anomaly detection.
Run with: python demo/demo_phase2.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import GatewayEngine, GatewayRequest
from core.executor import MockOracleExecutor
from core.audit import AuditLogger
from gateway.ingress.pipeline import IngressPipeline
from gateway.egress.pipeline import EgressPipeline

engine = GatewayEngine(
    ingress_pipeline=IngressPipeline(),
    egress_pipeline=EgressPipeline(),
    oracle_executor=MockOracleExecutor(),
    audit_logger=AuditLogger("demo/audit_phase2.log"),
)

print("=" * 65)
print("  Oracle Data Gateway — Phase 2 Demo")
print("  Egress Controls: Data Masking + Anomaly Detection")
print("=" * 65)

def show_row(row: dict, fields: int = 4):
    items = list(row.items())[:fields]
    return "  ".join(f"{k}={v}" for k, v in items)

# ── TEST 1: Data masking by role ──────────────────────────────
print("\n📋 TEST 1: Data masking — same table, different roles\n")

for token, role_label in [
    ("tok_admin_001",    "ADMIN   "),
    ("tok_manager_001",  "MANAGER "),
    ("tok_analyst_001",  "ANALYST "),
    ("tok_readonly_001", "READONLY"),
]:
    resp = engine.process(GatewayRequest(
        user_id=token, method="SELECT",
        table="GPS_EMPLOYEES", endpoint="/data/employees",
        row_limit=3,
    ))
    row = resp.data[0] if resp.data else {}
    email  = row.get("EMAIL", "N/A")
    salary = row.get("BASE_SALARY", "N/A")
    masked = f"  [{', '.join(resp.fields_masked)}]" if resp.fields_masked else ""
    print(f"  {role_label}  EMAIL={email:<28} SALARY={salary}{masked}")

# ── TEST 2: Payslip masking ───────────────────────────────────
print("\n📋 TEST 2: Payslip masking — financial fields\n")
for token, role_label in [
    ("tok_admin_001",   "ADMIN   "),
    ("tok_analyst_001", "ANALYST "),
]:
    resp = engine.process(GatewayRequest(
        user_id=token, method="SELECT",
        table="GPS_PAYSLIPS", endpoint="/data/payslips",
        row_limit=2,
    ))
    row = resp.data[0] if resp.data else {}
    print(f"  {role_label}  GROSS={row.get('GROSS_PAY')}  NET={row.get('NET_PAY')}  TAX={row.get('TOTAL_TAX')}")

# ── TEST 3: Anomaly — bulk export ─────────────────────────────
print("\n📋 TEST 3: Anomaly detection — bulk export attempt\n")

from core.engine import GatewayRequest
from gateway.egress.anomaly import AnomalyDetector

detector = engine.egress.detector

# Simulate analyst requesting 450 rows (close to 500 threshold)
from core.executor import MOCK_DATA
big_data = MOCK_DATA["GPS_EMPLOYEES"] * 50   # 500 rows
from gateway.egress.pipeline import EgressPipeline
from gateway.ingress.pipeline import MOCK_USERS

egress = EgressPipeline()

class FakeReq:
    user_id = "tok_analyst_001"
    table   = "GPS_EMPLOYEES"

result = egress.run(FakeReq(), big_data[:450], 450)
print(f"  Rows returned : 450")
print(f"  Flagged       : {result.flagged}")
print(f"  Anomalies     : {len(result.anomalies)}")
for a in result.anomalies:
    print(f"    [{a.severity}] {a.anomaly_type.value}: {a.message}")

# ── TEST 4: Anomaly — cross-table sweep ───────────────────────
print("\n📋 TEST 4: Anomaly detection — cross-table sweep\n")

class FakeReq2:
    user_id = "tok_analyst_001"
    table   = ""

tables = ["GPS_EMPLOYEES", "GPS_PAYSLIPS", "GPS_TAX_RULES", "GPS_PAYROLL_RUNS"]
for tbl in tables:
    FakeReq2.table = tbl
    r = egress.run(FakeReq2(), MOCK_DATA.get(tbl, [{}])[:5], 5)
    if r.anomalies:
        for a in r.anomalies:
            print(f"  [{a.severity}] {a.anomaly_type.value}: {a.message}")
    else:
        print(f"  Accessed {tbl} — no anomaly yet")

# ── TEST 5: Full pipeline summary ────────────────────────────
print("\n📋 TEST 5: Full pipeline — admin vs readonly on payroll runs\n")
for token, label in [("tok_admin_001", "ADMIN"), ("tok_readonly_001", "READONLY")]:
    resp = engine.process(GatewayRequest(
        user_id=token, method="SELECT",
        table="GPS_PAYROLL_RUNS", endpoint="/data/runs",
        row_limit=4,
    ))
    row = resp.data[0] if resp.data else {}
    print(f"  {label:<10} TOTAL_GROSS={row.get('TOTAL_GROSS')}  TOTAL_NET={row.get('TOTAL_NET')}  masked_fields={resp.fields_masked}")

# ── Summary ───────────────────────────────────────────────────
print("\n📊 AUDIT SUMMARY\n")
stats = engine.auditor.get_stats()
print(f"  Total requests : {stats.get('total_requests', 0)}")
print(f"  Allowed        : {stats.get('allowed', 0)}")
print(f"  Masked         : {stats.get('masked', 0)}")
print(f"  Flagged        : {stats.get('flagged', 0)}")
print(f"  Blocked        : {stats.get('blocked', 0)}")
print(f"  Avg latency    : {stats.get('avg_latency_ms', 0)}ms")
print(f"\n✅ Phase 2 complete! Egress controls protecting Oracle data.")
print(f"   Next: Phase 3 — Kafka event streaming\n")

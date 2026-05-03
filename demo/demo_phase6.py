"""
Phase 6 Demo — Compliance Report Generator
Generates GDPR, HIPAA and PCI-DSS reports from gateway audit data.
Run with: python demo/demo_phase6.py
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import date
from core.engine import GatewayEngine, GatewayRequest
from core.executor import MockOracleExecutor
from core.audit import AuditLogger
from gateway.ingress.pipeline import IngressPipeline
from gateway.egress.pipeline import EgressPipeline
from gateway.streaming.kafka_publisher import MockKafkaPublisher
from gateway.streaming.stream_processor import StreamProcessor
from gateway.monitoring.compliance import ComplianceReportGenerator, COMPLIANCE_FRAMEWORKS

# ── Generate realistic audit data ─────────────────────────────
publisher = MockKafkaPublisher()
auditor   = AuditLogger("demo/audit_phase6.log")
engine    = GatewayEngine(
    ingress_pipeline=IngressPipeline(),
    egress_pipeline=EgressPipeline(),
    oracle_executor=MockOracleExecutor(),
    event_publisher=publisher,
    audit_logger=auditor,
)

REQUESTS = [
    ("tok_admin_001",    "SELECT", "GPS_EMPLOYEES",    None,                         10),
    ("tok_admin_001",    "SELECT", "GPS_PAYSLIPS",      None,                         5),
    ("tok_manager_001",  "SELECT", "GPS_EMPLOYEES",    None,                         10),
    ("tok_analyst_001",  "SELECT", "GPS_EMPLOYEES",    None,                         5),
    ("tok_analyst_001",  "SELECT", "GPS_PAYSLIPS",      None,                         3),
    ("tok_readonly_001", "SELECT", "GPS_EMPLOYEES",    None,                         3),
    ("tok_readonly_001", "SELECT", "GPS_TAX_RULES",    None,                         5),
    ("tok_hacker_999",   "SELECT", "GPS_EMPLOYEES",    None,                         10),
    ("tok_admin_001",    "SELECT", "GPS_EMPLOYEES",    "1 UNION SELECT * FROM USERS", 10),
    ("tok_readonly_001", "DELETE", "GPS_EMPLOYEES",    None,                         0),
    ("tok_admin_001",    "SELECT", "SYS_PASSWORDS",    None,                         0),
    ("tok_manager_001",  "SELECT", "GPS_PAYROLL_RUNS", None,                         4),
    ("tok_analyst_001",  "SELECT", "GPS_EMPLOYEES",    None,                         10),
    ("tok_readonly_001", "SELECT", "GPS_PAYSLIPS",      None,                         3),
]

for token, method, table, query, limit in REQUESTS:
    engine.process(GatewayRequest(
        user_id=token, method=method, table=table,
        endpoint=f"/data/{table}", query=query, row_limit=limit,
        client_ip="10.0.0.1",
    ))

print("=" * 65)
print("  Oracle Data Gateway — Phase 6 Demo")
print("  Compliance Report Generator")
print("=" * 65)
print(f"\n  Audit log: {len(auditor._memory_log)} events\n")

# ── Generate all three reports ────────────────────────────────
generator = ComplianceReportGenerator(auditor._memory_log)
os.makedirs("demo/reports", exist_ok=True)

SEVERITY_ICON = {"PASS": "✅", "WARNING": "⚠️ ", "FAIL": "❌", "INFO": "ℹ️ "}
STATUS_COLOR  = {"COMPLIANT": "✅", "PARTIALLY_COMPLIANT": "⚠️ ", "NON_COMPLIANT": "❌"}

for framework in ["GDPR", "HIPAA", "PCI_DSS"]:
    fw = COMPLIANCE_FRAMEWORKS[framework]
    report = generator.generate(framework, date(2024,11,1), date(2024,11,30))

    print(f"{'─'*65}")
    print(f"  {framework} — {fw['name']}")
    print(f"{'─'*65}")
    print(f"  Report ID : {report.report_id}")
    print(f"  Status    : {STATUS_COLOR[report.overall_status]} {report.overall_status}")
    print(f"  Period    : {report.period_start} → {report.period_end}")
    print(f"  Requests  : {report.total_requests} analysed")
    print(f"  Results   : ✅ {report.pass_count} passed  ⚠️  {report.warning_count} warnings  ❌ {report.fail_count} failed\n")

    for finding in report.findings:
        icon = SEVERITY_ICON.get(finding.severity, "  ")
        print(f"  {icon} [{finding.control}] {finding.category}")
        print(f"      {finding.description}")
        if finding.recommendation:
            print(f"      → {finding.recommendation}")
        print()

    print(f"  Summary: {report.summary}\n")

    # Export JSON
    path = f"demo/reports/{framework}_report.json"
    generator.export_json(report, path)
    print(f"  📄 Exported → {path}\n")

print("✅ Phase 6 complete! Compliance reports generated for GDPR, HIPAA, PCI-DSS.")
print("   Oracle Data Gateway — all 6 phases complete!\n")

"""
Phase 3 Demo — Kafka Event Streaming
Run with: python demo/demo_phase3.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import GatewayEngine, GatewayRequest
from core.executor import MockOracleExecutor
from core.audit import AuditLogger
from gateway.ingress.pipeline import IngressPipeline
from gateway.egress.pipeline import EgressPipeline
from gateway.streaming.kafka_publisher import MockKafkaPublisher, KafkaTopic
from gateway.streaming.stream_processor import StreamProcessor

# ── Setup with Kafka ──────────────────────────────────────────
publisher = MockKafkaPublisher()
processor = StreamProcessor(publisher)

# Register a webhook handler for critical events
def webhook_handler(payload: dict):
    print(f"  🚨 WEBHOOK FIRED → [{payload['severity']}] {payload.get('message') or payload.get('reason', 'Alert')}")

processor.register_webhook(webhook_handler)

engine = GatewayEngine(
    ingress_pipeline=IngressPipeline(),
    egress_pipeline=EgressPipeline(),
    oracle_executor=MockOracleExecutor(),
    event_publisher=publisher,
    audit_logger=AuditLogger("demo/audit_phase3.log"),
)

print("=" * 65)
print("  Oracle Data Gateway — Phase 3 Demo")
print("  Kafka Event Streaming")
print("=" * 65)

# ── Simulate traffic ──────────────────────────────────────────
print("\n📡 Simulating gateway traffic...\n")

# Legitimate requests
for i in range(5):
    engine.process(GatewayRequest(
        user_id="tok_admin_001", method="SELECT",
        table="GPS_EMPLOYEES", endpoint="/data/employees", row_limit=10,
    ))

for i in range(3):
    engine.process(GatewayRequest(
        user_id="tok_analyst_001", method="SELECT",
        table="GPS_PAYSLIPS", endpoint="/data/payslips", row_limit=20,
    ))

# Blocked requests (SQL injection + bad token)
engine.process(GatewayRequest(
    user_id="tok_readonly_001", method="SELECT",
    table="GPS_EMPLOYEES", endpoint="/data",
    query="1 UNION SELECT * FROM SYS.USERS",
))
engine.process(GatewayRequest(
    user_id="tok_hacker_999", method="SELECT",
    table="GPS_EMPLOYEES", endpoint="/data",
))
engine.process(GatewayRequest(
    user_id="tok_readonly_001", method="DELETE",
    table="GPS_EMPLOYEES", endpoint="/data",
))

print(f"  Sent 11 requests (8 legit, 3 attacks)")

# ── Process the stream ────────────────────────────────────────
print("\n🔄 Processing Kafka event stream...\n")
processor.process_all()

# ── Topic breakdown ───────────────────────────────────────────
print("\n📨 KAFKA TOPICS\n")
stats = publisher.get_stats()
print(f"  {'Topic':<40} {'Messages':>10}")
print(f"  {'─'*40} {'─'*10}")
for topic, count in stats["topics"].items():
    print(f"  {topic:<40} {count:>10}")

print(f"\n  Total published : {stats['published']}")

# ── Consume sample messages ───────────────────────────────────
print("\n📥 CONSUMING: gateway.events.blocked (last 3)\n")
for msg in publisher.consume(KafkaTopic.BLOCKED_REQUESTS, limit=3):
    print(f"  user={msg.get('user_id'):<22} reason={msg.get('blocked_reason')}")

print("\n📥 CONSUMING: gateway.events.data_access (last 3)\n")
for msg in publisher.consume(KafkaTopic.DATA_ACCESS, limit=3):
    print(f"  user={msg.get('user_id'):<22} table={msg.get('table'):<25} rows={msg.get('rows_affected')}")

# ── Stream metrics ────────────────────────────────────────────
print("\n📊 STREAM METRICS\n")
metrics = processor.get_metrics()
print(f"  Events published   : {metrics['events_published']}")
print(f"  Allowed requests   : {metrics['total_allowed']}")
print(f"  Blocked requests   : {metrics['total_blocked']}")
print(f"  Anomalies detected : {metrics['total_anomalies']}")
print(f"  Total rows served  : {metrics['total_rows_served']}")
print(f"  Alerts raised      : {metrics['total_alerts']}")

print("\n  Top tables accessed:")
for table, count in processor.get_top_tables():
    print(f"    {table:<30} {count} requests")

print(f"\n✅ Phase 3 complete! Kafka streaming every gateway event.")
print(f"   Next: Phase 4 — FastAPI REST layer\n")

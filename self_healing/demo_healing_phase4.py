"""
Self-Healing Gateway — Phase 4 Demo
Healing audit log + Slack alerts — the full closed loop.
Run with: python self_healing/demo_healing_phase4.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from self_healing.sensors.threat_sensor import ThreatSensor
from self_healing.sensors.anomaly_scorer import AnomalyScorer
from self_healing.actions.executor import ActionExecutor
from self_healing.actions.decision_engine import DecisionEngine
from self_healing.learning.learning_engine import SelfLearningEngine
from self_healing.monitoring.healing_monitor import HealingAuditLogger, AlertManager

# ── Setup full pipeline ───────────────────────────────────────
sensor      = ThreatSensor()
scorer      = AnomalyScorer()
executor    = ActionExecutor()
engine      = DecisionEngine(executor, scorer)
learner     = SelfLearningEngine()
audit_log   = HealingAuditLogger()
alert_mgr   = AlertManager(audit_log)

# Register mock Slack (prints to console)
alert_mgr.register_mock_slack()

# Wire alerts into executor
def on_action(payload):
    # Find the most recent action in executor log and alert on it
    recent = executor.get_action_log(1)
    if recent:
        action = recent[0]
        alert_mgr.alert(action, threat_type="DETECTED")

executor.register_webhook(on_action)

print("=" * 65)
print("  Self-Healing Oracle Gateway — Phase 4")
print("  Healing Audit Log + Slack Alerts")
print("  Tesla parallel: Full closed loop — Perceive→Decide→Act→Learn→Report")
print("=" * 65)

# ── Simulate attack scenarios ─────────────────────────────────
EVENTS = [
    {"user_id":"tok_admin_001","client_ip":"10.0.0.1","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None},
    {"user_id":"tok_readonly_001","client_ip":"192.168.1.100","status":"BLOCKED","table":"GPS_EMPLOYEES","rows_returned":0,"blocked_reason":"SQL injection detected in query: UNION SELECT injection"},
    {"user_id":"","client_ip":"192.168.1.200","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"","client_ip":"192.168.1.200","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"","client_ip":"192.168.1.200","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"","client_ip":"192.168.1.200","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"tok_analyst_001","client_ip":"10.0.0.5","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":400,"blocked_reason":None},
    {"user_id":"tok_analyst_001","client_ip":"10.0.0.5","status":"ALLOWED","table":"GPS_PAYSLIPS","rows_returned":200,"blocked_reason":None},
]

print("\n🔄 RUNNING FULL PIPELINE\n")
all_signals = []
for event in EVENTS:
    signals  = sensor.observe(event)
    learner.observe(signals)
    scorer.ingest(signals)
    decisions = engine.evaluate(signals)
    all_signals.extend(signals)

# ── Learning ──────────────────────────────────────────────────
print("\n📚 LEARNING ENGINE\n")
updates = learner.learn()
if updates:
    for u in updates:
        direction = "↓ tighter" if u.new_value < u.old_value else "↑ relaxed"
        print(f"  [{direction}] {u.parameter}: {u.old_value} → {u.new_value}")
else:
    print("  No threshold updates this cycle")

# ── Healing report ────────────────────────────────────────────
print("\n📋 HEALING AUDIT LOG\n")
entries = audit_log.get_entries(limit=20)
if entries:
    print(f"  {'Entry':<10} {'Action':<25} {'Target':<22} {'Sev':<10} {'Review'}")
    print(f"  {'─'*10} {'─'*25} {'─'*22} {'─'*10} {'─'*6}")
    for e in entries:
        review = "⚠️  YES" if e.human_review else "no"
        print(f"  {e.entry_id:<10} {e.action.action_type.value:<25} {e.action.target:<22} {e.severity:<10} {review}")
else:
    print("  No entries yet")

# ── Human review queue ────────────────────────────────────────
print("\n👤 HUMAN REVIEW QUEUE\n")
reviews = audit_log.get_pending_review()
if reviews:
    for e in reviews:
        print(f"  ⚠️  {e.entry_id} — {e.action.action_type.value} on {e.action.target}")
        print(f"     Reason: {e.action.reason[:60]}")
        print(f"     Score:  {e.action.threat_score}/100")
        print()
else:
    print("  No items pending human review")

# ── Full healing report ───────────────────────────────────────
print("\n📊 AUTONOMOUS HEALING REPORT\n")
report = audit_log.generate_report(threshold_updates=updates)
print(f"  Report ID       : {report.report_id}")
print(f"  Total actions   : {report.total_actions}")
print(f"  Alerts fired    : {report.alerts_fired}")
print(f"  Human reviews   : {report.human_reviews}")
print(f"\n  Actions by type:")
for atype, count in report.actions_by_type.items():
    bar = "█" * count
    print(f"    {atype:<25} {bar} {count}")
print(f"\n  Top targets:")
for t in report.top_targets:
    print(f"    {t['target']:<25} {t['actions']} actions")
if report.threshold_changes:
    print(f"\n  Threshold changes:")
    for tc in report.threshold_changes:
        print(f"    {tc['parameter']:<35} {tc['old']} → {tc['new']} ({tc['direction']})")
print(f"\n  Summary: {report.summary}")

# ── Alert stats ───────────────────────────────────────────────
print("\n📣 ALERT STATS\n")
stats = alert_mgr.get_stats()
print(f"  Total alerts fired : {stats['total_alerts']}")
print(f"  Active channels    : {', '.join(stats['channels_active'])}")
print(f"  By severity:")
for sev, count in stats.get("by_severity", {}).items():
    print(f"    {sev:<10} {count}")

# ── Export report ─────────────────────────────────────────────
os.makedirs("self_healing/reports", exist_ok=True)
path = audit_log.export_json("self_healing/reports/healing_report.json", report)
print(f"\n💾 Report exported → {path}")

print(f"\n{'='*65}")
print(f"  ✅ ALL 4 SELF-HEALING PHASES COMPLETE")
print(f"{'='*65}")
print(f"""
  Perceive  → Threat sensor + anomaly scorer
  Decide    → Decision engine + rule matching
  Act       → IP block, token revoke, role downgrade, rate tighten
  Learn     → Threshold updater + model persistence
  Report    → Healing audit log + Slack alerts + JSON export

  Tesla parallel: A full autonomous loop — the gateway now
  detects threats, responds without human intervention, learns
  from every attack, and reports every action it takes.
""")

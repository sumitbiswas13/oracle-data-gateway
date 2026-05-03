"""
Self-Healing Gateway — Phase 2 Demo
Decision engine + autonomous actions — the full Perceive → Decide → Act cycle.
Run with: python self_healing/demo_healing_phase2.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from self_healing.sensors.threat_sensor import ThreatSensor
from self_healing.sensors.anomaly_scorer import AnomalyScorer
from self_healing.actions.executor import ActionExecutor
from self_healing.actions.decision_engine import DecisionEngine

# ── Setup ─────────────────────────────────────────────────────
sensor   = ThreatSensor()
scorer   = AnomalyScorer()
executor = ActionExecutor()
engine   = DecisionEngine(executor, scorer)

# Register webhook handler
def webhook(payload):
    print(f"  📣 WEBHOOK → {payload['message']}")

executor.register_webhook(webhook)

print("=" * 65)
print("  Self-Healing Oracle Gateway — Phase 2")
print("  Decision Engine + Autonomous Actions")
print("  Tesla parallel: Perceive → Decide → Act")
print("=" * 65)

# ── Simulate attack scenarios ─────────────────────────────────
EVENTS = [
    # Normal
    {"label": "Normal admin request",
     "event": {"user_id":"tok_admin_001","client_ip":"10.0.0.1","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None}},

    # SQL injection
    {"label": "SQL injection from 192.168.99.1",
     "event": {"user_id":"tok_readonly_001","client_ip":"192.168.99.1","status":"BLOCKED","table":"GPS_EMPLOYEES","rows_returned":0,"blocked_reason":"SQL injection detected in query: UNION SELECT injection"}},

    # Brute force x5
    *[{"label": f"Brute force #{i+1} from 192.168.99.2",
       "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}}
      for i in range(5)],

    # Data harvesting
    {"label": "Data harvesting — 300 rows",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.5","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":300,"blocked_reason":None}},

    # Credential stuffing
    *[{"label": f"Credential stuffing user {i+1} from 192.168.99.3",
       "event": {"user_id":f"tok_user_{i:03d}","client_ip":"192.168.99.3","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":3,"blocked_reason":None}}
      for i in range(4)],

    # Normal after attack — should be rate limited
    {"label": "Analyst request after harvesting (rate limited)",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.5","status":"ALLOWED","table":"GPS_PAYSLIPS","rows_returned":5,"blocked_reason":None}},
]

print("\n🔄 PERCEIVE → DECIDE → ACT\n")
for scenario in EVENTS:
    signals  = sensor.observe(scenario["event"])
    scorer.ingest(signals)
    decisions = engine.evaluate(signals)

    if decisions:
        for d in decisions:
            print(f"\n  ⚡ {scenario['label']}")
            print(f"     Rule    : {d.rule_matched}")
            print(f"     Score   : {d.signal.risk_score}/100")
            for r in d.actions_taken:
                icon = "✅" if r.success else "❌"
                print(f"     {icon} Action : {r.action.action_type.value} — {r.message}")
    elif signals:
        print(f"  🔍 {scenario['label']} → signals detected but no rule matched yet")
    else:
        print(f"  ✅ {scenario['label']} → safe")

# ── Active state ──────────────────────────────────────────────
print("\n\n🛡️  ACTIVE GATEWAY STATE (post-healing)\n")
state = executor.get_active_state()

print(f"  Blocked IPs:")
if state["blocked_ips"]:
    for ip, exp in state["blocked_ips"].items():
        print(f"    🚫 {ip:<20} expires {exp}")
else:
    print("    none")

print(f"\n  Revoked tokens:")
if state["revoked_tokens"]:
    for t in state["revoked_tokens"]:
        print(f"    🔑 {t}")
else:
    print("    none")

print(f"\n  Downgraded roles:")
if state["downgraded_roles"]:
    for uid, info in state["downgraded_roles"].items():
        print(f"    ⬇️  {uid:<25} {info['from']} → {info['to']}  expires {info['expires']}")
else:
    print("    none")

print(f"\n  Rate adjustments:")
if state["rate_adjustments"]:
    for uid, info in state["rate_adjustments"].items():
        print(f"    🐌 {uid:<25} {info['factor']} of normal  expires {info['expires']}")
else:
    print("    none")

# ── Stats ─────────────────────────────────────────────────────
print("\n📊 HEALING STATS\n")
stats = engine.get_stats()
ex    = stats["executor_stats"]
print(f"  Total decisions  : {stats['total_decisions']}")
print(f"  Total actions    : {ex['total_actions']}")
print(f"  Active blocks    : {ex['active_blocks']}")
print(f"  Revoked tokens   : {ex['revoked_tokens']}")
print(f"  Downgraded roles : {ex['downgraded_roles']}")
print(f"\n  Actions by type:")
for atype, count in ex["actions_by_type"].items():
    print(f"    {atype:<25} {count}")

# ── Action log ────────────────────────────────────────────────
print("\n📋 ACTION LOG (last 8)\n")
print(f"  {'ID':<10} {'Type':<25} {'Target':<25} {'Score':>6}")
print(f"  {'─'*10} {'─'*25} {'─'*25} {'─'*6}")
for a in executor.get_action_log(8):
    print(f"  {a.action_id:<10} {a.action_type.value:<25} {a.target:<25} {a.threat_score:>6.1f}")

print(f"\n✅ Phase 2 complete — Decide + Act layers operational.")
print(f"   Full Perceive → Decide → Act cycle working.")
print(f"   Next: Phase 3 — Self-learning threshold updater\n")

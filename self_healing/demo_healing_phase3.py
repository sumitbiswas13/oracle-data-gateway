"""
Self-Healing Gateway — Phase 3 Demo
Self-learning threshold updater — the Learn layer.
Run with: python self_healing/demo_healing_phase3.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from self_healing.sensors.threat_sensor import ThreatSensor
from self_healing.sensors.anomaly_scorer import AnomalyScorer
from self_healing.actions.executor import ActionExecutor
from self_healing.actions.decision_engine import DecisionEngine
from self_healing.learning.learning_engine import SelfLearningEngine

sensor   = ThreatSensor()
scorer   = AnomalyScorer()
executor = ActionExecutor()
engine   = DecisionEngine(executor, scorer)
learner  = SelfLearningEngine()

print("=" * 65)
print("  Self-Healing Oracle Gateway — Phase 3")
print("  Self-Learning Threshold Updater")
print("  Tesla parallel: Fleet learning — gets smarter over time")
print("=" * 65)

print(f"\n📐 DEFAULT THRESHOLDS\n")
defaults = learner.DEFAULT_THRESHOLDS
for k, v in defaults.items():
    print(f"  {k:<35} {v}")

# ── Wave 1: Light attack traffic ──────────────────────────────
print(f"\n{'─'*65}")
print(f"  WAVE 1 — Light brute force (3 failures)")
print(f"{'─'*65}\n")

wave1 = [
    {"user_id":"","client_ip":"10.1.1.1","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"","client_ip":"10.1.1.1","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"","client_ip":"10.1.1.1","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"},
    {"user_id":"tok_analyst_001","client_ip":"10.1.1.2","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None},
]

all_signals = []
for event in wave1:
    signals = sensor.observe(event)
    learner.observe(signals)
    scorer.ingest(signals)
    engine.evaluate(signals)
    all_signals.extend(signals)

updates1 = learner.learn()
print(f"  Signals detected : {len(all_signals)}")
print(f"  Threshold updates: {len(updates1)}")
if updates1:
    for u in updates1:
        arrow = "↓ tighter" if u.new_value < u.old_value else "↑ relaxed"
        print(f"  [{arrow}] {u.parameter}: {u.old_value} → {u.new_value}  ({u.reason[:55]})")
else:
    print("  No threshold updates yet — not enough signal volume")

# ── Wave 2: Heavy brute force ─────────────────────────────────
print(f"\n{'─'*65}")
print(f"  WAVE 2 — Heavy brute force + data harvesting attack")
print(f"{'─'*65}\n")

wave2 = (
    [{"user_id":"","client_ip":f"10.2.{i}.1","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}
     for i in range(8)] +
    [{"user_id":"tok_analyst_001","client_ip":"10.2.0.5","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":250,"blocked_reason":None}
     for _ in range(4)] +
    [{"user_id":"tok_analyst_001","client_ip":"10.2.0.5","status":"ALLOWED","table":"GPS_PAYSLIPS","rows_returned":300,"blocked_reason":None}
     for _ in range(3)]
)

all_signals2 = []
for event in wave2:
    signals = sensor.observe(event)
    learner.observe(signals)
    scorer.ingest(signals)
    engine.evaluate(signals)
    all_signals2.extend(signals)

updates2 = learner.learn()
print(f"  Events processed : {len(wave2)}")
print(f"  Signals detected : {len(all_signals2)}")
print(f"  Threshold updates: {len(updates2)}\n")
for u in updates2:
    arrow = "↓ tighter" if u.new_value < u.old_value else "↑ relaxed"
    conf  = f"confidence={u.confidence:.0%}"
    print(f"  [{arrow}] {u.parameter:<35} {u.old_value} → {u.new_value}  {conf}")
    print(f"           Reason: {u.reason[:60]}")

# ── Wave 3: Sustained attack — forces more learning ───────────
print(f"\n{'─'*65}")
print(f"  WAVE 3 — Sustained mixed attack (repeat offenders)")
print(f"{'─'*65}\n")

wave3 = (
    [{"user_id":"","client_ip":"10.1.1.1","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}
     for _ in range(6)] +   # Repeat offender IP
    [{"user_id":"tok_readonly_001","client_ip":"10.3.0.1","status":"BLOCKED","table":"GPS_EMPLOYEES","rows_returned":0,"blocked_reason":"SQL injection detected in query: UNION SELECT injection"}
     for _ in range(3)] +
    [{"user_id":"tok_analyst_001","client_ip":"10.3.0.2","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":180,"blocked_reason":None}
     for _ in range(5)]
)

all_signals3 = []
for event in wave3:
    signals = sensor.observe(event)
    learner.observe(signals)
    scorer.ingest(signals)
    engine.evaluate(signals)
    all_signals3.extend(signals)

updates3 = learner.learn()
print(f"  Events processed : {len(wave3)}")
print(f"  Signals detected : {len(all_signals3)}")
print(f"  Threshold updates: {len(updates3)}\n")
for u in updates3:
    arrow = "↓ tighter" if u.new_value < u.old_value else "↑ relaxed"
    conf  = f"confidence={u.confidence:.0%}"
    print(f"  [{arrow}] {u.parameter:<35} {u.old_value} → {u.new_value}  {conf}")
    print(f"           Reason: {u.reason[:60]}")

# ── Final threshold comparison ────────────────────────────────
print(f"\n{'─'*65}")
print(f"  THRESHOLD EVOLUTION — Default vs Learned")
print(f"{'─'*65}\n")
delta = learner.get_threshold_delta()
if delta:
    print(f"  {'Parameter':<35} {'Default':>8} {'Learned':>8} {'Change':>10} {'Direction'}")
    print(f"  {'─'*35} {'─'*8} {'─'*8} {'─'*10} {'─'*10}")
    for k, v in delta.items():
        direction = "↓ TIGHTER" if v["tighter"] else "↑ RELAXED"
        change    = f"{v['delta']:+.2f}"
        print(f"  {k:<35} {v['default']:>8} {v['current']:>8} {change:>10}  {direction}")
else:
    print("  No threshold changes yet")

# ── Known bad entities ────────────────────────────────────────
print(f"\n📋 KNOWN BAD ENTITIES\n")
bad = learner.get_known_bad_entities()
print(f"  Bad IPs    ({len(bad['bad_ips'])}):   {', '.join(bad['bad_ips'][:5])}")
print(f"  Bad users  ({len(bad['bad_users'])}):   {', '.join(bad['bad_users'][:5])}")

# ── Snapshot ──────────────────────────────────────────────────
print(f"\n📸 LEARNING SNAPSHOT\n")
snap = learner.take_snapshot()
print(f"  Snapshot ID       : {snap.snapshot_id}")
print(f"  Total signals     : {snap.total_signals}")
print(f"  Threshold updates : {len(snap.threshold_updates)}")
print(f"  Thresholds tightened: {snap.baseline_metrics['thresholds_tightened']}")
print(f"  Known bad IPs     : {snap.baseline_metrics['known_bad_ips']}")
print(f"\n  Threat breakdown:")
for threat, count in snap.threat_breakdown.items():
    bar = "█" * min(count, 20)
    print(f"    {threat:<28} {bar} {count}")

# ── Export model ──────────────────────────────────────────────
os.makedirs("self_healing/models", exist_ok=True)
model_path = learner.export_model("self_healing/models/learned_thresholds.json")
print(f"\n💾 Model exported → {model_path}")
print(f"   Gateway will load this on next restart — learning persists!")

print(f"\n✅ Phase 3 complete — Learn layer operational.")
print(f"   Gateway is now getting smarter with every attack.")
print(f"   Next: Phase 4 — Healing audit log + Slack alerts\n")

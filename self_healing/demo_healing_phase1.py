"""
Self-Healing Gateway — Phase 1 Demo
Threat sensor + anomaly scorer.
Run with: python self_healing/demo_healing_phase1.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from self_healing.sensors.threat_sensor import ThreatSensor, ThreatSeverity
from self_healing.sensors.anomaly_scorer import AnomalyScorer

sensor  = ThreatSensor()
scorer  = AnomalyScorer()

print("=" * 65)
print("  Self-Healing Oracle Gateway — Phase 1")
print("  Threat Sensor + Anomaly Scorer")
print("  Tesla parallel: Perceive layer")
print("=" * 65)

# ── Simulate attack scenarios ─────────────────────────────────
SCENARIOS = [
    # Normal traffic
    {"desc": "Admin reads employees (normal)",
     "event": {"user_id":"tok_admin_001","client_ip":"10.0.0.1","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":10,"blocked_reason":None}},
    {"desc": "Analyst reads payslips (normal)",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.2","status":"MASKED","table":"GPS_PAYSLIPS","rows_returned":5,"blocked_reason":None}},

    # SQL injection attack
    {"desc": "SQL injection attempt",
     "event": {"user_id":"tok_readonly_001","client_ip":"192.168.99.1","status":"BLOCKED","table":"GPS_EMPLOYEES","rows_returned":0,"blocked_reason":"SQL injection detected in query: UNION SELECT injection"}},

    # Brute force — 5 failed auth attempts from same IP
    {"desc": "Brute force attempt 1",
     "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}},
    {"desc": "Brute force attempt 2",
     "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}},
    {"desc": "Brute force attempt 3",
     "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}},
    {"desc": "Brute force attempt 4",
     "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}},
    {"desc": "Brute force attempt 5 (critical)",
     "event": {"user_id":"","client_ip":"192.168.99.2","status":"BLOCKED","table":"","rows_returned":0,"blocked_reason":"Invalid or expired token"}},

    # Data harvesting
    {"desc": "Bulk export — 200 rows from sensitive table",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.5","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":200,"blocked_reason":None}},

    # Credential stuffing — many users from same IP
    {"desc": "User 1 from suspicious IP",
     "event": {"user_id":"tok_admin_001","client_ip":"192.168.99.3","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None}},
    {"desc": "User 2 from same suspicious IP",
     "event": {"user_id":"tok_manager_001","client_ip":"192.168.99.3","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None}},
    {"desc": "User 3 from same suspicious IP",
     "event": {"user_id":"tok_analyst_001","client_ip":"192.168.99.3","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None}},
    {"desc": "User 4 from same suspicious IP (triggers stuffing alert)",
     "event": {"user_id":"tok_readonly_001","client_ip":"192.168.99.3","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":5,"blocked_reason":None}},

    # Table enumeration
    {"desc": "Table scan 1 — GPS_EMPLOYEES",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.6","status":"ALLOWED","table":"GPS_EMPLOYEES","rows_returned":3,"blocked_reason":None}},
    {"desc": "Table scan 2 — GPS_PAYSLIPS",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.6","status":"ALLOWED","table":"GPS_PAYSLIPS","rows_returned":3,"blocked_reason":None}},
    {"desc": "Table scan 3 — GPS_TAX_RULES",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.6","status":"ALLOWED","table":"GPS_TAX_RULES","rows_returned":3,"blocked_reason":None}},
    {"desc": "Table scan 4 — GPS_PAYROLL_RUNS (triggers enumeration alert)",
     "event": {"user_id":"tok_analyst_001","client_ip":"10.0.0.6","status":"ALLOWED","table":"GPS_PAYROLL_RUNS","rows_returned":3,"blocked_reason":None}},
]

print("\n📡 PROCESSING EVENTS THROUGH THREAT SENSOR\n")
all_signals = []
for scenario in SCENARIOS:
    signals = sensor.observe(scenario["event"])
    scorer.ingest(signals)
    if signals:
        for s in signals:
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(s.severity.value,"⚪")
            print(f"  {icon} [{s.severity.value:<8}] {s.threat_type.value:<25} risk={s.risk_score:>5.1f}  {s.description[:50]}")
        all_signals.extend(signals)
    else:
        print(f"  ✅ [SAFE    ] Normal traffic                            {scenario['desc'][:45]}")

print(f"\n  Total signals: {len(all_signals)}")

# ── Risk profiles ─────────────────────────────────────────────
print("\n📊 RISK PROFILES — HIGH RISK ENTITIES\n")
high_risk = scorer.get_all_high_risk(min_score=40)

print(f"  {'Entity':<25} {'Type':<6} {'Score':>6} {'Band':<10} {'Top threats'}")
print(f"  {'─'*25} {'─'*6} {'─'*6} {'─'*10} {'─'*30}")
for p in high_risk:
    threats = ", ".join(p.top_threats[:2])
    print(f"  {p.entity_id:<25} {p.entity_type:<6} {p.risk_score:>6.1f} {p.risk_band:<10} {threats}")

# ── Detailed profile ──────────────────────────────────────────
print("\n🔍 DETAILED PROFILE — 192.168.99.2 (brute force attacker)\n")
p = scorer.score_ip("192.168.99.2")
print(f"  Entity        : {p.entity_id}")
print(f"  Risk score    : {p.risk_score}/100")
print(f"  Risk band     : {p.risk_band} — {p.band_message}")
print(f"  Signals       : {p.signal_count}")
print(f"  Top threats   : {', '.join(p.top_threats)}")
print(f"  Recommended   : {', '.join(p.recommended_actions)}")

print(f"\n✅ Phase 1 complete — Perceive layer operational.")
print(f"   Next: Phase 2 — Decision engine + autonomous actions\n")

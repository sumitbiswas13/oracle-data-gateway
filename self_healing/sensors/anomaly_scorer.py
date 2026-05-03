"""
Anomaly Scorer
Combines all threat signals into a single risk score (0–100) per entity.
Tesla parallel: sensor fusion — combines camera, radar, lidar into one confidence score.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict
from self_healing.sensors.threat_sensor import ThreatSignal, ThreatSeverity, ThreatType


# ── Risk weights per threat type ──────────────────────────────
THREAT_WEIGHTS = {
    ThreatType.SQL_INJECTION:       1.5,   # Highest — direct attack
    ThreatType.CREDENTIAL_STUFFING: 1.4,
    ThreatType.BRUTE_FORCE:         1.3,
    ThreatType.DATA_HARVESTING:     1.2,
    ThreatType.VELOCITY_ATTACK:     1.1,
    ThreatType.TABLE_ENUMERATION:   1.0,
    ThreatType.PRIVILEGE_ABUSE:     1.0,
    ThreatType.ODD_HOUR_SWEEP:      0.8,   # Suspicious but not always malicious
}

# ── Risk thresholds → action bands ────────────────────────────
RISK_BANDS = [
    (90, "CRITICAL",  "Immediate autonomous response required"),
    (70, "HIGH",      "Autonomous response recommended"),
    (50, "MEDIUM",    "Monitor closely, partial response"),
    (30, "LOW",       "Flag and log only"),
    ( 0, "SAFE",      "Normal activity"),
]


@dataclass
class RiskProfile:
    """Unified risk profile for a user or IP."""
    entity_id:      str
    entity_type:    str      # "user" | "ip"
    risk_score:     float    # 0–100
    risk_band:      str
    band_message:   str
    signal_count:   int
    top_threats:    list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    last_updated:   datetime = field(default_factory=datetime.utcnow)


def _get_band(score: float) -> tuple[str, str]:
    for threshold, band, msg in RISK_BANDS:
        if score >= threshold:
            return band, msg
    return "SAFE", "Normal activity"


class AnomalyScorer:
    """
    Fuses threat signals into risk profiles.
    Tesla parallel: sensor fusion module — combines all inputs into
    a single actionable confidence value.
    """

    def __init__(self):
        self._user_signals: dict[str, list[ThreatSignal]] = defaultdict(list)
        self._ip_signals:   dict[str, list[ThreatSignal]] = defaultdict(list)

    def ingest(self, signals: list[ThreatSignal]):
        """Ingest new threat signals from the sensor."""
        for s in signals:
            if s.user_id:
                self._user_signals[s.user_id].append(s)
            if s.source_ip:
                self._ip_signals[s.source_ip].append(s)

    def score_user(self, user_id: str) -> RiskProfile:
        return self._build_profile(user_id, "user", self._user_signals.get(user_id, []))

    def score_ip(self, ip: str) -> RiskProfile:
        return self._build_profile(ip, "ip", self._ip_signals.get(ip, []))

    def get_all_high_risk(self, min_score: float = 50.0) -> list[RiskProfile]:
        """Return all users and IPs with risk score above threshold."""
        profiles = []
        seen = set()
        for user_id, signals in self._user_signals.items():
            p = self._build_profile(user_id, "user", signals)
            if p.risk_score >= min_score and user_id not in seen:
                profiles.append(p)
                seen.add(user_id)
        for ip, signals in self._ip_signals.items():
            p = self._build_profile(ip, "ip", signals)
            if p.risk_score >= min_score and ip not in seen:
                profiles.append(p)
                seen.add(ip)
        return sorted(profiles, key=lambda p: p.risk_score, reverse=True)

    def _build_profile(self, entity_id: str, entity_type: str, signals: list[ThreatSignal]) -> RiskProfile:
        if not signals:
            band, msg = _get_band(0)
            return RiskProfile(entity_id=entity_id, entity_type=entity_type,
                               risk_score=0.0, risk_band=band, band_message=msg,
                               signal_count=0)

        # Weighted sum of last 10 signals
        recent   = signals[-10:]
        raw_score = sum(
            s.risk_score * THREAT_WEIGHTS.get(s.threat_type, 1.0)
            for s in recent
        ) / len(recent)
        score = min(round(raw_score, 1), 100.0)

        band, msg = _get_band(score)
        top_threats = list({s.threat_type.value for s in recent})[:3]
        actions = self._recommend_actions(score, recent)

        return RiskProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            risk_score=score,
            risk_band=band,
            band_message=msg,
            signal_count=len(signals),
            top_threats=top_threats,
            recommended_actions=actions,
        )

    def _recommend_actions(self, score: float, signals: list[ThreatSignal]) -> list[str]:
        actions = []
        types = {s.threat_type for s in signals}

        if score >= 90:
            actions.append("BLOCK_IP")
            actions.append("REVOKE_TOKEN")
        elif score >= 70:
            actions.append("DOWNGRADE_ROLE")
            actions.append("TIGHTEN_RATE_LIMIT")
        elif score >= 50:
            actions.append("TIGHTEN_RATE_LIMIT")
            actions.append("ALERT_ADMIN")

        if ThreatType.SQL_INJECTION in types:
            if "BLOCK_IP" not in actions:
                actions.insert(0, "BLOCK_IP")

        if ThreatType.DATA_HARVESTING in types and "DOWNGRADE_ROLE" not in actions:
            actions.append("DOWNGRADE_ROLE")

        actions.append("LOG_HEALING_ACTION")
        return actions

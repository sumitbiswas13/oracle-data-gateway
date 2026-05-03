"""
Threat Sensor
The gateway's eyes — monitors every event and classifies threats.
Tesla parallel: the camera + radar array that feeds the FSD neural net.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ThreatType(str, Enum):
    SQL_INJECTION       = "SQL_INJECTION"
    BRUTE_FORCE         = "BRUTE_FORCE"        # Repeated auth failures
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING" # Many users from same IP
    DATA_HARVESTING     = "DATA_HARVESTING"     # Bulk + sensitive tables
    PRIVILEGE_ABUSE     = "PRIVILEGE_ABUSE"     # Role used unusually
    VELOCITY_ATTACK     = "VELOCITY_ATTACK"     # Too many requests too fast
    ODD_HOUR_SWEEP      = "ODD_HOUR_SWEEP"      # Off-hours bulk access
    TABLE_ENUMERATION   = "TABLE_ENUMERATION"   # Trying many tables fast


class ThreatSeverity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ThreatSignal:
    """A single detected threat signal from the sensor."""
    threat_type:  ThreatType
    severity:     ThreatSeverity
    source_ip:    Optional[str]
    user_id:      Optional[str]
    description:  str
    evidence:     dict = field(default_factory=dict)
    risk_score:   float = 0.0       # 0–100
    timestamp:    datetime = field(default_factory=datetime.utcnow)
    auto_respond: bool = True        # Should the decision engine act?


class ThreatSensor:
    """
    Monitors the gateway event stream and emits ThreatSignals.
    Tesla parallel: the sensor array — sees everything, classifies everything.
    """

    # Risk scores per threat type
    BASE_RISK = {
        ThreatType.SQL_INJECTION:       85.0,
        ThreatType.BRUTE_FORCE:         70.0,
        ThreatType.CREDENTIAL_STUFFING: 80.0,
        ThreatType.DATA_HARVESTING:     75.0,
        ThreatType.PRIVILEGE_ABUSE:     65.0,
        ThreatType.VELOCITY_ATTACK:     60.0,
        ThreatType.ODD_HOUR_SWEEP:      50.0,
        ThreatType.TABLE_ENUMERATION:   55.0,
    }

    def __init__(self):
        # Sliding windows (seconds → list of timestamps)
        self._auth_failures:  dict[str, list[float]] = defaultdict(list)  # ip → times
        self._ip_users:       dict[str, set]          = defaultdict(set)   # ip → users
        self._user_tables:    dict[str, list]          = defaultdict(list)  # user → (time, table)
        self._user_requests:  dict[str, list[float]]   = defaultdict(list)  # user → times
        self._signals:        list[ThreatSignal]       = []

    def observe(self, event: dict) -> list[ThreatSignal]:
        """
        Process a gateway audit event and return any threat signals detected.
        Called for every event that passes through the gateway.
        """
        now    = time.time()
        signals = []

        user_id   = event.get("user_id",   "")
        client_ip = event.get("client_ip", "unknown")
        status    = event.get("status",    "")
        table     = event.get("table",     "")
        rows      = event.get("rows_returned", 0) or 0
        reason    = event.get("blocked_reason", "") or ""
        hour      = datetime.utcnow().hour

        # ── 1. SQL injection ──────────────────────────────────
        if "injection" in reason.lower():
            s = self._make_signal(
                ThreatType.SQL_INJECTION, ThreatSeverity.CRITICAL,
                client_ip, user_id,
                f"SQL injection attempt detected from {client_ip}",
                {"reason": reason, "table": table},
            )
            signals.append(s)

        # ── 2. Brute force — repeated auth failures ───────────
        if "token" in reason.lower() or "auth" in reason.lower():
            self._auth_failures[client_ip] = [
                t for t in self._auth_failures[client_ip] if now - t < 300
            ]
            self._auth_failures[client_ip].append(now)
            count = len(self._auth_failures[client_ip])
            if count >= 3:
                severity = ThreatSeverity.CRITICAL if count >= 5 else ThreatSeverity.HIGH
                s = self._make_signal(
                    ThreatType.BRUTE_FORCE, severity,
                    client_ip, user_id,
                    f"Brute force detected: {count} auth failures from {client_ip} in 5 min",
                    {"failure_count": count, "window_seconds": 300},
                    risk_boost=min(count * 3, 15),
                )
                signals.append(s)

        # ── 3. Credential stuffing — many users same IP ───────
        if user_id:
            self._ip_users[client_ip].add(user_id)
        if len(self._ip_users[client_ip]) >= 4:
            s = self._make_signal(
                ThreatType.CREDENTIAL_STUFFING, ThreatSeverity.HIGH,
                client_ip, user_id,
                f"Credential stuffing: {len(self._ip_users[client_ip])} users from same IP {client_ip}",
                {"unique_users": list(self._ip_users[client_ip])},
                risk_boost=10,
            )
            signals.append(s)

        # ── 4. Velocity attack ────────────────────────────────
        if user_id and status != "BLOCKED":
            self._user_requests[user_id] = [
                t for t in self._user_requests[user_id] if now - t < 60
            ]
            self._user_requests[user_id].append(now)
            rpm = len(self._user_requests[user_id])
            if rpm >= 40:
                s = self._make_signal(
                    ThreatType.VELOCITY_ATTACK, ThreatSeverity.HIGH,
                    client_ip, user_id,
                    f"Velocity attack: {rpm} requests/min from user {user_id}",
                    {"requests_per_minute": rpm, "threshold": 40},
                    risk_boost=min(rpm - 40, 20),
                )
                signals.append(s)

        # ── 5. Data harvesting — bulk rows + sensitive table ──
        SENSITIVE = {"GPS_EMPLOYEES", "GPS_PAYSLIPS", "GPS_PAYROLL_RUNS"}
        if rows > 50 and table in SENSITIVE:
            s = self._make_signal(
                ThreatType.DATA_HARVESTING, ThreatSeverity.HIGH,
                client_ip, user_id,
                f"Data harvesting: {rows} rows from sensitive table {table}",
                {"rows": rows, "table": table},
                risk_boost=min(rows // 10, 20),
            )
            signals.append(s)

        # ── 6. Odd-hour sweep ─────────────────────────────────
        if table in SENSITIVE and rows > 10 and not (7 <= hour <= 22):
            s = self._make_signal(
                ThreatType.ODD_HOUR_SWEEP, ThreatSeverity.MEDIUM,
                client_ip, user_id,
                f"Off-hours bulk access: {rows} rows from {table} at {hour:02d}:00 UTC",
                {"hour": hour, "rows": rows, "table": table},
            )
            signals.append(s)

        # ── 7. Table enumeration ──────────────────────────────
        if user_id and table:
            self._user_tables[user_id] = [
                (t, tb) for t, tb in self._user_tables[user_id] if now - t < 120
            ]
            self._user_tables[user_id].append((now, table))
            unique_tables = {tb for _, tb in self._user_tables[user_id]}
            if len(unique_tables) >= 4:
                s = self._make_signal(
                    ThreatType.TABLE_ENUMERATION, ThreatSeverity.MEDIUM,
                    client_ip, user_id,
                    f"Table enumeration: {len(unique_tables)} tables in 2 min by {user_id}",
                    {"tables": list(unique_tables)},
                )
                signals.append(s)

        self._signals.extend(signals)
        return signals

    def _make_signal(
        self,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        ip: str,
        user: str,
        description: str,
        evidence: dict,
        risk_boost: float = 0,
    ) -> ThreatSignal:
        base  = self.BASE_RISK[threat_type]
        score = min(base + risk_boost, 100.0)
        return ThreatSignal(
            threat_type=threat_type,
            severity=severity,
            source_ip=ip,
            user_id=user,
            description=description,
            evidence=evidence,
            risk_score=round(score, 1),
        )

    def get_signals(self, min_severity: Optional[ThreatSeverity] = None) -> list[ThreatSignal]:
        ORDER = {ThreatSeverity.LOW:0, ThreatSeverity.MEDIUM:1,
                 ThreatSeverity.HIGH:2, ThreatSeverity.CRITICAL:3}
        signals = self._signals
        if min_severity:
            signals = [s for s in signals if ORDER[s.severity] >= ORDER[min_severity]]
        return sorted(signals, key=lambda s: s.risk_score, reverse=True)

    def get_risk_score(self, user_id: str = "", ip: str = "") -> float:
        """Get combined risk score for a user or IP."""
        relevant = [
            s for s in self._signals
            if (user_id and s.user_id == user_id) or (ip and s.source_ip == ip)
        ]
        if not relevant:
            return 0.0
        return min(sum(s.risk_score for s in relevant[-5:]) / len(relevant[-5:]), 100.0)

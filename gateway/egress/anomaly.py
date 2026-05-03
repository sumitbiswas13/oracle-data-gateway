"""
Anomaly Detection Engine
Detects suspicious egress patterns and raises alerts.
Patterns: bulk exports, odd-hour access, high-frequency queries,
          repeated sensitive field access, cross-table harvesting.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum


class AnomalyType(str, Enum):
    BULK_EXPORT          = "BULK_EXPORT"           # Too many rows in one request
    ODD_HOUR_ACCESS      = "ODD_HOUR_ACCESS"       # Access outside business hours
    HIGH_FREQUENCY       = "HIGH_FREQUENCY"         # Too many requests too fast
    SENSITIVE_HARVESTING = "SENSITIVE_HARVESTING"  # Repeated sensitive field access
    CROSS_TABLE_SWEEP    = "CROSS_TABLE_SWEEP"     # Accessing many tables quickly
    ROLE_ESCALATION      = "ROLE_ESCALATION"       # Unusual permission usage


@dataclass
class AnomalyAlert:
    anomaly_type: AnomalyType
    severity: str                    # LOW | MEDIUM | HIGH | CRITICAL
    message: str
    user_id: Optional[str] = None
    table: Optional[str] = None
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class AnomalyDetector:
    """
    Stateful anomaly detector — tracks user behaviour over time
    and flags suspicious patterns.
    """

    # Thresholds
    BULK_EXPORT_THRESHOLDS = {
        "ADMIN":    5000,
        "MANAGER":  2000,
        "ANALYST":  500,
        "READONLY": 50,
    }

    BUSINESS_HOURS = (7, 22)    # 7am – 10pm UTC considered normal
    HIGH_FREQ_WINDOW_SEC = 60
    HIGH_FREQ_THRESHOLD  = 30   # requests per minute = suspicious

    SENSITIVE_TABLES = {"GPS_EMPLOYEES", "GPS_PAYSLIPS", "GPS_PAYROLL_RUNS"}
    SENSITIVE_HARVEST_THRESHOLD = 10  # sensitive table hits in 5 min

    def __init__(self):
        self._request_times: dict[str, list[float]] = defaultdict(list)
        self._sensitive_hits: dict[str, list[float]] = defaultdict(list)
        self._table_access:   dict[str, set]         = defaultdict(set)
        self._table_access_times: dict[str, list[float]] = defaultdict(list)

    def check(
        self,
        user_id: str,
        role: str,
        table: str,
        row_count: int,
        fields_accessed: list[str],
        client_ip: Optional[str] = None,
    ) -> list[AnomalyAlert]:
        alerts = []
        now = time.time()
        current_hour = datetime.utcnow().hour

        # ── 1. Bulk export ────────────────────────────────────
        threshold = self.BULK_EXPORT_THRESHOLDS.get(role, 50)
        if row_count >= threshold * 0.8:
            severity = "CRITICAL" if row_count >= threshold else "HIGH"
            alerts.append(AnomalyAlert(
                anomaly_type=AnomalyType.BULK_EXPORT,
                severity=severity,
                message=f"Large export: {row_count} rows from {table} by {role}",
                user_id=user_id,
                table=table,
                details={"rows": row_count, "threshold": threshold, "role": role},
            ))

        # ── 2. Odd-hour access ────────────────────────────────
        start_h, end_h = self.BUSINESS_HOURS
        if not (start_h <= current_hour <= end_h):
            if table in self.SENSITIVE_TABLES:
                alerts.append(AnomalyAlert(
                    anomaly_type=AnomalyType.ODD_HOUR_ACCESS,
                    severity="MEDIUM",
                    message=f"Sensitive table '{table}' accessed at {current_hour:02d}:00 UTC (outside business hours)",
                    user_id=user_id,
                    table=table,
                    details={"hour_utc": current_hour, "business_hours": f"{start_h}:00-{end_h}:00"},
                ))

        # ── 3. High frequency ─────────────────────────────────
        key = f"{user_id}:{table}"
        self._request_times[key] = [
            t for t in self._request_times[key] if now - t < self.HIGH_FREQ_WINDOW_SEC
        ]
        self._request_times[key].append(now)
        freq = len(self._request_times[key])
        if freq >= self.HIGH_FREQ_THRESHOLD:
            alerts.append(AnomalyAlert(
                anomaly_type=AnomalyType.HIGH_FREQUENCY,
                severity="HIGH",
                message=f"High frequency: {freq} requests to {table} in 60s by user {user_id}",
                user_id=user_id,
                table=table,
                details={"requests_per_minute": freq, "threshold": self.HIGH_FREQ_THRESHOLD},
            ))

        # ── 4. Sensitive table harvesting ─────────────────────
        if table in self.SENSITIVE_TABLES:
            sens_key = user_id
            self._sensitive_hits[sens_key] = [
                t for t in self._sensitive_hits[sens_key] if now - t < 300  # 5 min window
            ]
            self._sensitive_hits[sens_key].append(now)
            hits = len(self._sensitive_hits[sens_key])
            if hits >= self.SENSITIVE_HARVEST_THRESHOLD:
                alerts.append(AnomalyAlert(
                    anomaly_type=AnomalyType.SENSITIVE_HARVESTING,
                    severity="CRITICAL",
                    message=f"Sensitive data harvesting: {hits} sensitive table hits in 5 min by user {user_id}",
                    user_id=user_id,
                    table=table,
                    details={"hits_in_5min": hits, "threshold": self.SENSITIVE_HARVEST_THRESHOLD},
                ))

        # ── 5. Cross-table sweep ──────────────────────────────
        sweep_key = user_id
        self._table_access_times[sweep_key] = [
            t for t in self._table_access_times[sweep_key] if now - t < 120  # 2 min window
        ]
        self._table_access_times[sweep_key].append(now)
        self._table_access[sweep_key].add(table)

        # Reset table set every 2 minutes
        if len(self._table_access_times[sweep_key]) == 1:
            self._table_access[sweep_key] = {table}

        if len(self._table_access[sweep_key]) >= 4:
            alerts.append(AnomalyAlert(
                anomaly_type=AnomalyType.CROSS_TABLE_SWEEP,
                severity="HIGH",
                message=f"Cross-table sweep: user {user_id} accessed {len(self._table_access[sweep_key])} tables in 2 min",
                user_id=user_id,
                table=table,
                details={"tables_accessed": list(self._table_access[sweep_key])},
            ))

        return alerts

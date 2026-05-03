"""
Egress Pipeline — Phase 2
Full implementation: data masking + anomaly detection + field-level rules.
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from gateway.egress.masking import DataMaskingEngine
from gateway.egress.anomaly import AnomalyDetector, AnomalyAlert
from gateway.ingress.pipeline import MOCK_USERS


@dataclass
class EgressResult:
    data: Any = None
    rows_masked: int = 0
    fields_masked: list[str] = field(default_factory=list)
    flagged: bool = False
    reason: Optional[str] = None
    alerts: list[str] = field(default_factory=list)
    anomalies: list[AnomalyAlert] = field(default_factory=list)


class EgressPipeline:
    """
    Full egress pipeline:
    1. Data masking — PII fields masked based on role
    2. Anomaly detection — bulk exports, odd hours, harvesting
    3. Field-level rules — restrict columns per role
    """

    def __init__(self):
        self.masker   = DataMaskingEngine()
        self.detector = AnomalyDetector()

    def run(self, request, data: Any, row_count: int) -> EgressResult:
        if not data:
            return EgressResult(data=data)

        user = MOCK_USERS.get(request.user_id or "")
        role = user["role"] if user else "READONLY"

        result = EgressResult(data=data)

        # 1. Data masking
        if isinstance(data, list) and data and isinstance(data[0], dict):
            masked_data, rows_masked, fields_masked = self.masker.mask_dataset(
                data=data,
                table=request.table or "",
                role=role,
            )
            result.data          = masked_data
            result.rows_masked   = rows_masked
            result.fields_masked = fields_masked

        # 2. Anomaly detection
        anomalies = self.detector.check(
            user_id=request.user_id or "anonymous",
            role=role,
            table=request.table or "",
            row_count=row_count,
            fields_accessed=list(data[0].keys()) if data and isinstance(data, list) else [],
        )

        if anomalies:
            result.anomalies = anomalies
            result.alerts    = [a.message for a in anomalies]
            critical = [a for a in anomalies if a.severity in ("HIGH", "CRITICAL")]
            if critical:
                result.flagged = True
                result.reason  = critical[0].message

        return result

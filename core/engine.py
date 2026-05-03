"""
Oracle Data Gateway — Core Engine
Every request into Oracle and every response out passes through here.
Nothing touches the DB directly.
"""

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from enum import Enum


class RequestDirection(str, Enum):
    INGRESS = "INGRESS"   # Coming INTO Oracle
    EGRESS  = "EGRESS"    # Going OUT of Oracle


class RequestStatus(str, Enum):
    ALLOWED  = "ALLOWED"
    BLOCKED  = "BLOCKED"
    MASKED   = "MASKED"
    FLAGGED  = "FLAGGED"


@dataclass
class GatewayRequest:
    """Represents a request entering the gateway."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    direction: RequestDirection = RequestDirection.INGRESS
    user_id: Optional[str] = None
    user_role: Optional[str] = None
    client_ip: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    table: Optional[str] = None
    query: Optional[str] = None
    payload: Optional[dict] = None
    row_limit: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GatewayResponse:
    """Represents a response leaving the gateway."""
    request_id: str
    status: RequestStatus
    direction: RequestDirection
    data: Optional[Any] = None
    rows_returned: int = 0
    rows_masked: int = 0
    fields_masked: list[str] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    flagged_reason: Optional[str] = None
    alerts: list[str] = field(default_factory=list)
    processing_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GatewayEvent:
    """An event published to Kafka for every gateway transaction."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = ""          # REQUEST_ALLOWED | REQUEST_BLOCKED | ANOMALY_DETECTED
    request_id: str = ""
    direction: str = ""
    user_id: Optional[str] = None
    user_role: Optional[str] = None
    client_ip: Optional[str] = None
    endpoint: Optional[str] = None
    table: Optional[str] = None
    status: str = ""
    rows_affected: int = 0
    blocked_reason: Optional[str] = None
    flagged_reason: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class GatewayEngine:
    """
    Central orchestrator for all Oracle data access.
    Chains ingress controls → Oracle execution → egress controls.
    """

    def __init__(
        self,
        ingress_pipeline,
        egress_pipeline,
        oracle_executor,
        event_publisher=None,
        audit_logger=None,
    ):
        self.ingress  = ingress_pipeline
        self.egress   = egress_pipeline
        self.executor = oracle_executor
        self.publisher = event_publisher
        self.auditor   = audit_logger

    def process(self, request: GatewayRequest) -> GatewayResponse:
        """
        Full gateway pipeline:
        1. Run ingress controls (auth, rate limit, validation, SQL filter)
        2. Execute against Oracle
        3. Run egress controls (masking, anomaly detection, field rules)
        4. Publish event to Kafka
        5. Write audit log
        """
        start = time.time()

        # ── Step 1: Ingress ──────────────────────────────────
        ingress_result = self.ingress.run(request)
        if ingress_result.blocked:
            response = GatewayResponse(
                request_id=request.request_id,
                status=RequestStatus.BLOCKED,
                direction=RequestDirection.INGRESS,
                blocked_reason=ingress_result.reason,
                processing_ms=round((time.time() - start) * 1000, 2),
            )
            self._publish(request, response)
            self._audit(request, response)
            return response

        # ── Step 2: Oracle execution ─────────────────────────
        try:
            raw_data, row_count = self.executor.execute(request)
        except Exception as e:
            response = GatewayResponse(
                request_id=request.request_id,
                status=RequestStatus.BLOCKED,
                direction=RequestDirection.INGRESS,
                blocked_reason=f"DB error: {str(e)}",
                processing_ms=round((time.time() - start) * 1000, 2),
            )
            self._publish(request, response)
            self._audit(request, response)
            return response

        # ── Step 3: Egress ───────────────────────────────────
        egress_result = self.egress.run(request, raw_data, row_count)

        status = RequestStatus.ALLOWED
        if egress_result.rows_masked > 0:
            status = RequestStatus.MASKED
        if egress_result.flagged:
            status = RequestStatus.FLAGGED

        response = GatewayResponse(
            request_id=request.request_id,
            status=status,
            direction=RequestDirection.EGRESS,
            data=egress_result.data,
            rows_returned=row_count,
            rows_masked=egress_result.rows_masked,
            fields_masked=egress_result.fields_masked,
            flagged_reason=egress_result.reason if egress_result.flagged else None,
            alerts=egress_result.alerts,
            processing_ms=round((time.time() - start) * 1000, 2),
        )

        # ── Step 4 & 5: Publish + Audit ──────────────────────
        self._publish(request, response)
        self._audit(request, response)

        return response

    def _publish(self, request: GatewayRequest, response: GatewayResponse):
        if not self.publisher:
            return
        event = GatewayEvent(
            event_type="REQUEST_BLOCKED" if response.status == RequestStatus.BLOCKED
                       else "ANOMALY_DETECTED" if response.status == RequestStatus.FLAGGED
                       else "REQUEST_ALLOWED",
            request_id=request.request_id,
            direction=request.direction.value,
            user_id=request.user_id,
            user_role=request.user_role,
            client_ip=request.client_ip,
            endpoint=request.endpoint,
            table=request.table,
            status=response.status.value,
            rows_affected=response.rows_returned,
            blocked_reason=response.blocked_reason,
            flagged_reason=response.flagged_reason,
        )
        self.publisher.publish(event)

    def _audit(self, request: GatewayRequest, response: GatewayResponse):
        if not self.auditor:
            return
        self.auditor.log(request, response)

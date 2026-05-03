"""
Audit Logger
Records every gateway transaction — ingress and egress.
In production, writes to Oracle GPS_AUDIT_LOG table.
"""

import json
from datetime import datetime
from pathlib import Path
from core.engine import GatewayRequest, GatewayResponse


class AuditLogger:

    def __init__(self, log_file: str = "gateway_audit.log"):
        self.log_file = Path(log_file)
        self._memory_log: list[dict] = []   # In-memory for demo

    def log(self, request: GatewayRequest, response: GatewayResponse):
        entry = {
            "timestamp":      datetime.utcnow().isoformat(),
            "request_id":     request.request_id,
            "direction":      request.direction.value,
            "user_id":        request.user_id,
            "client_ip":      request.client_ip,
            "endpoint":       request.endpoint,
            "table":          request.table,
            "method":         request.method,
            "status":         response.status.value,
            "rows_returned":  response.rows_returned,
            "rows_masked":    response.rows_masked,
            "blocked_reason": response.blocked_reason,
            "flagged_reason": response.flagged_reason,
            "processing_ms":  response.processing_ms,
        }
        self._memory_log.append(entry)

        # Also write to file
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def get_recent(self, limit: int = 50) -> list[dict]:
        return list(reversed(self._memory_log[-limit:]))

    def get_stats(self) -> dict:
        if not self._memory_log:
            return {}
        total    = len(self._memory_log)
        blocked  = sum(1 for e in self._memory_log if e["status"] == "BLOCKED")
        flagged  = sum(1 for e in self._memory_log if e["status"] == "FLAGGED")
        masked   = sum(1 for e in self._memory_log if e["status"] == "MASKED")
        allowed  = sum(1 for e in self._memory_log if e["status"] == "ALLOWED")
        avg_ms   = sum(e["processing_ms"] for e in self._memory_log) / total
        return {
            "total_requests": total,
            "allowed":        allowed,
            "blocked":        blocked,
            "flagged":        flagged,
            "masked":         masked,
            "block_rate_pct": round(blocked / total * 100, 1),
            "avg_latency_ms": round(avg_ms, 2),
        }

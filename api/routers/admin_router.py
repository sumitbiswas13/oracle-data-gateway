"""
Admin Router — gateway management endpoints.
"""

from fastapi import APIRouter, Header, HTTPException, Query, Request
from typing import Optional

router = APIRouter(prefix="/admin", tags=["Admin"])
ADMIN_TOKENS = {"tok_admin_001"}

def _require_admin(token):
    if not token or token not in ADMIN_TOKENS:
        raise HTTPException(status_code=403, detail={"error": "ADMIN_REQUIRED", "reason": "Admin token required"})

@router.get("/stats")
async def get_stats(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token")):
    _require_admin(token)
    return {
        "gateway": request.app.state.engine.auditor.get_stats(),
        "kafka":   request.app.state.publisher.get_stats(),
        "stream":  request.app.state.processor.get_metrics(),
    }

@router.get("/audit")
async def get_audit(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token"), limit: int = Query(20, ge=1, le=200)):
    _require_admin(token)
    return {"entries": request.app.state.engine.auditor.get_recent(limit=limit)}

@router.get("/kafka/topics")
async def kafka_topics(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token")):
    _require_admin(token)
    stats = request.app.state.publisher.get_stats()
    return {"topics": stats["topics"], "published": stats["published"]}

@router.get("/kafka/consume/{topic}")
async def consume_topic(topic: str, request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token"), limit: int = Query(10, ge=1, le=100)):
    _require_admin(token)
    valid = request.app.state.publisher.list_topics()
    if topic not in valid:
        raise HTTPException(status_code=404, detail={"error": "TOPIC_NOT_FOUND", "valid_topics": valid})
    return {"topic": topic, "messages": request.app.state.publisher.consume(topic, limit=limit)}

@router.get("/alerts")
async def get_alerts(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token"), severity: Optional[str] = None):
    _require_admin(token)
    return {"alerts": request.app.state.processor.get_alerts(severity=severity)}

@router.get("/rules/masking")
async def masking_rules(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token")):
    _require_admin(token)
    from gateway.egress.masking import MASK_RULES
    return {"total": len(MASK_RULES), "rules": [{"table": r.table, "field": r.field, "strategy": r.strategy.value, "allowed_roles": r.allowed_roles} for r in MASK_RULES]}

@router.get("/rules/tables")
async def table_rules(request: Request, token: Optional[str] = Header(None, alias="X-Gateway-Token")):
    _require_admin(token)
    from gateway.ingress.pipeline import TABLE_SCHEMAS, MAX_ROW_LIMITS
    return {"tables": list(TABLE_SCHEMAS.keys()), "row_limits": MAX_ROW_LIMITS}

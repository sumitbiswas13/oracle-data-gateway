"""
Data Access Router
The primary gateway endpoint — all Oracle data access goes through here.
"""

from fastapi import APIRouter, Header, HTTPException, Query, Request
from typing import Optional, Any
from pydantic import BaseModel

from core.engine import GatewayEngine, GatewayRequest, RequestDirection

router = APIRouter(prefix="/data", tags=["Data Access"])


class WritePayload(BaseModel):
    data: dict[str, Any]


@router.get("/{table}", summary="Read data from an Oracle table through the gateway")
async def read_table(
    table: str,
    request: Request,
    token: Optional[str] = Header(None, alias="X-Gateway-Token"),
    limit: int = Query(100, ge=1, le=10000),
    filter: Optional[str] = Query(None),
):
    engine = request.app.state.engine
    gw_request = GatewayRequest(
        direction=RequestDirection.INGRESS,
        user_id=token,
        method="SELECT",
        table=table.upper(),
        endpoint=f"/data/{table}",
        client_ip=request.client.host if request.client else "unknown",
        query=filter,
        row_limit=limit,
    )
    response = engine.process(gw_request)
    if response.status.value == "BLOCKED":
        raise HTTPException(status_code=403, detail={
            "error": "GATEWAY_BLOCKED",
            "reason": response.blocked_reason,
            "request_id": response.request_id,
        })
    return {
        "request_id":    response.request_id,
        "table":         table.upper(),
        "status":        response.status.value,
        "rows":          response.rows_returned,
        "rows_masked":   response.rows_masked,
        "fields_masked": response.fields_masked,
        "flagged":       response.status.value == "FLAGGED",
        "alerts":        response.alerts,
        "latency_ms":    response.processing_ms,
        "data":          response.data,
    }


@router.post("/{table}", summary="Insert a row into an Oracle table through the gateway", status_code=201)
async def write_table(
    table: str,
    body: WritePayload,
    request: Request,
    token: Optional[str] = Header(None, alias="X-Gateway-Token"),
):
    engine = request.app.state.engine
    gw_request = GatewayRequest(
        direction=RequestDirection.INGRESS,
        user_id=token,
        method="INSERT",
        table=table.upper(),
        endpoint=f"/data/{table}",
        client_ip=request.client.host if request.client else "unknown",
        payload=body.data,
    )
    response = engine.process(gw_request)
    if response.status.value == "BLOCKED":
        raise HTTPException(status_code=403, detail={
            "error": "GATEWAY_BLOCKED",
            "reason": response.blocked_reason,
            "request_id": response.request_id,
        })
    return {"request_id": response.request_id, "status": "inserted", "table": table.upper(), "latency_ms": response.processing_ms}

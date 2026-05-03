"""
Oracle Data Gateway — FastAPI App
Run with: uvicorn api.app:app --reload
Docs at:  http://localhost:8000/docs
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.engine import GatewayEngine
from core.executor import MockOracleExecutor
from core.audit import AuditLogger
from gateway.ingress.pipeline import IngressPipeline
from gateway.egress.pipeline import EgressPipeline
from gateway.streaming.kafka_publisher import MockKafkaPublisher
from gateway.streaming.stream_processor import StreamProcessor
from api.routers.data_router import router as data_router
from api.routers.admin_router import router as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🛡️  Oracle Data Gateway starting...")

    publisher = MockKafkaPublisher()
    processor = StreamProcessor(publisher)

    def alert_handler(payload: dict):
        print(f"🚨 ALERT [{payload['severity']}]: {payload.get('message') or payload.get('reason')}")

    processor.register_webhook(alert_handler)

    engine = GatewayEngine(
        ingress_pipeline=IngressPipeline(),
        egress_pipeline=EgressPipeline(),
        oracle_executor=MockOracleExecutor(),
        event_publisher=publisher,
        audit_logger=AuditLogger("gateway_audit.log"),
    )

    app.state.engine    = engine
    app.state.publisher = publisher
    app.state.processor = processor

    print("✅ Gateway ready — all controls active")
    print("📖 Docs: http://localhost:8000/docs")
    yield
    print("👋 Gateway shutting down...")


app = FastAPI(
    title="Oracle Data Gateway",
    description="""
## 🛡️ Oracle Data Gateway

A security gateway that sits between your applications and Oracle DB.
Every byte of data flowing in (ingress) and out (egress) is controlled,
monitored, and audited.

### How to use
Pass your token in the `X-Gateway-Token` header on every request.

### Demo tokens

| Token | Role | Row Limit | Permissions |
|-------|------|-----------|-------------|
| `tok_admin_001` | ADMIN | 10,000 | SELECT, INSERT, UPDATE, DELETE |
| `tok_manager_001` | MANAGER | 5,000 | SELECT, INSERT, UPDATE |
| `tok_analyst_001` | ANALYST | 1,000 | SELECT only |
| `tok_readonly_001` | READONLY | 100 | SELECT only |

### What the gateway does
- **Ingress**: Validates JWT, enforces rate limits, blocks SQL injection, whitelists tables
- **Egress**: Masks PII fields by role, detects anomalies, publishes events to Kafka
- **Audit**: Logs every request with full context
    """,
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(data_router)
app.include_router(admin_router)


@app.get("/", tags=["Health"])
def root():
    return {
        "system":  "Oracle Data Gateway",
        "version": "1.0.0",
        "status":  "active",
        "docs":    "/docs",
        "controls": {
            "ingress": ["JWT auth", "Rate limiting", "SQL injection filter", "Schema validation"],
            "egress":  ["Data masking", "Anomaly detection", "Field-level rules"],
            "streaming": ["Kafka event publishing"],
        },
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}

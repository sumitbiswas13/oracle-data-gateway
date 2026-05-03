# 🛡️ Oracle Data Gateway

> A security gateway that sits between your applications and Oracle DB, controlling and monitoring every byte of data flowing in (ingress) and out (egress). Nothing touches Oracle directly — everything goes through the gateway.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Oracle](https://img.shields.io/badge/Oracle-DB-red?style=flat-square&logo=oracle)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square&logo=fastapi)
![Kafka](https://img.shields.io/badge/Kafka-Streaming-black?style=flat-square&logo=apachekafka)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🎯 What problem does it solve?

Enterprise Oracle databases often have dozens of applications, services, and users accessing them directly. There is no central place to enforce security rules, mask sensitive data, detect anomalies, or audit every access. The Oracle Data Gateway fixes this by acting as a single controlled entry and exit point for all Oracle data access.

---

## 🏗️ Architecture

```
External clients
       ↓
┌─────────────────────────────────────────┐
│           INGRESS CONTROLS              │
│  JWT Auth → Rate Limit → SQL Filter     │
│  → Schema Validation                    │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│              ORACLE DB                  │
│  Tables · Views · Stored Procedures     │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│           EGRESS CONTROLS               │
│  Data Masking → Anomaly Detection       │
│  → Field Rules → Kafka Streaming        │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│             MONITORING                  │
│  Audit Log · Alerts · Dashboard         │
│  Compliance Reports (GDPR, HIPAA, PCI)  │
└─────────────────────────────────────────┘
```

---

## ✨ Features

### Ingress controls
- JWT authentication — every request requires a valid token
- Role-based access — ADMIN, MANAGER, ANALYST, READONLY with different permissions
- Rate limiting — sliding window per user and per endpoint
- SQL injection filter — 14 attack patterns detected and blocked
- Schema validation — only whitelisted tables accessible, row limits enforced per role

### Egress controls
- PII data masking — emails, salaries masked based on role
- Field-level rules — define exactly which fields each role can see
- Anomaly detection — bulk export alerts, odd-hour access, cross-table sweeps
- Kafka streaming — every egress event published to 5 topics

### Monitoring
- Audit log — every request logged with full context
- React dashboard — live traffic, block rates, latency, Kafka metrics, gateway tester
- Alert engine — webhook notifications on anomalies
- Compliance reports — GDPR, HIPAA, PCI-DSS audit trail generation

---

## 🚀 Quick start

**1. Install dependencies**
```bash
pip3 install -r requirements.txt
```

**2. Run any demo (no Oracle needed)**
```bash
python3 demo/demo_phase1.py   # Ingress controls
python3 demo/demo_phase2.py   # Egress masking + anomaly detection
python3 demo/demo_phase3.py   # Kafka event streaming
python3 demo/demo_phase6.py   # Compliance reports
```

**3. Open the monitoring dashboard**
```
Open dashboard/index.html in your browser
```

**4. Start the API**
```bash
python3 -m uvicorn api.app:app --reload
# Docs: http://localhost:8000/docs
```

---

## 🔑 Demo tokens

| Token | Role | Row Limit | Permissions |
|-------|------|-----------|-------------|
| tok_admin_001 | ADMIN | 10,000 | SELECT, INSERT, UPDATE, DELETE |
| tok_manager_001 | MANAGER | 5,000 | SELECT, INSERT, UPDATE |
| tok_analyst_001 | ANALYST | 1,000 | SELECT only |
| tok_readonly_001 | READONLY | 100 | SELECT only |

---

## 📡 API endpoints

| Method | Endpoint | Role | Description |
|--------|----------|------|-------------|
| GET | /data/{table} | Any | Read table through gateway |
| POST | /data/{table} | Admin/Manager | Insert row through gateway |
| GET | /admin/stats | Admin | Gateway statistics |
| GET | /admin/audit | Admin | Audit log |
| GET | /admin/kafka/topics | Admin | Kafka topic counts |
| GET | /admin/kafka/consume/{topic} | Admin | Consume topic messages |
| GET | /admin/alerts | Admin | Active alerts |
| GET | /admin/rules/masking | Admin | Active masking rules |

---

## 🗂️ Project structure

```
oracle-data-gateway/
├── core/
│   ├── engine.py              # Central gateway orchestrator
│   ├── executor.py            # Oracle DB executor (mock + real)
│   └── audit.py               # Audit logger
├── gateway/
│   ├── ingress/
│   │   └── pipeline.py        # JWT, rate limiter, SQL filter, validation
│   ├── egress/
│   │   ├── pipeline.py        # Egress orchestrator
│   │   ├── masking.py         # Data masking engine
│   │   └── anomaly.py         # Anomaly detection engine
│   ├── streaming/
│   │   ├── kafka_publisher.py # Mock + real Kafka publisher
│   │   └── stream_processor.py# Event stream processor + alerts
│   └── monitoring/
│       └── compliance.py      # GDPR, HIPAA, PCI-DSS report generator
├── api/
│   ├── app.py                 # FastAPI app
│   └── routers/               # Data + admin endpoints
├── dashboard/
│   └── index.html             # React monitoring dashboard
├── demo/
│   ├── demo_phase1.py         # Ingress controls demo
│   ├── demo_phase2.py         # Egress controls demo
│   ├── demo_phase3.py         # Kafka streaming demo
│   └── demo_phase6.py         # Compliance reports demo
└── requirements.txt
```

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | Complete | Core engine + ingress controls |
| 2 | Complete | Egress controls — data masking + anomaly detection |
| 3 | Complete | Kafka event streaming |
| 4 | Complete | FastAPI REST layer |
| 5 | Complete | React monitoring dashboard |
| 6 | Complete | Compliance report generator (GDPR, HIPAA, PCI-DSS) |

---

## 🔗 Related project

This gateway protects the [Kronos Oracle Global Payroll System](https://github.com/sumitbiswas13/kronos-oracle-global-payroll-system).

---

## 📄 License

MIT

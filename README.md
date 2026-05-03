# 🛡️ Oracle Data Gateway

> A security gateway that sits between your applications and Oracle DB, controlling and monitoring every byte of data flowing in (ingress) and out (egress). Nothing touches Oracle directly — everything goes through the gateway.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Oracle](https://img.shields.io/badge/Oracle-DB-red?style=flat-square&logo=oracle)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square&logo=fastapi)
![Kafka](https://img.shields.io/badge/Kafka-Streaming-black?style=flat-square&logo=apachekafka)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🎯 What problem does it solve?

Enterprise Oracle databases often have dozens of applications, services, and users accessing them directly. There's no central place to enforce security rules, mask sensitive data, detect anomalies, or audit every access. The Oracle Data Gateway fixes this by acting as a **single controlled entry and exit point** for all Oracle data access.

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
│  Compliance Reports (GDPR, HIPAA)       │
└─────────────────────────────────────────┘
```

---

## ✨ Features

### Ingress controls (data coming IN)
- **JWT authentication** — every request requires a valid token
- **Role-based access** — ADMIN, MANAGER, ANALYST, READONLY with different permissions
- **Rate limiting** — sliding window per user and per endpoint
- **SQL injection filter** — 14 attack patterns detected and blocked
- **Schema validation** — only whitelisted tables accessible, row limits enforced per role

### Egress controls (data going OUT) — Phase 2
- **PII data masking** — emails, salaries, SSNs masked based on role
- **Field-level rules** — define exactly which fields each role can see
- **Anomaly detection** — bulk export alerts, odd-hour access flags
- **Kafka streaming** — every egress event published as a topic

### Monitoring — Phase 5
- **Audit log** — every request logged with full context
- **React dashboard** — live traffic, block rates, latency metrics
- **Alert engine** — Slack/webhook notifications on anomalies
- **Compliance reports** — GDPR, HIPAA audit trail generation

---

## 🚀 Quick start

**1. Install dependencies**
```bash
pip install -r requirements.txt
```

**2. Run Phase 1 demo (no Oracle needed)**
```bash
python demo/demo_phase1.py
```

**3. Expected output**
```
✅ Valid admin token          ALLOWED    10 rows, 0.13ms
🛡️ Missing token → BLOCK      BLOCKED    Missing authentication token
🛡️ UNION SELECT attack → BLOCK BLOCKED   SQL injection detected in query
🛡️ Unknown table → BLOCK      BLOCKED    Table 'SYS_PASSWORDS' not accessible
```

---

## 🔑 Demo tokens

| Token | Role | Permissions |
|-------|------|-------------|
| `tok_admin_001` | ADMIN | SELECT, INSERT, UPDATE, DELETE |
| `tok_manager_001` | MANAGER | SELECT, INSERT, UPDATE |
| `tok_analyst_001` | ANALYST | SELECT (max 1000 rows) |
| `tok_readonly_001` | READONLY | SELECT (max 100 rows) |

---

## 🗂️ Project structure

```
oracle-data-gateway/
├── core/
│   ├── engine.py          # Central gateway orchestrator
│   ├── executor.py        # Oracle DB executor (mock + real)
│   └── audit.py           # Audit logger
├── gateway/
│   ├── ingress/
│   │   └── pipeline.py    # JWT, rate limiter, SQL filter, validation
│   └── egress/
│       └── pipeline.py    # Data masking, anomaly detection (Phase 2)
├── demo/
│   └── demo_phase1.py     # Phase 1 demo — no Oracle needed
├── requirements.txt
└── README.md
```

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | ✅ Complete | Core engine + ingress controls |
| 2 | 🔜 Next | Egress controls — data masking + anomaly detection |
| 3 | 📋 Planned | Kafka event streaming |
| 4 | 📋 Planned | FastAPI REST layer |
| 5 | 📋 Planned | React monitoring dashboard |
| 6 | 📋 Planned | Compliance report generator |

---

## 🔗 Related project

This gateway is designed to protect the [Kronos Oracle Global Payroll System](https://github.com/sumitbiswas13/kronos-oracle-global-payroll-system) — ensuring no sensitive payroll data (salaries, SSNs, tax details) can be accessed without going through the security gateway.

---

## 📄 License

MIT

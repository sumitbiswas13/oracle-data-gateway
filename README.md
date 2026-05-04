# 🛡️ Oracle Data Gateway

> An autonomous, self-healing Oracle security gateway — JWT auth, SQL injection prevention, PII masking, Kafka streaming, GDPR/HIPAA/PCI-DSS compliance, and a Tesla-inspired Perceive→Decide→Act→Learn loop that detects threats and responds without human intervention.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Oracle](https://img.shields.io/badge/Oracle-DB-red?style=flat-square&logo=oracle)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square&logo=fastapi)
![Kafka](https://img.shields.io/badge/Kafka-Streaming-black?style=flat-square&logo=apachekafka)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## 🎯 What problem does it solve?

Enterprise Oracle databases often have dozens of applications, services, and users accessing them directly. There is no central place to enforce security rules, mask sensitive data, detect anomalies, or audit every access. The Oracle Data Gateway fixes this by acting as a single controlled entry and exit point — and now autonomously responds to threats without human intervention.

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
│       SELF-HEALING ENGINE               │
│  Perceive → Decide → Act → Learn        │
│  Autonomous threat response             │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│             MONITORING                  │
│  Audit Log · Slack Alerts · Dashboard   │
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

### Self-healing engine (Tesla-inspired)
- Perceive — threat sensor classifies 8 threat types, scores every entity 0–100
- Decide — decision engine maps risk scores to autonomous actions using rules
- Act — IP blocks, token revocation, role downgrades, rate tightening — no human needed
- Learn — analyses attack patterns, auto-updates detection thresholds, persists model to JSON
- Report — healing audit log, Slack alerts, human review queue, JSON export

### Monitoring
- Audit log — every request logged with full context
- React dashboard — live traffic, block rates, latency, Kafka metrics, gateway tester
- Compliance reports — GDPR, HIPAA, PCI-DSS audit trail generation

---

## 🚀 Quick start

**1. Install dependencies**
```bash
pip3 install -r requirements.txt
```

**2. Run any demo (no Oracle needed)**
```bash
# Gateway controls
python3 demo/demo_phase1.py       # Ingress controls
python3 demo/demo_phase2.py       # Egress masking + anomaly detection
python3 demo/demo_phase3.py       # Kafka event streaming
python3 demo/demo_phase6.py       # Compliance reports

# Self-healing engine
python3 self_healing/demo_healing_phase1.py   # Perceive layer
python3 self_healing/demo_healing_phase2.py   # Decide + Act layers
python3 self_healing/demo_healing_phase3.py   # Learn layer
python3 self_healing/demo_healing_phase4.py   # Full closed loop
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

## 🤖 Self-healing — Tesla FSD parallel

Tesla's Full Self-Driving works on a closed loop: perceive the road, decide what to do, act on it, learn from every mile driven. The self-healing gateway applies the same architecture to database security.

| FSD Layer | Gateway Equivalent |
|-----------|-------------------|
| Camera + radar array | Threat sensor — monitors every event |
| Neural network decision | Decision engine — maps risk scores to actions |
| Steering + braking actuators | Action executor — blocks IPs, revokes tokens, downgrades roles |
| Fleet learning | Learning engine — updates thresholds from attack history |
| Event data recorder | Healing audit log — logs every autonomous decision |

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
├── core/                          # Gateway engine + executor + audit
├── gateway/
│   ├── ingress/                   # JWT, rate limiter, SQL filter, validation
│   ├── egress/                    # Masking, anomaly detection
│   ├── streaming/                 # Kafka publisher + stream processor
│   └── monitoring/                # GDPR, HIPAA, PCI-DSS reports
├── self_healing/
│   ├── sensors/                   # Threat sensor + anomaly scorer
│   ├── actions/                   # Decision engine + action executor
│   ├── learning/                  # Self-learning threshold updater
│   └── monitoring/                # Healing audit log + Slack alerts
├── api/                           # FastAPI app + routers
├── dashboard/                     # React monitoring dashboard
└── demo/                          # Demo scripts (no Oracle needed)
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
| 6 | Complete | Compliance reports (GDPR, HIPAA, PCI-DSS) |
| SH-1 | Complete | Self-healing: Threat sensor + anomaly scorer |
| SH-2 | Complete | Self-healing: Decision engine + autonomous actions |
| SH-3 | Complete | Self-healing: Learning engine + model persistence |
| SH-4 | Complete | Self-healing: Healing audit log + Slack alerts |

---

## 🔗 Related project

This gateway protects the [Kronos Oracle Global Payroll System](https://github.com/sumitbiswas13/kronos-oracle-global-payroll-system).

---

## 📄 License

MIT

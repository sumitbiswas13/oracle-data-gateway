"""
Stream Processor
Consumes events from Kafka topics and triggers downstream actions:
- Alert on blocked requests
- Alert on anomalies
- Aggregate metrics in real time
- Trigger webhooks for critical events
"""

import json
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional, Callable
from gateway.streaming.kafka_publisher import MockKafkaPublisher, KafkaTopic


class AlertSeverity:
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class StreamProcessor:
    """
    Processes the Kafka event stream in real time.
    In production, runs as a separate Kafka consumer service.
    For demo, processes events from the MockKafkaPublisher in memory.
    """

    def __init__(self, publisher: MockKafkaPublisher):
        self.publisher    = publisher
        self._alerts:     list[dict] = []
        self._metrics:    dict = defaultdict(int)
        self._user_stats: dict = defaultdict(lambda: defaultdict(int))
        self._webhooks:   list[Callable] = []

    def register_webhook(self, handler: Callable):
        """Register a webhook handler called on CRITICAL events."""
        self._webhooks.append(handler)

    def process_all(self):
        """Process all unread events from all topics."""
        # Process blocked requests
        for msg in self.publisher.consume(KafkaTopic.BLOCKED_REQUESTS, limit=100):
            self._handle_blocked(msg)

        # Process anomalies
        for msg in self.publisher.consume(KafkaTopic.ANOMALIES, limit=100):
            self._handle_anomaly(msg)

        # Process data access — build metrics
        for msg in self.publisher.consume(KafkaTopic.DATA_ACCESS, limit=100):
            self._handle_data_access(msg)

    def _handle_blocked(self, msg: dict):
        alert = {
            "type":      "BLOCKED_REQUEST",
            "severity":  AlertSeverity.HIGH,
            "user_id":   msg.get("user_id"),
            "endpoint":  msg.get("endpoint"),
            "reason":    msg.get("blocked_reason"),
            "timestamp": msg.get("timestamp"),
        }
        self._alerts.append(alert)
        self._metrics["total_blocked"] += 1
        uid = msg.get("user_id", "unknown")
        self._user_stats[uid]["blocked"] += 1

        # Trigger webhook for repeated blocks from same user
        if self._user_stats[uid]["blocked"] >= 3:
            self._fire_webhooks({
                "severity": AlertSeverity.CRITICAL,
                "message":  f"User {uid} has been blocked {self._user_stats[uid]['blocked']} times",
                "user_id":  uid,
            })

    def _handle_anomaly(self, msg: dict):
        alert = {
            "type":      "ANOMALY",
            "severity":  AlertSeverity.CRITICAL,
            "user_id":   msg.get("user_id"),
            "table":     msg.get("table"),
            "reason":    msg.get("flagged_reason"),
            "timestamp": msg.get("timestamp"),
        }
        self._alerts.append(alert)
        self._metrics["total_anomalies"] += 1
        self._fire_webhooks(alert)

    def _handle_data_access(self, msg: dict):
        self._metrics["total_allowed"]     += 1
        self._metrics["total_rows_served"] += msg.get("rows_affected", 0)
        uid = msg.get("user_id", "unknown")
        self._user_stats[uid]["allowed"] += 1
        tbl = msg.get("table", "unknown")
        self._metrics[f"table:{tbl}"] += 1

    def _fire_webhooks(self, payload: dict):
        for handler in self._webhooks:
            try:
                handler(payload)
            except Exception:
                pass

    def get_alerts(self, severity: Optional[str] = None) -> list[dict]:
        if severity:
            return [a for a in self._alerts if a["severity"] == severity]
        return self._alerts

    def get_metrics(self) -> dict:
        topic_counts = self.publisher.get_topic_counts()
        return {
            "events_published":    self.publisher.get_stats()["published"],
            "total_allowed":       self._metrics["total_allowed"],
            "total_blocked":       self._metrics["total_blocked"],
            "total_anomalies":     self._metrics["total_anomalies"],
            "total_rows_served":   self._metrics["total_rows_served"],
            "total_alerts":        len(self._alerts),
            "topic_counts":        topic_counts,
            "top_users":           dict(self._user_stats),
        }

    def get_top_tables(self) -> list[tuple[str, int]]:
        tables = [(k.replace("table:", ""), v)
                  for k, v in self._metrics.items() if k.startswith("table:")]
        return sorted(tables, key=lambda x: x[1], reverse=True)

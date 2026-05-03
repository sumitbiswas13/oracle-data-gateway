"""
Kafka Event Publisher
Publishes every gateway ingress/egress event to Kafka topics.
Mock publisher for demo — swap KafkaEventPublisher for real when Kafka is available.
Both implement EventPublisherBase — no other code changes needed.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import asdict
from datetime import datetime
from typing import Optional
from core.engine import GatewayEvent


# ── Topics ────────────────────────────────────────────────────
class KafkaTopic:
    ALL_EVENTS        = "gateway.events.all"
    BLOCKED_REQUESTS  = "gateway.events.blocked"
    ANOMALIES         = "gateway.events.anomalies"
    DATA_ACCESS       = "gateway.events.data_access"
    AUDIT_TRAIL       = "gateway.audit.trail"


def _route_event(event: GatewayEvent) -> list[str]:
    """Route an event to the appropriate Kafka topics."""
    topics = [KafkaTopic.ALL_EVENTS, KafkaTopic.AUDIT_TRAIL]

    if event.event_type == "REQUEST_BLOCKED":
        topics.append(KafkaTopic.BLOCKED_REQUESTS)
    elif event.event_type == "ANOMALY_DETECTED":
        topics.append(KafkaTopic.ANOMALIES)
    elif event.event_type == "REQUEST_ALLOWED":
        topics.append(KafkaTopic.DATA_ACCESS)

    return topics


def _serialize(event: GatewayEvent) -> str:
    """Serialize event to JSON string."""
    data = {
        "event_id":       event.event_id,
        "event_type":     event.event_type,
        "request_id":     event.request_id,
        "direction":      event.direction,
        "user_id":        event.user_id,
        "user_role":      event.user_role,
        "client_ip":      event.client_ip,
        "endpoint":       event.endpoint,
        "table":          event.table,
        "status":         event.status,
        "rows_affected":  event.rows_affected,
        "blocked_reason": event.blocked_reason,
        "flagged_reason": event.flagged_reason,
        "timestamp":      event.timestamp.isoformat(),
    }
    return json.dumps(data)


# ── Base interface ────────────────────────────────────────────
class EventPublisherBase(ABC):
    @abstractmethod
    def publish(self, event: GatewayEvent) -> bool:
        pass

    @abstractmethod
    def get_stats(self) -> dict:
        pass


# ── Mock publisher ────────────────────────────────────────────
class MockKafkaPublisher(EventPublisherBase):
    """
    In-memory Kafka mock. Simulates topic routing and message delivery.
    Replace with KafkaEventPublisher when a real Kafka cluster is available.
    """

    def __init__(self):
        self._topics: dict[str, list[dict]] = {
            KafkaTopic.ALL_EVENTS:       [],
            KafkaTopic.BLOCKED_REQUESTS: [],
            KafkaTopic.ANOMALIES:        [],
            KafkaTopic.DATA_ACCESS:      [],
            KafkaTopic.AUDIT_TRAIL:      [],
        }
        self._published_count = 0
        self._failed_count    = 0

    def publish(self, event: GatewayEvent) -> bool:
        try:
            topics   = _route_event(event)
            payload  = json.loads(_serialize(event))
            for topic in topics:
                self._topics[topic].append(payload)
            self._published_count += 1
            return True
        except Exception:
            self._failed_count += 1
            return False

    def consume(self, topic: str, limit: int = 10) -> list[dict]:
        """Simulate a Kafka consumer reading from a topic."""
        messages = self._topics.get(topic, [])
        return list(reversed(messages[-limit:]))

    def get_topic_counts(self) -> dict[str, int]:
        return {t: len(msgs) for t, msgs in self._topics.items()}

    def get_stats(self) -> dict:
        return {
            "published":    self._published_count,
            "failed":       self._failed_count,
            "topics":       self.get_topic_counts(),
        }

    def list_topics(self) -> list[str]:
        return list(self._topics.keys())


# ── Real Kafka publisher ──────────────────────────────────────
class KafkaEventPublisher(EventPublisherBase):
    """
    Production Kafka publisher using kafka-python.
    Swap MockKafkaPublisher → KafkaEventPublisher in config.
    No other code changes required.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:9092",
        client_id: str = "oracle-data-gateway",
    ):
        self.bootstrap_servers = bootstrap_servers
        self.client_id         = client_id
        self._producer         = None
        self._published_count  = 0
        self._failed_count     = 0

    def _get_producer(self):
        if not self._producer:
            from kafka import KafkaProducer
            self._producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                client_id=self.client_id,
                value_serializer=lambda v: v.encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",                 # Wait for all replicas
                retries=3,
                linger_ms=5,               # Small batching window
            )
        return self._producer

    def publish(self, event: GatewayEvent) -> bool:
        try:
            producer = self._get_producer()
            topics   = _route_event(event)
            payload  = _serialize(event)
            key      = event.user_id or event.request_id

            for topic in topics:
                producer.send(topic, key=key, value=payload)

            producer.flush(timeout=5)
            self._published_count += 1
            return True
        except Exception as e:
            self._failed_count += 1
            print(f"⚠️  Kafka publish failed: {e}")
            return False

    def get_stats(self) -> dict:
        return {
            "published": self._published_count,
            "failed":    self._failed_count,
            "broker":    self.bootstrap_servers,
        }

    def close(self):
        if self._producer:
            self._producer.close()

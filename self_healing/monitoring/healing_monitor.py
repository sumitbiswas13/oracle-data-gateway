"""
Healing Audit Log + Alert System
Records every autonomous action the gateway takes and fires alerts.
Tesla parallel: Tesla's event data recorder — logs everything the car does autonomously
so engineers can review, audit, and improve the system.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from self_healing.actions.executor import HealingAction, ActionType


# ── Alert channels ────────────────────────────────────────────

class AlertChannel:
    SLACK   = "SLACK"
    WEBHOOK = "WEBHOOK"
    EMAIL   = "EMAIL"
    LOG     = "LOG"


# ── Alert severity mapping ────────────────────────────────────

ACTION_SEVERITY = {
    ActionType.BLOCK_IP:           "CRITICAL",
    ActionType.REVOKE_TOKEN:       "CRITICAL",
    ActionType.DOWNGRADE_ROLE:     "HIGH",
    ActionType.TIGHTEN_RATE_LIMIT: "MEDIUM",
    ActionType.RESTORE_ROLE:       "INFO",
    ActionType.UNBLOCK_IP:         "INFO",
    ActionType.RESTORE_RATE_LIMIT: "INFO",
    ActionType.ALERT_ADMIN:        "HIGH",
    ActionType.LOG_HEALING_ACTION: "LOW",
}


@dataclass
class HealingAuditEntry:
    """One entry in the healing audit log."""
    entry_id:       str
    action:         HealingAction
    threat_type:    str
    severity:       str
    alert_fired:    bool
    alert_channels: list[str]
    human_review:   bool          # Should a human review this?
    notes:          str = ""
    timestamp:      datetime = field(default_factory=datetime.utcnow)


@dataclass
class HealingReport:
    """A summary report of all autonomous healing activity."""
    report_id:       str
    period_start:    datetime
    period_end:      datetime
    total_actions:   int
    actions_by_type: dict
    top_targets:     list[dict]
    threshold_changes: list[dict]
    alerts_fired:    int
    human_reviews:   int
    summary:         str
    generated_at:    datetime = field(default_factory=datetime.utcnow)


class HealingAuditLogger:
    """
    Logs every autonomous healing action with full context.
    Tesla parallel: Tesla's shadow mode + event recorder.
    Every autonomous decision is logged so humans can:
    1. Audit what the system did
    2. Verify it made the right call
    3. Identify false positives
    4. Feed corrections back into the learning engine
    """

    def __init__(self):
        self._entries: list[HealingAuditEntry] = []
        self._counter = 0

    def log(self, action: HealingAction, threat_type: str = "UNKNOWN") -> HealingAuditEntry:
        self._counter += 1
        severity     = ACTION_SEVERITY.get(action.action_type, "MEDIUM")
        human_review = severity in ("CRITICAL", "HIGH")

        entry = HealingAuditEntry(
            entry_id=f"HEAL-{self._counter:04d}",
            action=action,
            threat_type=threat_type,
            severity=severity,
            alert_fired=False,
            alert_channels=[],
            human_review=human_review,
        )
        self._entries.append(entry)
        return entry

    def get_entries(self, limit: int = 50, severity: str = None) -> list[HealingAuditEntry]:
        entries = list(reversed(self._entries))
        if severity:
            entries = [e for e in entries if e.severity == severity]
        return entries[:limit]

    def get_pending_review(self) -> list[HealingAuditEntry]:
        return [e for e in self._entries if e.human_review]

    def generate_report(
        self,
        period_start: Optional[datetime] = None,
        period_end:   Optional[datetime] = None,
        threshold_updates: list = None,
    ) -> HealingReport:
        period_start = period_start or (datetime.utcnow() - timedelta(hours=24))
        period_end   = period_end   or datetime.utcnow()

        entries = [
            e for e in self._entries
            if period_start <= e.timestamp <= period_end
        ] or self._entries

        by_type  = defaultdict(int)
        by_target = defaultdict(int)
        for e in entries:
            by_type[e.action.action_type.value] += 1
            by_target[e.action.target] += 1

        top_targets = sorted(
            [{"target": t, "actions": c} for t, c in by_target.items()],
            key=lambda x: x["actions"], reverse=True
        )[:5]

        threshold_summary = []
        for u in (threshold_updates or []):
            threshold_summary.append({
                "parameter": u.parameter,
                "old":       u.old_value,
                "new":       u.new_value,
                "direction": "tighter" if u.new_value < u.old_value else "relaxed",
            })

        alerts  = sum(1 for e in entries if e.alert_fired)
        reviews = sum(1 for e in entries if e.human_review)
        critical = sum(1 for e in entries if e.severity == "CRITICAL")

        summary = (
            f"Gateway took {len(entries)} autonomous healing actions in this period. "
            f"{critical} critical actions fired. "
            f"{len(threshold_summary)} thresholds updated by learning engine. "
            f"{reviews} actions flagged for human review. "
            f"Top target: {top_targets[0]['target'] if top_targets else 'none'} "
            f"({top_targets[0]['actions'] if top_targets else 0} actions)."
        )

        return HealingReport(
            report_id=f"HEAL-RPT-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            period_start=period_start,
            period_end=period_end,
            total_actions=len(entries),
            actions_by_type=dict(by_type),
            top_targets=top_targets,
            threshold_changes=threshold_summary,
            alerts_fired=alerts,
            human_reviews=reviews,
            summary=summary,
        )

    def export_json(self, path: str, report: HealingReport):
        data = {
            "report_id":       report.report_id,
            "generated_at":    report.generated_at.isoformat(),
            "period_start":    report.period_start.isoformat(),
            "period_end":      report.period_end.isoformat(),
            "total_actions":   report.total_actions,
            "actions_by_type": report.actions_by_type,
            "top_targets":     report.top_targets,
            "threshold_changes": report.threshold_changes,
            "alerts_fired":    report.alerts_fired,
            "human_reviews":   report.human_reviews,
            "summary":         report.summary,
            "entries": [
                {
                    "entry_id":     e.entry_id,
                    "action_id":    e.action.action_id,
                    "action_type":  e.action.action_type.value,
                    "target":       e.action.target,
                    "reason":       e.action.reason,
                    "threat_score": e.action.threat_score,
                    "severity":     e.severity,
                    "threat_type":  e.threat_type,
                    "human_review": e.human_review,
                    "old_value":    e.action.old_value,
                    "new_value":    e.action.new_value,
                    "timestamp":    e.timestamp.isoformat(),
                }
                for e in self._entries
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path


class AlertManager:
    """
    Fires alerts when the gateway takes autonomous actions.
    Supports Slack webhooks, generic webhooks, and console logging.
    Tesla parallel: Tesla's alert system that notifies engineers
    when FSD encounters a situation it hasn't seen before.
    """

    # Emoji per action type for Slack messages
    ACTION_EMOJI = {
        ActionType.BLOCK_IP:           "🚫",
        ActionType.REVOKE_TOKEN:       "🔑",
        ActionType.DOWNGRADE_ROLE:     "⬇️",
        ActionType.TIGHTEN_RATE_LIMIT: "🐌",
        ActionType.RESTORE_ROLE:       "✅",
        ActionType.UNBLOCK_IP:         "✅",
    }

    def __init__(self, audit_logger: HealingAuditLogger):
        self._logger   = audit_logger
        self._handlers = []        # List of (channel, handler_fn)
        self._fired:   list[dict] = []

    def register_slack(self, webhook_url: str):
        """Register a real Slack webhook URL."""
        try:
            import httpx
            def slack_handler(payload: dict):
                httpx.post(webhook_url, json={"text": payload["text"]}, timeout=5)
            self._handlers.append((AlertChannel.SLACK, slack_handler))
        except ImportError:
            print("  ⚠️  httpx not available for Slack webhook")

    def register_mock_slack(self):
        """Register a mock Slack handler that prints to console."""
        def mock_slack(payload: dict):
            print(f"\n  ┌─ SLACK ALERT {'─'*42}")
            for line in payload["text"].split("\n"):
                print(f"  │ {line}")
            print(f"  └{'─'*50}\n")
        self._handlers.append((AlertChannel.SLACK, mock_slack))

    def register_webhook(self, url_or_fn):
        """Register a generic webhook (URL string or callable)."""
        if callable(url_or_fn):
            self._handlers.append((AlertChannel.WEBHOOK, url_or_fn))
        else:
            try:
                import httpx
                def webhook_handler(payload: dict):
                    httpx.post(url_or_fn, json=payload, timeout=5)
                self._handlers.append((AlertChannel.WEBHOOK, webhook_handler))
            except ImportError:
                pass

    def alert(self, action: HealingAction, threat_type: str = "UNKNOWN"):
        """Fire an alert for an autonomous healing action."""
        entry    = self._logger.log(action, threat_type)
        severity = ACTION_SEVERITY.get(action.action_type, "MEDIUM")

        # Only alert on MEDIUM and above
        if severity not in ("MEDIUM", "HIGH", "CRITICAL"):
            return entry

        payload  = self._build_payload(action, entry, severity)
        channels = []

        for channel, handler in self._handlers:
            try:
                handler(payload)
                channels.append(channel)
            except Exception as e:
                print(f"  ⚠️  Alert failed ({channel}): {e}")

        entry.alert_fired    = bool(channels)
        entry.alert_channels = channels
        self._fired.append(payload)

        return entry

    def _build_payload(self, action: HealingAction, entry: HealingAuditEntry, severity: str) -> dict:
        emoji  = self.ACTION_EMOJI.get(action.action_type, "⚡")
        sev_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(severity,"⚪")
        duration = f" for {action.duration_mins}min" if action.duration_mins else ""
        change   = f" ({action.old_value} → {action.new_value})" if action.old_value else ""

        text = (
            f"{sev_emoji} *GATEWAY AUTO-HEALED* [{severity}]\n"
            f"{emoji} *Action:* `{action.action_type.value}`{duration}{change}\n"
            f"🎯 *Target:* `{action.target}`\n"
            f"⚠️  *Reason:* {action.reason}\n"
            f"📊 *Threat score:* {action.threat_score}/100\n"
            f"🔖 *Entry:* `{entry.entry_id}` · {action.executed_at.strftime('%H:%M:%S UTC')}\n"
            f"👤 *Human review:* {'Required' if entry.human_review else 'Not required'}"
        )
        return {
            "text":       text,
            "entry_id":   entry.entry_id,
            "action":     action.action_type.value,
            "target":     action.target,
            "severity":   severity,
            "score":      action.threat_score,
            "timestamp":  action.executed_at.isoformat(),
        }

    def get_fired(self) -> list[dict]:
        return self._fired

    def get_stats(self) -> dict:
        by_severity = defaultdict(int)
        for p in self._fired:
            by_severity[p["severity"]] += 1
        return {
            "total_alerts":    len(self._fired),
            "by_severity":     dict(by_severity),
            "channels_active": list({ch for ch, _ in self._handlers}),
        }

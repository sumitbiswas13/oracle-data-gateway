"""
Decision Engine
Maps threat signals + risk scores → autonomous actions.
Tesla parallel: the FSD neural network — takes sensor data and decides what to do.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from self_healing.sensors.threat_sensor import ThreatSignal, ThreatType, ThreatSeverity
from self_healing.sensors.anomaly_scorer import RiskProfile, AnomalyScorer
from self_healing.actions.executor import ActionExecutor, ActionType, ActionResult


# ── Decision rules ────────────────────────────────────────────
# Each rule maps: (risk_band, threat_types) → list of actions to take
# Rules are evaluated in order — first match wins per signal

DECISION_RULES = [
    # CRITICAL — immediate hard response
    {
        "name":        "Critical SQL injection → block IP + revoke token",
        "min_score":   85,
        "threats":     {ThreatType.SQL_INJECTION},
        "actions":     [ActionType.BLOCK_IP, ActionType.REVOKE_TOKEN, ActionType.ALERT_ADMIN],
        "block_mins":  60,
    },
    {
        "name":        "Critical brute force → block IP",
        "min_score":   80,
        "threats":     {ThreatType.BRUTE_FORCE},
        "actions":     [ActionType.BLOCK_IP, ActionType.ALERT_ADMIN],
        "block_mins":  30,
    },
    {
        "name":        "Critical credential stuffing → block IP",
        "min_score":   75,
        "threats":     {ThreatType.CREDENTIAL_STUFFING},
        "actions":     [ActionType.BLOCK_IP, ActionType.ALERT_ADMIN],
        "block_mins":  45,
    },
    # HIGH — role + rate limit response
    {
        "name":        "High data harvesting → downgrade role",
        "min_score":   70,
        "threats":     {ThreatType.DATA_HARVESTING},
        "actions":     [ActionType.DOWNGRADE_ROLE, ActionType.TIGHTEN_RATE_LIMIT, ActionType.ALERT_ADMIN],
        "block_mins":  None,
    },
    {
        "name":        "High velocity attack → tighten rate limit",
        "min_score":   60,
        "threats":     {ThreatType.VELOCITY_ATTACK},
        "actions":     [ActionType.TIGHTEN_RATE_LIMIT, ActionType.ALERT_ADMIN],
        "block_mins":  None,
    },
    # MEDIUM — soft response
    {
        "name":        "Medium table enumeration → tighten rate limit",
        "min_score":   50,
        "threats":     {ThreatType.TABLE_ENUMERATION},
        "actions":     [ActionType.TIGHTEN_RATE_LIMIT],
        "block_mins":  None,
    },
    {
        "name":        "Medium odd-hour sweep → alert only",
        "min_score":   40,
        "threats":     {ThreatType.ODD_HOUR_SWEEP},
        "actions":     [ActionType.ALERT_ADMIN],
        "block_mins":  None,
    },
]

# Role map for decision context
TOKEN_ROLES = {
    "tok_admin_001":   "ADMIN",
    "tok_manager_001": "MANAGER",
    "tok_analyst_001": "ANALYST",
    "tok_readonly_001":"READONLY",
}


@dataclass
class Decision:
    """A single autonomous decision made by the engine."""
    decision_id:   str
    rule_matched:  str
    signal:        ThreatSignal
    actions_taken: list[ActionResult] = field(default_factory=list)
    timestamp:     datetime = field(default_factory=datetime.utcnow)

    @property
    def summary(self) -> str:
        acts = [r.action.action_type.value for r in self.actions_taken if r.success]
        return f"[{self.signal.risk_score:.0f}] {self.rule_matched} → {', '.join(acts)}"


class DecisionEngine:
    """
    The autonomous brain of the self-healing gateway.
    Receives threat signals, evaluates rules, fires actions.
    Tesla parallel: FSD neural network — perceive → decide → act in real time.
    """

    def __init__(self, executor: ActionExecutor, scorer: AnomalyScorer):
        self._executor  = executor
        self._scorer    = scorer
        self._decisions: list[Decision] = []
        self._counter   = 0
        self._already_acted: set[str] = set()  # Deduplicate — don't act twice on same entity

    def evaluate(self, signals: list[ThreatSignal]) -> list[Decision]:
        """
        Evaluate threat signals and take autonomous action where warranted.
        Called after every gateway event.
        """
        decisions = []

        for signal in signals:
            self._counter += 1
            decision_id = f"DEC-{self._counter:04d}"

            # Find matching rule
            rule = self._match_rule(signal)
            if not rule:
                continue

            # Deduplicate — don't keep re-acting on same entity for same threat
            dedup_key = f"{signal.source_ip or signal.user_id}:{signal.threat_type.value}"
            if dedup_key in self._already_acted and signal.risk_score < 90:
                continue
            self._already_acted.add(dedup_key)

            decision = Decision(decision_id=decision_id, rule_matched=rule["name"], signal=signal)

            # Execute each action in the rule
            for action_type in rule["actions"]:
                result = self._execute_action(
                    action_type=action_type,
                    signal=signal,
                    block_mins=rule.get("block_mins", 30),
                )
                if result:
                    decision.actions_taken.append(result)

            if decision.actions_taken:
                decisions.append(decision)
                self._decisions.append(decision)

        return decisions

    def _match_rule(self, signal: ThreatSignal) -> Optional[dict]:
        """Find the first matching decision rule for a signal."""
        for rule in DECISION_RULES:
            if signal.risk_score >= rule["min_score"]:
                if signal.threat_type in rule["threats"]:
                    return rule
        return None

    def _execute_action(
        self,
        action_type: ActionType,
        signal: ThreatSignal,
        block_mins: Optional[int],
    ) -> Optional[ActionResult]:
        ip      = signal.source_ip or "unknown"
        user_id = signal.user_id   or "unknown"
        reason  = signal.description
        score   = signal.risk_score

        if action_type == ActionType.BLOCK_IP and ip != "unknown":
            return self._executor.block_ip(ip, reason, score, block_mins or 30)

        elif action_type == ActionType.REVOKE_TOKEN and user_id != "unknown":
            return self._executor.revoke_token(user_id, reason, score)

        elif action_type == ActionType.DOWNGRADE_ROLE and user_id != "unknown":
            current_role = TOKEN_ROLES.get(user_id, "READONLY")
            effective    = self._executor.get_effective_role(user_id, current_role)
            return self._executor.downgrade_role(user_id, effective, reason, score)

        elif action_type == ActionType.TIGHTEN_RATE_LIMIT and user_id != "unknown":
            return self._executor.tighten_rate_limit(user_id, reason, score)

        elif action_type == ActionType.ALERT_ADMIN:
            # Alert is fired inside executor._alert via the webhook
            return None

        return None

    def get_decisions(self, limit: int = 20) -> list[Decision]:
        return list(reversed(self._decisions[-limit:]))

    def get_stats(self) -> dict:
        return {
            "total_decisions":  len(self._decisions),
            "executor_stats":   self._executor.get_stats(),
            "active_state":     self._executor.get_active_state(),
        }

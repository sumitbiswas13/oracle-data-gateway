"""
Action Executor
Executes autonomous responses to threats.
Tesla parallel: the actuators — steers, brakes, accelerates based on FSD decisions.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from enum import Enum
from collections import defaultdict


class ActionType(str, Enum):
    BLOCK_IP           = "BLOCK_IP"           # Ban IP for N minutes
    UNBLOCK_IP         = "UNBLOCK_IP"         # Lift IP ban
    REVOKE_TOKEN       = "REVOKE_TOKEN"       # Invalidate user token
    DOWNGRADE_ROLE     = "DOWNGRADE_ROLE"     # Reduce user permissions
    RESTORE_ROLE       = "RESTORE_ROLE"       # Restore original role
    TIGHTEN_RATE_LIMIT = "TIGHTEN_RATE_LIMIT" # Reduce rate limit for user
    RESTORE_RATE_LIMIT = "RESTORE_RATE_LIMIT" # Restore original rate limit
    ALERT_ADMIN        = "ALERT_ADMIN"        # Fire webhook alert
    LOG_HEALING_ACTION = "LOG_HEALING_ACTION" # Write to healing audit log


@dataclass
class HealingAction:
    """A single autonomous action taken by the gateway."""
    action_id:      str
    action_type:    ActionType
    target:         str               # IP or user_id
    reason:         str
    threat_score:   float
    duration_mins:  Optional[int] = None   # For temporary actions
    old_value:      Optional[str] = None   # What it was before
    new_value:      Optional[str] = None   # What it changed to
    reversible:     bool = True
    executed_at:    datetime = field(default_factory=datetime.utcnow)
    expires_at:     Optional[datetime] = None
    success:        bool = True


@dataclass
class ActionResult:
    action:   HealingAction
    success:  bool
    message:  str


class ActionExecutor:
    """
    Executes autonomous healing actions.
    Maintains state of all active blocks, downgrades, and rate limit changes.
    Tesla parallel: the actuator layer — receives a decision and executes it.
    """

    # Default durations for temporary actions (minutes)
    DEFAULT_DURATIONS = {
        ActionType.BLOCK_IP:           30,
        ActionType.DOWNGRADE_ROLE:     60,
        ActionType.TIGHTEN_RATE_LIMIT: 15,
        ActionType.REVOKE_TOKEN:       None,  # Permanent until manual restore
    }

    # Role downgrade map
    ROLE_DOWNGRADE = {
        "ADMIN":    "MANAGER",
        "MANAGER":  "ANALYST",
        "ANALYST":  "READONLY",
        "READONLY": "READONLY",
    }

    # Rate limit tightening (% of original)
    RATE_TIGHTEN_PCT = 0.3   # Reduce to 30% of normal

    def __init__(self):
        self._blocked_ips:      dict[str, datetime]  = {}   # ip → expiry
        self._revoked_tokens:   set[str]              = set()
        self._downgraded_roles: dict[str, tuple]      = {}   # user → (old, new, expiry)
        self._rate_adjustments: dict[str, tuple]      = {}   # user → (factor, expiry)
        self._action_log:       list[HealingAction]   = []
        self._action_counter:   int                   = 0
        self._webhook_handler   = None

    def register_webhook(self, handler):
        """Register a webhook handler for admin alerts."""
        self._webhook_handler = handler

    # ── Primary actions ───────────────────────────────────────

    def block_ip(self, ip: str, reason: str, score: float, duration_mins: int = 30) -> ActionResult:
        expiry = datetime.utcnow() + timedelta(minutes=duration_mins)
        self._blocked_ips[ip] = expiry
        action = self._log(ActionType.BLOCK_IP, ip, reason, score,
                          duration_mins=duration_mins,
                          new_value=f"BLOCKED until {expiry.strftime('%H:%M:%S')} UTC")
        self._alert(f"🚫 IP BLOCKED: {ip} for {duration_mins}min — {reason} (score={score})")
        return ActionResult(action, True, f"IP {ip} blocked for {duration_mins} minutes")

    def revoke_token(self, user_id: str, reason: str, score: float) -> ActionResult:
        self._revoked_tokens.add(user_id)
        action = self._log(ActionType.REVOKE_TOKEN, user_id, reason, score,
                          new_value="REVOKED", reversible=False)
        self._alert(f"🔑 TOKEN REVOKED: {user_id} — {reason} (score={score})")
        return ActionResult(action, True, f"Token for {user_id} revoked")

    def downgrade_role(self, user_id: str, current_role: str, reason: str, score: float,
                       duration_mins: int = 60) -> ActionResult:
        new_role = self.ROLE_DOWNGRADE.get(current_role, "READONLY")
        if new_role == current_role:
            return ActionResult(
                self._log(ActionType.DOWNGRADE_ROLE, user_id, "Already at minimum role", score),
                False, "Already at minimum role"
            )
        expiry = datetime.utcnow() + timedelta(minutes=duration_mins)
        self._downgraded_roles[user_id] = (current_role, new_role, expiry)
        action = self._log(ActionType.DOWNGRADE_ROLE, user_id, reason, score,
                          duration_mins=duration_mins,
                          old_value=current_role, new_value=new_role)
        self._alert(f"⬇️  ROLE DOWNGRADED: {user_id} {current_role}→{new_role} for {duration_mins}min (score={score})")
        return ActionResult(action, True, f"Role for {user_id} downgraded {current_role}→{new_role}")

    def tighten_rate_limit(self, user_id: str, reason: str, score: float,
                           duration_mins: int = 15) -> ActionResult:
        expiry = datetime.utcnow() + timedelta(minutes=duration_mins)
        self._rate_adjustments[user_id] = (self.RATE_TIGHTEN_PCT, expiry)
        action = self._log(ActionType.TIGHTEN_RATE_LIMIT, user_id, reason, score,
                          duration_mins=duration_mins,
                          old_value="100%", new_value=f"{int(self.RATE_TIGHTEN_PCT*100)}%")
        self._alert(f"🐌 RATE TIGHTENED: {user_id} to {int(self.RATE_TIGHTEN_PCT*100)}% for {duration_mins}min (score={score})")
        return ActionResult(action, True, f"Rate limit for {user_id} reduced to {int(self.RATE_TIGHTEN_PCT*100)}%")

    # ── State checks ──────────────────────────────────────────

    def is_ip_blocked(self, ip: str) -> bool:
        if ip not in self._blocked_ips:
            return False
        if datetime.utcnow() > self._blocked_ips[ip]:
            del self._blocked_ips[ip]
            return False
        return True

    def is_token_revoked(self, user_id: str) -> bool:
        return user_id in self._revoked_tokens

    def get_effective_role(self, user_id: str, original_role: str) -> str:
        if user_id not in self._downgraded_roles:
            return original_role
        old, new, expiry = self._downgraded_roles[user_id]
        if datetime.utcnow() > expiry:
            del self._downgraded_roles[user_id]
            return original_role
        return new

    def get_rate_factor(self, user_id: str) -> float:
        if user_id not in self._rate_adjustments:
            return 1.0
        factor, expiry = self._rate_adjustments[user_id]
        if datetime.utcnow() > expiry:
            del self._rate_adjustments[user_id]
            return 1.0
        return factor

    # ── Restoration ───────────────────────────────────────────

    def unblock_ip(self, ip: str) -> ActionResult:
        self._blocked_ips.pop(ip, None)
        action = self._log(ActionType.UNBLOCK_IP, ip, "Manual unblock", 0)
        return ActionResult(action, True, f"IP {ip} unblocked")

    def restore_role(self, user_id: str) -> ActionResult:
        entry = self._downgraded_roles.pop(user_id, None)
        old_role = entry[0] if entry else "UNKNOWN"
        action = self._log(ActionType.RESTORE_ROLE, user_id, "Manual restore", 0,
                          old_value=entry[1] if entry else "?", new_value=old_role)
        return ActionResult(action, True, f"Role for {user_id} restored to {old_role}")

    # ── State summary ─────────────────────────────────────────

    def get_active_state(self) -> dict:
        now = datetime.utcnow()
        return {
            "blocked_ips": {
                ip: exp.strftime("%H:%M:%S UTC")
                for ip, exp in self._blocked_ips.items()
                if now < exp
            },
            "revoked_tokens":   list(self._revoked_tokens),
            "downgraded_roles": {
                uid: {"from": old, "to": new, "expires": exp.strftime("%H:%M:%S UTC")}
                for uid, (old, new, exp) in self._downgraded_roles.items()
                if now < exp
            },
            "rate_adjustments": {
                uid: {"factor": f"{int(f*100)}%", "expires": exp.strftime("%H:%M:%S UTC")}
                for uid, (f, exp) in self._rate_adjustments.items()
                if now < exp
            },
        }

    def get_action_log(self, limit: int = 20) -> list[HealingAction]:
        return list(reversed(self._action_log[-limit:]))

    def get_stats(self) -> dict:
        by_type = defaultdict(int)
        for a in self._action_log:
            by_type[a.action_type.value] += 1
        return {
            "total_actions":   len(self._action_log),
            "actions_by_type": dict(by_type),
            "active_blocks":   len(self._blocked_ips),
            "revoked_tokens":  len(self._revoked_tokens),
            "downgraded_roles":len(self._downgraded_roles),
        }

    # ── Helpers ───────────────────────────────────────────────

    def _log(self, action_type: ActionType, target: str, reason: str, score: float,
             duration_mins: int = None, old_value: str = None,
             new_value: str = None, reversible: bool = True) -> HealingAction:
        self._action_counter += 1
        action = HealingAction(
            action_id=f"ACT-{self._action_counter:04d}",
            action_type=action_type,
            target=target,
            reason=reason,
            threat_score=score,
            duration_mins=duration_mins,
            old_value=old_value,
            new_value=new_value,
            reversible=reversible,
            expires_at=(datetime.utcnow() + timedelta(minutes=duration_mins))
                       if duration_mins else None,
        )
        self._action_log.append(action)
        return action

    def _alert(self, message: str):
        if self._webhook_handler:
            try:
                self._webhook_handler({"message": message, "timestamp": datetime.utcnow().isoformat()})
            except Exception:
                pass

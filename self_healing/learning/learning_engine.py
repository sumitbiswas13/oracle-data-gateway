"""
Self-Learning Engine
Analyses attack history and automatically updates detection thresholds.
Tesla parallel: Tesla's fleet learning — every car's experience improves the whole fleet.
The gateway learns from every attack and gets smarter over time.
"""

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
from self_healing.sensors.threat_sensor import ThreatType, ThreatSignal


@dataclass
class ThresholdUpdate:
    """A single threshold adjustment made by the learning engine."""
    threat_type:   ThreatType
    parameter:     str            # What was adjusted e.g. "brute_force_window_secs"
    old_value:     float
    new_value:     float
    reason:        str
    confidence:    float          # 0–1 how confident the engine is
    timestamp:     datetime = field(default_factory=datetime.utcnow)


@dataclass
class LearningSnapshot:
    """A point-in-time snapshot of what the engine has learned."""
    snapshot_id:     str
    period_start:    datetime
    period_end:      datetime
    total_signals:   int
    threat_breakdown: dict
    threshold_updates: list[ThresholdUpdate]
    baseline_metrics: dict
    timestamp:       datetime = field(default_factory=datetime.utcnow)


class SelfLearningEngine:
    """
    Analyses the stream of threat signals over time and automatically
    tightens or relaxes detection thresholds based on observed patterns.

    Tesla parallel: Fleet learning system.
    - Every Tesla sends anonymised driving data back to improve FSD.
    - Every gateway attack updates the detection model.
    - Over time the system gets smarter without manual tuning.

    Three learning strategies:
    1. Frequency learning — if attack type X spikes, lower its threshold
    2. Temporal learning  — if attacks cluster at certain hours, tighten off-hours rules
    3. Entity learning    — if specific IPs/users repeatedly attack, remember them
    """

    # Default thresholds — learning engine adjusts these
    DEFAULT_THRESHOLDS = {
        "brute_force_count":        3,      # Failures before brute force fires
        "brute_force_window_secs":  300,    # Window for counting failures
        "data_harvest_rows":        50,     # Rows before harvest alert fires
        "velocity_rpm":             40,     # Requests/min before velocity fires
        "table_enum_count":         4,      # Tables in window before enum fires
        "table_enum_window_secs":   120,    # Window for table enumeration
        "credential_stuff_users":   4,      # Users from same IP before fires
        "odd_hour_start":           22,     # Hour after which = odd hours
        "odd_hour_end":             7,      # Hour before which = odd hours
    }

    # Learning rate — how aggressively to adjust (0–1)
    LEARNING_RATE = 0.15

    # Min/max bounds to prevent over-tightening
    THRESHOLD_BOUNDS = {
        "brute_force_count":        (2,   10),
        "brute_force_window_secs":  (60,  600),
        "data_harvest_rows":        (10,  500),
        "velocity_rpm":             (10,  200),
        "table_enum_count":         (3,   10),
        "table_enum_window_secs":   (60,  300),
        "credential_stuff_users":   (2,   8),
        "odd_hour_start":           (18,  23),
        "odd_hour_end":             (5,   9),
    }

    def __init__(self):
        self._thresholds     = dict(self.DEFAULT_THRESHOLDS)
        self._signal_history: list[ThreatSignal]        = []
        self._ip_history:     dict[str, list[datetime]] = defaultdict(list)
        self._user_history:   dict[str, list[datetime]] = defaultdict(list)
        self._updates:        list[ThresholdUpdate]     = []
        self._snapshots:      list[LearningSnapshot]    = []
        self._known_bad_ips:  set[str]                  = set()
        self._known_bad_users:set[str]                  = set()

    def observe(self, signals: list[ThreatSignal]):
        """Feed new signals into the learning engine."""
        for s in signals:
            self._signal_history.append(s)
            if s.source_ip:
                self._ip_history[s.source_ip].append(s.timestamp)
                if s.severity.value in ("HIGH", "CRITICAL"):
                    self._known_bad_ips.add(s.source_ip)
            if s.user_id:
                self._user_history[s.user_id].append(s.timestamp)
                if s.severity.value in ("HIGH", "CRITICAL"):
                    self._known_bad_users.add(s.user_id)

    def learn(self) -> list[ThresholdUpdate]:
        """
        Analyse signal history and update thresholds.
        Called periodically — e.g. every hour or after every N signals.
        """
        if len(self._signal_history) < 5:
            return []

        updates = []

        # ── Strategy 1: Frequency learning ───────────────────
        updates += self._learn_from_frequency()

        # ── Strategy 2: Temporal learning ────────────────────
        updates += self._learn_from_temporal_patterns()

        # ── Strategy 3: Entity learning ──────────────────────
        updates += self._learn_from_entities()

        self._updates.extend(updates)
        return updates

    def _learn_from_frequency(self) -> list[ThresholdUpdate]:
        """
        If a threat type is spiking, tighten its threshold.
        If it's rare, relax slightly to reduce false positives.
        """
        updates = []
        recent  = [s for s in self._signal_history if
                   (datetime.utcnow() - s.timestamp).seconds < 3600]

        # Count by type
        counts = defaultdict(int)
        for s in recent:
            counts[s.threat_type] += 1
        total = max(len(recent), 1)

        # Brute force frequency
        bf_rate = counts[ThreatType.BRUTE_FORCE] / total
        if bf_rate > 0.3:  # More than 30% of signals are brute force
            old = self._thresholds["brute_force_count"]
            new = max(self._clamp("brute_force_count",
                      old - self.LEARNING_RATE * old), 2)
            if abs(new - old) >= 0.5:
                self._thresholds["brute_force_count"] = new
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.BRUTE_FORCE,
                    parameter="brute_force_count",
                    old_value=old, new_value=round(new, 1),
                    reason=f"Brute force rate {bf_rate:.0%} in last hour — tightening threshold",
                    confidence=min(bf_rate * 2, 0.95),
                ))
        elif bf_rate < 0.05 and old < self.DEFAULT_THRESHOLDS["brute_force_count"]:
            # Relax if attack rate is low
            old = self._thresholds["brute_force_count"]
            new = min(self._clamp("brute_force_count",
                      old + self.LEARNING_RATE * 0.5), self.DEFAULT_THRESHOLDS["brute_force_count"])
            if abs(new - old) >= 0.3:
                self._thresholds["brute_force_count"] = new
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.BRUTE_FORCE,
                    parameter="brute_force_count",
                    old_value=old, new_value=round(new, 1),
                    reason=f"Low brute force rate {bf_rate:.0%} — relaxing threshold slightly",
                    confidence=0.6,
                ))

        # Data harvesting — tighten row threshold if harvesting is common
        dh_rate = counts[ThreatType.DATA_HARVESTING] / total
        if dh_rate > 0.2:
            old = self._thresholds["data_harvest_rows"]
            new = self._clamp("data_harvest_rows", old * (1 - self.LEARNING_RATE))
            if abs(new - old) >= 2:
                self._thresholds["data_harvest_rows"] = round(new)
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.DATA_HARVESTING,
                    parameter="data_harvest_rows",
                    old_value=old, new_value=round(new),
                    reason=f"Data harvesting rate {dh_rate:.0%} — lowering row threshold",
                    confidence=min(dh_rate * 3, 0.9),
                ))

        # Velocity — tighten RPM threshold
        vel_rate = counts[ThreatType.VELOCITY_ATTACK] / total
        if vel_rate > 0.25:
            old = self._thresholds["velocity_rpm"]
            new = self._clamp("velocity_rpm", old * (1 - self.LEARNING_RATE))
            if abs(new - old) >= 1:
                self._thresholds["velocity_rpm"] = round(new)
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.VELOCITY_ATTACK,
                    parameter="velocity_rpm",
                    old_value=old, new_value=round(new),
                    reason=f"Velocity attack rate {vel_rate:.0%} — lowering RPM threshold",
                    confidence=min(vel_rate * 3, 0.9),
                ))

        return updates

    def _learn_from_temporal_patterns(self) -> list[ThresholdUpdate]:
        """
        If attacks cluster at specific hours, adjust odd-hour boundaries.
        Tesla parallel: learns that a specific road segment is always congested
        at 8am and adjusts routing accordingly.
        """
        updates = []
        if len(self._signal_history) < 10:
            return updates

        hour_counts = defaultdict(int)
        for s in self._signal_history:
            if s.severity.value in ("HIGH", "CRITICAL"):
                hour_counts[s.timestamp.hour] += 1

        if not hour_counts:
            return updates

        # Find peak attack hour
        peak_hour = max(hour_counts, key=hour_counts.get)
        peak_count = hour_counts[peak_hour]
        total_attacks = sum(hour_counts.values())

        if total_attacks < 3:
            return updates

        peak_pct = peak_count / total_attacks

        # If attacks cluster heavily in off-hours, tighten the window
        off_hours = [h for h in hour_counts if not (7 <= h <= 22)]
        off_count = sum(hour_counts[h] for h in off_hours)
        off_pct   = off_count / total_attacks

        if off_pct > 0.6:  # 60%+ of attacks happen off-hours
            old_start = self._thresholds["odd_hour_start"]
            new_start = min(self._clamp("odd_hour_start", old_start - 1), 22)
            if new_start != old_start:
                self._thresholds["odd_hour_start"] = new_start
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.ODD_HOUR_SWEEP,
                    parameter="odd_hour_start",
                    old_value=old_start, new_value=new_start,
                    reason=f"{off_pct:.0%} of attacks occur off-hours — expanding monitoring window",
                    confidence=off_pct,
                ))

        return updates

    def _learn_from_entities(self) -> list[ThresholdUpdate]:
        """
        If specific IPs keep attacking, lower thresholds for those entities.
        Tesla parallel: remembers that a specific intersection is dangerous
        and applies extra caution there in future.
        """
        updates = []

        # IPs that have attacked multiple times
        repeat_offenders = {
            ip: len(times) for ip, times in self._ip_history.items()
            if len(times) >= 3
        }

        if repeat_offenders:
            # Lower the brute force window for repeat offenders
            old = self._thresholds["brute_force_window_secs"]
            new = self._clamp("brute_force_window_secs", old * (1 + self.LEARNING_RATE))
            if abs(new - old) >= 5:
                self._thresholds["brute_force_window_secs"] = round(new)
                updates.append(ThresholdUpdate(
                    threat_type=ThreatType.BRUTE_FORCE,
                    parameter="brute_force_window_secs",
                    old_value=old, new_value=round(new),
                    reason=f"{len(repeat_offenders)} repeat-offender IPs detected — widening detection window",
                    confidence=min(len(repeat_offenders) * 0.2, 0.9),
                ))

        return updates

    def _clamp(self, key: str, value: float) -> float:
        lo, hi = self.THRESHOLD_BOUNDS[key]
        return max(lo, min(hi, value))

    def get_thresholds(self) -> dict:
        return dict(self._thresholds)

    def get_threshold_delta(self) -> dict:
        """Show how much thresholds have changed from defaults."""
        return {
            k: {
                "default": self.DEFAULT_THRESHOLDS[k],
                "current": round(self._thresholds[k], 2),
                "delta":   round(self._thresholds[k] - self.DEFAULT_THRESHOLDS[k], 2),
                "tighter": self._thresholds[k] < self.DEFAULT_THRESHOLDS[k],
            }
            for k in self._thresholds
            if abs(self._thresholds[k] - self.DEFAULT_THRESHOLDS[k]) > 0.01
        }

    def get_known_bad_entities(self) -> dict:
        return {
            "bad_ips":   list(self._known_bad_ips),
            "bad_users": list(self._known_bad_users),
        }

    def take_snapshot(self) -> LearningSnapshot:
        """Take a point-in-time snapshot of what has been learned."""
        counts = defaultdict(int)
        for s in self._signal_history:
            counts[s.threat_type.value] += 1

        snap = LearningSnapshot(
            snapshot_id=f"SNAP-{len(self._snapshots)+1:04d}",
            period_start=(self._signal_history[0].timestamp
                         if self._signal_history else datetime.utcnow()),
            period_end=datetime.utcnow(),
            total_signals=len(self._signal_history),
            threat_breakdown=dict(counts),
            threshold_updates=list(self._updates),
            baseline_metrics={
                "known_bad_ips":   len(self._known_bad_ips),
                "known_bad_users": len(self._known_bad_users),
                "thresholds_tightened": len([
                    k for k, v in self._thresholds.items()
                    if v < self.DEFAULT_THRESHOLDS.get(k, v)
                ]),
            },
        )
        self._snapshots.append(snap)
        return snap

    def export_model(self, path: str):
        """Export learned thresholds to JSON — persist between restarts."""
        model = {
            "exported_at":     datetime.utcnow().isoformat(),
            "thresholds":      self._thresholds,
            "known_bad_ips":   list(self._known_bad_ips),
            "known_bad_users": list(self._known_bad_users),
            "updates_count":   len(self._updates),
        }
        with open(path, "w") as f:
            json.dump(model, f, indent=2)
        return path

    def import_model(self, path: str):
        """Load previously learned thresholds — survive restarts."""
        with open(path) as f:
            model = json.load(f)
        self._thresholds.update(model.get("thresholds", {}))
        self._known_bad_ips.update(model.get("known_bad_ips", []))
        self._known_bad_users.update(model.get("known_bad_users", []))

"""
Data Masking Engine
Masks sensitive fields in egress data based on role and field-level rules.
Rules are defined per table, per field, per role — fully configurable.
"""

import re
import hashlib
from dataclasses import dataclass
from typing import Any, Optional
from enum import Enum


class MaskStrategy(str, Enum):
    REDACT       = "REDACT"        # Replace with ***
    PARTIAL      = "PARTIAL"       # Show first/last N chars
    HASH         = "HASH"          # One-way SHA-256 (preserves uniqueness)
    NULLIFY      = "NULLIFY"       # Replace with None
    FAKE_EMAIL   = "FAKE_EMAIL"    # Replace with fake@masked.com
    SALARY_RANGE = "SALARY_RANGE"  # Replace exact salary with a band


@dataclass
class FieldMaskRule:
    table: str
    field: str
    strategy: MaskStrategy
    allowed_roles: list[str]          # Roles that see the real value
    partial_start: int = 2
    partial_end: int = 2


# ── Masking rules registry ────────────────────────────────────
MASK_RULES: list[FieldMaskRule] = [
    # GPS_EMPLOYEES sensitive fields
    FieldMaskRule("GPS_EMPLOYEES", "EMAIL",       MaskStrategy.FAKE_EMAIL,   ["ADMIN"]),
    FieldMaskRule("GPS_EMPLOYEES", "BASE_SALARY", MaskStrategy.SALARY_RANGE, ["ADMIN", "MANAGER"]),
    FieldMaskRule("GPS_EMPLOYEES", "HOURLY_RATE", MaskStrategy.SALARY_RANGE, ["ADMIN", "MANAGER"]),

    # GPS_PAYSLIPS sensitive fields
    FieldMaskRule("GPS_PAYSLIPS", "GROSS_PAY",  MaskStrategy.REDACT, ["ADMIN", "MANAGER"]),
    FieldMaskRule("GPS_PAYSLIPS", "NET_PAY",    MaskStrategy.REDACT, ["ADMIN", "MANAGER"]),
    FieldMaskRule("GPS_PAYSLIPS", "TOTAL_TAX",  MaskStrategy.REDACT, ["ADMIN", "MANAGER"]),

    # GPS_PAYROLL_RUNS aggregate financials
    FieldMaskRule("GPS_PAYROLL_RUNS", "TOTAL_GROSS", MaskStrategy.REDACT, ["ADMIN"]),
    FieldMaskRule("GPS_PAYROLL_RUNS", "TOTAL_NET",   MaskStrategy.REDACT, ["ADMIN"]),
]


def _apply_strategy(value: Any, rule: FieldMaskRule) -> Any:
    if value is None:
        return None
    str_val = str(value)

    if rule.strategy == MaskStrategy.REDACT:
        return "*" * max(len(str_val), 3)

    elif rule.strategy == MaskStrategy.PARTIAL:
        n = len(str_val)
        s, e = rule.partial_start, rule.partial_end
        if n <= s + e:
            return "*" * n
        return str_val[:s] + "*" * (n - s - e) + str_val[n - e:]

    elif rule.strategy == MaskStrategy.HASH:
        return hashlib.sha256(str_val.encode()).hexdigest()[:12]

    elif rule.strategy == MaskStrategy.NULLIFY:
        return None

    elif rule.strategy == MaskStrategy.FAKE_EMAIL:
        local = hashlib.md5(str_val.encode()).hexdigest()[:8]
        return f"{local}@masked.com"

    elif rule.strategy == MaskStrategy.SALARY_RANGE:
        try:
            amount = float(value)
            if amount < 30000:    return "< 30,000"
            elif amount < 60000:  return "30,000 – 60,000"
            elif amount < 100000: return "60,000 – 100,000"
            elif amount < 200000: return "100,000 – 200,000"
            elif amount < 500000: return "200,000 – 500,000"
            elif amount < 1000000:return "500,000 – 1,000,000"
            else:                 return "> 1,000,000"
        except (ValueError, TypeError):
            return "***"

    return value


class DataMaskingEngine:
    """
    Applies field-level masking rules to egress data.
    Rules determine which roles see real values vs masked values.
    """

    def __init__(self, rules: list[FieldMaskRule] = None):
        self.rules = rules or MASK_RULES

    def mask_row(self, row: dict, table: str, role: str) -> tuple[dict, list[str]]:
        """
        Apply masking to a single row.
        Returns (masked_row, list_of_masked_fields).
        """
        masked_row = dict(row)
        masked_fields = []
        table_upper = table.upper()

        applicable = [r for r in self.rules if r.table == table_upper]

        for rule in applicable:
            field = rule.field
            if field not in masked_row:
                continue
            # If role is NOT in allowed_roles, mask the field
            if role not in rule.allowed_roles:
                masked_row[field] = _apply_strategy(masked_row[field], rule)
                masked_fields.append(field)

        return masked_row, masked_fields

    def mask_dataset(
        self,
        data: list[dict],
        table: str,
        role: str,
    ) -> tuple[list[dict], int, list[str]]:
        """
        Mask an entire dataset.
        Returns (masked_data, rows_masked_count, fields_masked).
        """
        if not data:
            return data, 0, []

        masked_data = []
        rows_masked = 0
        all_masked_fields = set()

        for row in data:
            masked_row, fields = self.mask_row(row, table, role)
            masked_data.append(masked_row)
            if fields:
                rows_masked += 1
                all_masked_fields.update(fields)

        return masked_data, rows_masked, sorted(all_masked_fields)

"""
Ingress Pipeline
Chains all ingress controls in order:
1. JWT authentication + role check
2. Rate limiter (per user, per endpoint)
3. SQL injection filter
4. Schema validation + sanitization
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict


@dataclass
class IngressResult:
    blocked: bool = False
    reason: Optional[str] = None
    warnings: list[str] = field(default_factory=list)


# ── JWT Auth ──────────────────────────────────────────────────

# Mock user store — replace with Oracle GPS_USERS in production
MOCK_USERS = {
    "tok_admin_001":   {"user_id": "admin_1",   "role": "ADMIN",    "name": "Admin User"},
    "tok_manager_001": {"user_id": "manager_1", "role": "MANAGER",  "name": "Jane Manager"},
    "tok_readonly_001":{"user_id": "readonly_1","role": "READONLY", "name": "Read Only User"},
    "tok_analyst_001": {"user_id": "analyst_1", "role": "ANALYST",  "name": "Data Analyst"},
}

# Role permissions — what each role can do
ROLE_PERMISSIONS = {
    "ADMIN":    {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "MANAGER":  {"SELECT", "INSERT", "UPDATE"},
    "ANALYST":  {"SELECT"},
    "READONLY": {"SELECT"},
}

class JWTAuthControl:
    def check(self, token: Optional[str], method: Optional[str]) -> IngressResult:
        if not token:
            return IngressResult(blocked=True, reason="Missing authentication token")

        user = MOCK_USERS.get(token)
        if not user:
            return IngressResult(blocked=True, reason="Invalid or expired token")

        # Check role has permission for this method
        allowed_ops = ROLE_PERMISSIONS.get(user["role"], set())
        op = (method or "SELECT").upper()
        if op not in allowed_ops:
            return IngressResult(
                blocked=True,
                reason=f"Role '{user['role']}' does not have {op} permission"
            )

        return IngressResult(blocked=False)

    def get_user(self, token: str) -> Optional[dict]:
        return MOCK_USERS.get(token)


# ── Rate Limiter ──────────────────────────────────────────────

class RateLimiter:
    """
    Sliding window rate limiter.
    Limits: requests per minute per user, and per endpoint per user.
    """

    LIMITS = {
        "ADMIN":    {"per_minute": 300, "per_endpoint_minute": 100},
        "MANAGER":  {"per_minute": 200, "per_endpoint_minute": 60},
        "ANALYST":  {"per_minute": 100, "per_endpoint_minute": 30},
        "READONLY": {"per_minute": 60,  "per_endpoint_minute": 20},
    }

    def __init__(self):
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, user_id: str, role: str, endpoint: str) -> IngressResult:
        now = time.time()
        limits = self.LIMITS.get(role, self.LIMITS["READONLY"])

        # Global per-user window
        user_key  = f"user:{user_id}"
        ep_key    = f"user:{user_id}:ep:{endpoint}"

        # Clean old entries (older than 60s)
        for key in (user_key, ep_key):
            self._windows[key] = [t for t in self._windows[key] if now - t < 60]

        # Check global limit
        if len(self._windows[user_key]) >= limits["per_minute"]:
            return IngressResult(
                blocked=True,
                reason=f"Rate limit exceeded: {limits['per_minute']} requests/min for role {role}"
            )

        # Check endpoint limit
        if len(self._windows[ep_key]) >= limits["per_endpoint_minute"]:
            return IngressResult(
                blocked=True,
                reason=f"Endpoint rate limit exceeded: {limits['per_endpoint_minute']} requests/min on {endpoint}"
            )

        # Record this request
        self._windows[user_key].append(now)
        self._windows[ep_key].append(now)

        return IngressResult(blocked=False)

    def get_usage(self, user_id: str, endpoint: str) -> dict:
        now = time.time()
        user_key = f"user:{user_id}"
        ep_key   = f"user:{user_id}:ep:{endpoint}"
        return {
            "user_requests_last_minute":     len([t for t in self._windows[user_key] if now - t < 60]),
            "endpoint_requests_last_minute": len([t for t in self._windows[ep_key]   if now - t < 60]),
        }


# ── SQL Injection Filter ──────────────────────────────────────

class SQLInjectionFilter:
    """
    Detects common SQL injection patterns in query parameters and payloads.
    Blocks requests that contain dangerous patterns.
    """

    DANGEROUS_PATTERNS = [
        # Classic injection
        (r"(\s|;|'|\")(OR|AND)\s+['\"0-9]",                "Classic OR/AND injection"),
        (r"(--|#|/\*)",                                      "SQL comment injection"),
        (r";\s*(DROP|DELETE|TRUNCATE|ALTER|CREATE)\s+",      "DDL injection attempt"),
        (r"UNION\s+(ALL\s+)?SELECT",                         "UNION SELECT injection"),
        (r"EXEC(\s|\()",                                     "EXEC injection"),
        (r"xp_cmdshell",                                     "xp_cmdshell injection"),
        (r"INTO\s+(OUTFILE|DUMPFILE)",                       "File write injection"),
        (r"LOAD_FILE\s*\(",                                  "File read injection"),
        (r"INFORMATION_SCHEMA",                              "Schema enumeration"),
        (r"SLEEP\s*\(\s*\d+\s*\)",                          "Time-based blind injection"),
        (r"WAITFOR\s+DELAY",                                 "Time-based blind injection"),
        (r"BENCHMARK\s*\(",                                  "Benchmark injection"),
        (r"CHAR\s*\(\s*\d+",                                 "CHAR() obfuscation"),
        (r"0x[0-9a-fA-F]{4,}",                              "Hex encoding injection"),
    ]

    def check(self, query: Optional[str] = None, payload: Optional[dict] = None) -> IngressResult:
        targets = []
        if query:
            targets.append(("query", query))
        if payload:
            for k, v in payload.items():
                if isinstance(v, str):
                    targets.append((f"field:{k}", v))

        for field_name, value in targets:
            for pattern, description in self.DANGEROUS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    return IngressResult(
                        blocked=True,
                        reason=f"SQL injection detected in {field_name}: {description}"
                    )

        return IngressResult(blocked=False)


# ── Schema Validator ──────────────────────────────────────────

# Known tables and their allowed columns for each role
TABLE_SCHEMAS = {
    "GPS_EMPLOYEES": {
        "columns": ["EMPLOYEE_ID", "FIRST_NAME", "LAST_NAME", "EMAIL",
                    "TYPE_CODE", "OFFICE_ID", "BASE_SALARY", "HOURLY_RATE",
                    "CURRENCY_CODE", "HIRE_DATE", "KRONOS_ID", "ACTIVE"],
        "sensitive_columns": ["BASE_SALARY", "HOURLY_RATE", "EMAIL"],
        "restricted_roles": {
            "READONLY": ["EMPLOYEE_ID", "FIRST_NAME", "LAST_NAME", "TYPE_CODE", "OFFICE_ID"],
        }
    },
    "GPS_PAYSLIPS": {
        "columns": ["PAYSLIP_ID", "RUN_ID", "EMPLOYEE_ID", "GROSS_PAY",
                    "NET_PAY", "TOTAL_TAX", "CURRENCY_CODE", "STATUS"],
        "sensitive_columns": ["GROSS_PAY", "NET_PAY", "TOTAL_TAX"],
        "restricted_roles": {
            "READONLY": ["PAYSLIP_ID", "EMPLOYEE_ID", "STATUS"],
            "ANALYST":  ["PAYSLIP_ID", "EMPLOYEE_ID", "CURRENCY_CODE", "STATUS"],
        }
    },
    "GPS_TAX_RULES": {
        "columns": ["TAX_RULE_ID", "COUNTRY_CODE", "TAX_TYPE", "TAX_NAME",
                    "EMPLOYEE_RATE", "EMPLOYER_RATE", "INCOME_FROM", "INCOME_TO"],
        "sensitive_columns": [],
        "restricted_roles": {}
    },
    "GPS_PAYROLL_RUNS": {
        "columns": ["RUN_ID", "OFFICE_ID", "PAY_PERIOD_START", "PAY_PERIOD_END",
                    "STATUS", "TOTAL_GROSS", "TOTAL_NET", "CURRENCY_CODE"],
        "sensitive_columns": ["TOTAL_GROSS", "TOTAL_NET"],
        "restricted_roles": {
            "READONLY": ["RUN_ID", "OFFICE_ID", "PAY_PERIOD_START", "PAY_PERIOD_END", "STATUS"],
        }
    },
}

MAX_ROW_LIMITS = {
    "ADMIN":    10000,
    "MANAGER":  5000,
    "ANALYST":  1000,
    "READONLY": 100,
}

class SchemaValidator:
    def check(self, table: Optional[str], role: str, row_limit: Optional[int]) -> IngressResult:
        warnings = []

        # Validate table exists
        if table and table.upper() not in TABLE_SCHEMAS:
            return IngressResult(
                blocked=True,
                reason=f"Table '{table}' is not accessible through the gateway"
            )

        # Enforce row limit
        max_rows = MAX_ROW_LIMITS.get(role, 100)
        if row_limit and row_limit > max_rows:
            return IngressResult(
                blocked=True,
                reason=f"Row limit {row_limit} exceeds maximum {max_rows} for role '{role}'"
            )

        if row_limit and row_limit > max_rows * 0.8:
            warnings.append(f"Large query: {row_limit} rows requested (limit: {max_rows})")

        return IngressResult(blocked=False, warnings=warnings)


# ── Ingress Pipeline ──────────────────────────────────────────

class IngressPipeline:
    """
    Chains all ingress controls. Stops at first block.
    """

    def __init__(self):
        self.auth      = JWTAuthControl()
        self.limiter   = RateLimiter()
        self.sql_filter = SQLInjectionFilter()
        self.validator = SchemaValidator()

    def run(self, request) -> IngressResult:
        results = []

        # 1. JWT auth
        r = self.auth.check(request.user_id, request.method)
        if r.blocked:
            return r
        results.append(r)

        # Get user info for subsequent checks
        user = self.auth.get_user(request.user_id or "")
        role = user["role"] if user else "READONLY"

        # 2. Rate limiter
        r = self.limiter.check(
            user_id=request.user_id or "anonymous",
            role=role,
            endpoint=request.endpoint or "/",
        )
        if r.blocked:
            return r
        results.append(r)

        # 3. SQL injection
        r = self.sql_filter.check(query=request.query, payload=request.payload)
        if r.blocked:
            return r
        results.append(r)

        # 4. Schema validation
        r = self.validator.check(
            table=request.table,
            role=role,
            row_limit=request.row_limit,
        )
        if r.blocked:
            return r
        results.append(r)

        # Collect all warnings
        all_warnings = [w for res in results for w in res.warnings]
        return IngressResult(blocked=False, warnings=all_warnings)

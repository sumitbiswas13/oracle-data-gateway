"""
Oracle Executor
Executes validated requests against Oracle DB.
Mock version for demo — swap for real oracledb connection in production.
"""

import random
from datetime import date
from typing import Any, Optional
from core.engine import GatewayRequest


# ── Mock Oracle data ──────────────────────────────────────────
MOCK_DATA = {
    "GPS_EMPLOYEES": [
        {"EMPLOYEE_ID": 1,  "FIRST_NAME": "James",   "LAST_NAME": "Carter",   "EMAIL": "jcarter@acme.com",   "TYPE_CODE": "FULLTIME", "OFFICE_ID": 1, "BASE_SALARY": 95000,   "HOURLY_RATE": None, "CURRENCY_CODE": "USD"},
        {"EMPLOYEE_ID": 2,  "FIRST_NAME": "Priya",   "LAST_NAME": "Sharma",   "EMAIL": "psharma@acme.com",   "TYPE_CODE": "FULLTIME", "OFFICE_ID": 4, "BASE_SALARY": 1800000, "HOURLY_RATE": None, "CURRENCY_CODE": "INR"},
        {"EMPLOYEE_ID": 3,  "FIRST_NAME": "Oliver",  "LAST_NAME": "Bennett",  "EMAIL": "obennett@acme.com",  "TYPE_CODE": "FULLTIME", "OFFICE_ID": 3, "BASE_SALARY": 65000,   "HOURLY_RATE": None, "CURRENCY_CODE": "GBP"},
        {"EMPLOYEE_ID": 4,  "FIRST_NAME": "Chloe",   "LAST_NAME": "Thompson", "EMAIL": "cthompson@acme.com", "TYPE_CODE": "FULLTIME", "OFFICE_ID": 6, "BASE_SALARY": 95000,   "HOURLY_RATE": None, "CURRENCY_CODE": "AUD"},
        {"EMPLOYEE_ID": 5,  "FIRST_NAME": "Marcus",  "LAST_NAME": "Williams", "EMAIL": "mwilliams@acme.com", "TYPE_CODE": "HOURLY",   "OFFICE_ID": 1, "BASE_SALARY": None,    "HOURLY_RATE": 28.0, "CURRENCY_CODE": "USD"},
        {"EMPLOYEE_ID": 6,  "FIRST_NAME": "Aisha",   "LAST_NAME": "Patel",    "EMAIL": "apatel@acme.com",    "TYPE_CODE": "HOURLY",   "OFFICE_ID": 5, "BASE_SALARY": None,    "HOURLY_RATE": 450.0,"CURRENCY_CODE": "INR"},
        {"EMPLOYEE_ID": 7,  "FIRST_NAME": "Emma",    "LAST_NAME": "Wilson",   "EMAIL": "ewilson@acme.com",   "TYPE_CODE": "PARTTIME", "OFFICE_ID": 3, "BASE_SALARY": None,    "HOURLY_RATE": 18.0, "CURRENCY_CODE": "GBP"},
        {"EMPLOYEE_ID": 8,  "FIRST_NAME": "Liam",    "LAST_NAME": "Johnson",  "EMAIL": "ljohnson@acme.com",  "TYPE_CODE": "HOURLY",   "OFFICE_ID": 7, "BASE_SALARY": None,    "HOURLY_RATE": 35.0, "CURRENCY_CODE": "AUD"},
        {"EMPLOYEE_ID": 9,  "FIRST_NAME": "Sofia",   "LAST_NAME": "Martinez", "EMAIL": "smartinez@acme.com", "TYPE_CODE": "FULLTIME", "OFFICE_ID": 2, "BASE_SALARY": 110000,  "HOURLY_RATE": None, "CURRENCY_CODE": "USD"},
        {"EMPLOYEE_ID": 10, "FIRST_NAME": "Raj",     "LAST_NAME": "Kumar",    "EMAIL": "rkumar@acme.com",    "TYPE_CODE": "CONTRACT", "OFFICE_ID": 4, "BASE_SALARY": 2400000, "HOURLY_RATE": None, "CURRENCY_CODE": "INR"},
    ],
    "GPS_PAYSLIPS": [
        {"PAYSLIP_ID": 1, "RUN_ID": 1, "EMPLOYEE_ID": 1, "GROSS_PAY": 3653.85, "NET_PAY": 2639.34, "TOTAL_TAX": 545.28, "CURRENCY_CODE": "USD", "STATUS": "GENERATED"},
        {"PAYSLIP_ID": 2, "RUN_ID": 1, "EMPLOYEE_ID": 2, "GROSS_PAY": 150000,  "NET_PAY": 87000,   "TOTAL_TAX": 63000,  "CURRENCY_CODE": "INR", "STATUS": "GENERATED"},
        {"PAYSLIP_ID": 3, "RUN_ID": 2, "EMPLOYEE_ID": 3, "GROSS_PAY": 5416.67, "NET_PAY": 3208.33, "TOTAL_TAX": 1937.5, "CURRENCY_CODE": "GBP", "STATUS": "GENERATED"},
        {"PAYSLIP_ID": 4, "RUN_ID": 3, "EMPLOYEE_ID": 4, "GROSS_PAY": 7916.67, "NET_PAY": 5185.42, "TOTAL_TAX": 2731.25,"CURRENCY_CODE": "AUD", "STATUS": "GENERATED"},
        {"PAYSLIP_ID": 5, "RUN_ID": 1, "EMPLOYEE_ID": 5, "GROSS_PAY": 4704.00, "NET_PAY": 3528.00, "TOTAL_TAX": 1176.00,"CURRENCY_CODE": "USD", "STATUS": "GENERATED"},
    ],
    "GPS_TAX_RULES": [
        {"TAX_RULE_ID": 1, "COUNTRY_CODE": "US", "TAX_TYPE": "INCOME",         "TAX_NAME": "Federal 22%",      "EMPLOYEE_RATE": 0.22, "EMPLOYER_RATE": 0,     "INCOME_FROM": 47151,  "INCOME_TO": 100525},
        {"TAX_RULE_ID": 2, "COUNTRY_CODE": "US", "TAX_TYPE": "SOCIAL_SECURITY","TAX_NAME": "FICA SS",          "EMPLOYEE_RATE": 0.062,"EMPLOYER_RATE": 0.062, "INCOME_FROM": 0,      "INCOME_TO": 168600},
        {"TAX_RULE_ID": 3, "COUNTRY_CODE": "GB", "TAX_TYPE": "INCOME",         "TAX_NAME": "Basic Rate 20%",   "EMPLOYEE_RATE": 0.20, "EMPLOYER_RATE": 0,     "INCOME_FROM": 12571,  "INCOME_TO": 50270},
        {"TAX_RULE_ID": 4, "COUNTRY_CODE": "IN", "TAX_TYPE": "INCOME",         "TAX_NAME": "30% Band",         "EMPLOYEE_RATE": 0.30, "EMPLOYER_RATE": 0,     "INCOME_FROM": 1500001,"INCOME_TO": None},
        {"TAX_RULE_ID": 5, "COUNTRY_CODE": "AU", "TAX_TYPE": "INCOME",         "TAX_NAME": "32.5% Band",       "EMPLOYEE_RATE": 0.325,"EMPLOYER_RATE": 0,     "INCOME_FROM": 45001,  "INCOME_TO": 120000},
    ],
    "GPS_PAYROLL_RUNS": [
        {"RUN_ID": 1, "OFFICE_ID": 1, "PAY_PERIOD_START": "2024-11-01", "PAY_PERIOD_END": "2024-11-30", "STATUS": "COMPLETE", "TOTAL_GROSS": 158423, "TOTAL_NET": 118234, "CURRENCY_CODE": "USD"},
        {"RUN_ID": 2, "OFFICE_ID": 3, "PAY_PERIOD_START": "2024-11-01", "PAY_PERIOD_END": "2024-11-30", "STATUS": "COMPLETE", "TOTAL_GROSS": 48291,  "TOTAL_NET": 31840,  "CURRENCY_CODE": "GBP"},
        {"RUN_ID": 3, "OFFICE_ID": 4, "PAY_PERIOD_START": "2024-11-01", "PAY_PERIOD_END": "2024-11-30", "STATUS": "COMPLETE", "TOTAL_GROSS": 324560, "TOTAL_NET": 218430, "CURRENCY_CODE": "INR"},
        {"RUN_ID": 4, "OFFICE_ID": 6, "PAY_PERIOD_START": "2024-11-01", "PAY_PERIOD_END": "2024-11-30", "STATUS": "COMPLETE", "TOTAL_GROSS": 72841,  "TOTAL_NET": 51230,  "CURRENCY_CODE": "AUD"},
    ],
}


class MockOracleExecutor:
    """
    Simulates Oracle query execution.
    Returns realistic data without requiring a live DB connection.
    Replace with RealOracleExecutor for production.
    """

    def execute(self, request: GatewayRequest) -> tuple[Any, int]:
        table = (request.table or "").upper()
        data  = MOCK_DATA.get(table, [])

        # Apply row limit
        limit = request.row_limit or len(data)
        data  = data[:limit]

        return data, len(data)


class RealOracleExecutor:
    """
    Production Oracle executor.
    Requires python-oracledb and a live Oracle connection.
    """

    def __init__(self, connection):
        self._conn = connection

    def execute(self, request: GatewayRequest) -> tuple[Any, int]:
        cur = self._conn.cursor()
        table = request.table.upper()
        limit = request.row_limit or 100

        sql = f"SELECT * FROM {table} FETCH FIRST {limit} ROWS ONLY"
        cur.execute(sql)

        columns = [d[0] for d in cur.description]
        rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        return rows, len(rows)

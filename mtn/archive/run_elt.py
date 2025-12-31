#!/usr/bin/env python3
import os
import sys
import json
import argparse
import logging
from datetime import datetime
import configparser
import textwrap
import requests
import time

# =========================
# Constants / Defaults
# =========================
CONFIG_FILE = "config.ini"
TABLES_CONFIG_FILE = "config_elt_tables.json"
DATES_CONFIG_FILE = "config_elt_dates.json"
LOG_DIR = "logs"

# =========================
# Logging
# =========================
def setup_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_filename = os.path.join(LOG_DIR, f"elt_run_{datetime.now():%Y%m%d_%H%M%S}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_filename, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.info(f"Logging initialized -> {log_filename}")
    return log_filename


def log_step(message, level="info"):
    """Unified logging with simple tag style."""
    prefix = {
        "info": "ℹ️",
        "success": "✅",
        "warning": "⚠️",
        "error": "❌",
        "debug": "🐞",
    }.get(level, "ℹ️")

    msg = f"{prefix} {message}"

    if level == "success":
        logging.info(msg)
    elif level == "warning":
        logging.warning(msg)
    elif level == "error":
        logging.error(msg)
    elif level == "debug":
        logging.debug(msg)
    else:
        logging.info(msg)


# =========================
# Dremio Client (pluggable)
# =========================
class DremioClient:
    """
    Very simple Dremio SQL executor using REST API.
    Reads settings from config.ini:

    [dremio]
    base_url = https://your-dremio:9047
    username = your_user
    password = your_pass
    timeout_seconds = 600
    """

    def __init__(self, config_path=CONFIG_FILE):
        self.session = requests.Session()
        self.base_url = None
        self.timeout = 600
        self._load_config(config_path)
        self._login()

    def _load_config(self, config_path):
        config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"Config file '{config_path}' not found. "
                f"Create it with [dremio] section."
            )
        config.read(config_path)

        if "dremio" not in config:
            raise KeyError("Missing [dremio] section in config.ini")

        self.base_url = config["dremio"].get("base_url", "").rstrip("/")
        username = config["dremio"].get("username")
        password = config["dremio"].get("password")
        self.timeout = config["dremio"].getint("timeout_seconds", fallback=600)

        if not self.base_url or not username or not password:
            raise ValueError(
                "base_url, username, password must be set under [dremio] in config.ini"
            )

        self.username = username
        self.password = password

    def _login(self):
        url = f"{self.base_url}/apiv3/login"
        payload = {"userName": self.username, "password": self.password}
        r = self.session.post(url, json=payload, timeout=self.timeout)
        if r.status_code != 200:
            raise RuntimeError(f"Failed to login Dremio: {r.status_code} {r.text}")
        token = r.json().get("token")
        if not token:
            raise RuntimeError("No token in Dremio login response")
        self.session.headers.update({"Authorization": f"_dremio{token}"})
        log_step("Authenticated to Dremio API", "success")

    def run_sql(self, sql):
        """
        Execute a single SQL statement and wait for completion.
        Adjust to your job polling logic if needed.
        """
        sql = sql.strip().rstrip(";")
        if not sql:
            return

        submit_url = f"{self.base_url}/api/v3/sql"
        resp = self.session.post(submit_url, json={"sql": sql}, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"SQL submit failed: {resp.status_code} {resp.text}")
        job_id = resp.json().get("id")
        if not job_id:
            raise RuntimeError(f"No job id returned for SQL: {sql}")

        # Poll job
        state_url = f"{self.base_url}/api/v3/job/{job_id}"
        start = time.time()
        while True:
            r = self.session.get(state_url, timeout=self.timeout)
            if r.status_code != 200:
                raise RuntimeError(f"Job status failed: {r.status_code} {r.text}")
            data = r.json()
            state = data.get("jobState")
            if state in ("COMPLETED", "FAILED", "CANCELED"):
                break
            if time.time() - start > self.timeout:
                raise TimeoutError(f"Job {job_id} timed out")
            time.sleep(2)

        if state != "COMPLETED":
            raise RuntimeError(f"Job {job_id} ended with state={state}")

        log_step(f"Executed SQL successfully (job={job_id})", "success")


# =========================
# Helper functions
# =========================
def load_json(path, description):
    if not os.path.exists(path):
        raise FileNotFoundError(f"{description} file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "y")
    return False


def format_tbl_dt_value(date_str):
    """
    Convert start_date/end_date into a tbl_dt literal.
    If it contains '-', treat as DATE 'YYYY-MM-DD'.
    Else treat as numeric (no quotes).
    """
    if not date_str:
        return None
    s = date_str.strip()
    if "-" in s:
        return f"DATE '{s}'"
    return s  # assume numeric like 20251106


def build_filter_clause(start_date, end_date):
    start_val = format_tbl_dt_value(start_date)
    end_val = format_tbl_dt_value(end_date) if end_date else None

    if start_val and end_val:
        return f"tbl_dt BETWEEN {start_val} AND {end_val}"
    elif start_val:
        return f"tbl_dt = {start_val}"
    else:
        raise ValueError("start_date is required for filter")


def load_columns_from_file(columns_file):
    """
    Expect JSON containing either:
    - { "columns": [ {"name": "col1", "display": true}, ... ] }
    OR
    - [ {"name": "col1", "display": true}, ... ]
    Returns list of column names where display == true.
    """
    data = load_json(columns_file, f"Columns config ({columns_file})")

    if isinstance(data, dict) and "columns" in data:
        cols = data["columns"]
    else:
        cols = data

    selected = [c["name"] for c in cols if normalize_bool(c.get("display", False))]

    if not selected:
        raise ValueError(f"No display=true columns found in {columns_file}")

    return selected


def build_view_name(ref_view_name, start_date, end_date):
    if end_date:
        return f"{ref_view_name}_{start_date.replace('-', '')}_{end_date.replace('-', '')}"
    return f"{ref_view_name}_{start_date.replace('-', '')}"


def build_reflection_name(ref_view_name, start_date, end_date):
    if end_date:
        return f"rfl_{ref_view_name}_{start_date.replace('-', '')}_{end_date.replace('-', '')}"
    return f"rfl_{ref_view_name}_{start_date.replace('-', '')}"


# =========================
# Core ELT Logic
# =========================
class ELTProcessor:
    def __init__(self, mode="plan"):
        """
        mode: "plan" (no execution) or "execute" (run against Dremio)
        """
        self.mode = mode
        self.tables_cfg = load_json(TABLES_CONFIG_FILE, "Tables config")
        self.dates_cfg = load_json(DATES_CONFIG_FILE, "Dates config")
        self.dremio = None

        if self.mode == "execute":
            self.dremio = DremioClient()
            log_step("Running in EXECUTE mode (SQL will be executed)", "warning")
        else:
            log_step("Running in PLAN mode (no SQL will be executed)", "info")

    def run(self):
        for date_entry in self.dates_cfg.get("dates", []):
            # Each date_entry is like { "20251106": { ... } }
            if not isinstance(date_entry, dict):
                continue

            for _, defn in date_entry.items():
                start_date = defn.get("start_date", "").strip()
                end_date = defn.get("end_date", "").strip()
                tables = defn.get("tables", [])

                if not start_date or not tables:
                    log_step(
                        f"Skipping date entry (missing start_date or tables): {defn}",
                        "warning",
                    )
                    continue

                log_step(
                    f"Processing date range: start={start_date}, end={end_date or 'N/A'} for tables={tables}",
                    "info",
                )

                for table_name in tables:
                    self.process_table_for_date(table_name, start_date, end_date)

    def process_table_for_date(self, table_name, start_date, end_date):
        table_cfg = self.tables_cfg.get(table_name)
        if not table_cfg:
            log_step(f"Table '{table_name}' not found in {TABLES_CONFIG_FILE}", "error")
            return

        if not normalize_bool(table_cfg.get("is_active", True)):
            log_step(f"Table '{table_name}' is not active. Skipping.", "info")
            return

        # Extract config
        hive_source = table_cfg["hive_source"]
        hive_schema = table_cfg["hive_schema_name"]
        hive_table = table_cfg["hive_table_name"]

        ref_space = table_cfg["ref_space_name"]
        ref_schema = table_cfg["ref_schema_name"]
        ref_view_name = table_cfg["ref_view_name"]

        s3_space = table_cfg["s3_source"]
        s3_schema = table_cfg["s3_schema_name"]
        s3_table = table_cfg["s3_table_name"]

        all_columns = normalize_bool(table_cfg.get("all_columns", False))
        columns_file = table_cfg.get("columns_file")
        s3_partition = normalize_bool(table_cfg.get("s3_partition", False))

        filter_clause = build_filter_clause(start_date, end_date)

        # 3.1 Columns
        if all_columns:
            select_cols = "*"
            used_columns = ["*"]
        else:
            if not columns_file:
                log_step(
                    f"Table '{table_name}' has all_columns=false but no columns_file defined",
                    "error",
                )
                return
            used_columns = load_columns_from_file(columns_file)
            select_cols = ", ".join(used_columns)

        # 3.1 View name & SQL
        view_name_only = build_view_name(ref_view_name, start_date, end_date)
        full_view = f"\"{ref_space}\".\"{ref_schema}\".\"{view_name_only}\""

        source_table = f"\"{hive_source}\".\"{hive_schema}\".\"{hive_table}\""

        sql_create_view = textwrap.dedent(
            f"""
            CREATE VIEW IF NOT EXISTS {full_view} AS
            SELECT {select_cols}
            FROM {source_table}
            WHERE {filter_clause}
            """
        ).strip()

        self._execute_or_print(sql_create_view, f"[3.1] Create view {full_view}")

        # 3.2 Reflection (RAW reflection with same displayed columns)
        refl_name = build_reflection_name(ref_view_name, start_date, end_date)
        sql_create_refl = textwrap.dedent(
            f"""
            ALTER TABLE {full_view}
            CREATE RAW REFLECTION "{refl_name}"
            USING DISPLAY ({select_cols})
            """
        ).strip()

        self._execute_or_print(
            sql_create_refl,
            f"[3.2] Create reflection {refl_name} on {full_view}",
        )

        # 4.1 Create S3 table if not exists (structure only)
        full_s3_table = f"\"{s3_space}\".\"{s3_schema}\".\"{s3_table}\""
        sql_create_s3_table = textwrap.dedent(
            f"""
            CREATE TABLE IF NOT EXISTS {full_s3_table} AS
            SELECT {select_cols}
            FROM {full_view}
            WHERE 1 = 0
            """
        ).strip()

        self._execute_or_print(
            sql_create_s3_table,
            f"[4.1] Ensure S3 table exists {full_s3_table}",
        )

        # 4.2 Insert data from view into S3 table
        sql_insert_s3 = textwrap.dedent(
            f"""
            INSERT INTO {full_s3_table}
            SELECT {select_cols}
            FROM {full_view}
            """
        ).strip()

        self._execute_or_print(
            sql_insert_s3,
            f"[4.2] Insert data from {full_view} into {full_s3_table}",
        )

        # 4.3 Partition handling placeholder
        if s3_partition:
            sql_partition = self._build_s3_partition_sql_placeholder(
                full_s3_table, start_date, end_date
            )
            self._execute_or_print(
                sql_partition,
                f"[4.3] (PLACEHOLDER) Partition handling for {full_s3_table}",
            )
        else:
            log_step(
                f"[4.3] s3_partition=false for {table_name}, skipping partition step.",
                "debug",
            )

    def _build_s3_partition_sql_placeholder(self, full_s3_table, start_date, end_date):
        """
        Placeholder for future partition logic.
        Adjust once partitioning strategy is finalized.
        """
        return f"-- TODO: implement partitioning for {full_s3_table} for range {start_date} - {end_date or start_date}"

    def _execute_or_print(self, sql, description):
        if self.mode == "execute":
            log_step(f"{description} | EXECUTING", "info")
            try:
                self.dremio.run_sql(sql)
            except Exception as e:
                log_step(f"Error executing SQL: {e}", "error")
                raise
        else:
            log_step(f"{description} | PLAN ONLY", "info")
            print("\n" + "-" * 80)
            print(sql + ";")
            print("-" * 80 + "\n")


# =========================
# Entry point
# =========================
def parse_args():
    parser = argparse.ArgumentParser(
        description="ELT Orchestrator for Dremio/Hive -> S3 pipeline"
    )
    parser.add_argument(
        "--mode",
        choices=["plan", "execute"],
        default="plan",
        help="plan = only print/log SQL, execute = run against Dremio",
    )
    parser.add_argument(
        "--tables-config",
        default=TABLES_CONFIG_FILE,
        help="Path to config_elt_tables.json",
    )
    parser.add_argument(
        "--dates-config",
        default=DATES_CONFIG_FILE,
        help="Path to config_elt_dates.json",
    )
    return parser.parse_args()


def main():
    setup_logger()
    args = parse_args()

    # Allow overriding config filenames via CLI
    global TABLES_CONFIG_FILE, DATES_CONFIG_FILE
    TABLES_CONFIG_FILE = args.tables_config
    DATES_CONFIG_FILE = args.dates_config

    try:
        processor = ELTProcessor(mode=args.mode)
        processor.run()
        log_step("ELT process completed.", "success")
    except Exception as e:
        log_step(f"ELT process failed: {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()

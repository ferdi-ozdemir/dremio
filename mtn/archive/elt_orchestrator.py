#!/usr/bin/env python3
import os
import sys
import json
import argparse
import logging
from datetime import datetime
import configparser
import textwrap
import time
import requests

# =========================
# Constants / Defaults
# =========================
CONFIG_FILE = "config.ini"
TABLES_CONFIG_FILE = "config_elt_tables.json"
DATES_CONFIG_FILE = "config_elt_dates.json"
LOG_DIR = "logs"
OUTPUT_DIR = "sql_scripts"

# =========================
# Logging
# =========================
def setup_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_filename = os.path.join(
        LOG_DIR, f"elt_orchestrator_{datetime.now():%Y%m%d_%H%M%S}.log"
    )
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
    icons = {
        "info": "ℹ️",
        "success": "✅",
        "warning": "⚠️",
        "error": "❌",
        "debug": "🐞",
    }
    prefix = icons.get(level, "ℹ️")
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


def fmt_sec(start_time):
    return f"{time.time() - start_time:.2f}s"


# =========================
# Dremio Client
# =========================
class DremioClient:
    """
    Supports:
    - [dremio]
        base_url, username, password, timeout_seconds, poll_interval_seconds
    - or:
      [server], [auth], [defaults]
    """

    def __init__(self, config_path=CONFIG_FILE):
        self.session = requests.Session()
        self.base_url = None
        self.username = None
        self.password = None
        self.timeout = 7200        # job max wait
        self.poll_interval = 60    # seconds between polls

        self._load_config(config_path)
        self._login()

    def _load_config(self, config_path):
        cfg = configparser.ConfigParser()
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file '{config_path}' not found")
        cfg.read(config_path)

        # Style 1: [dremio]
        if "dremio" in cfg:
            sec = cfg["dremio"]
            self.base_url = sec.get("base_url", "").strip().rstrip("/")
            self.username = sec.get("username")
            self.password = sec.get("password")
            self.timeout = sec.getint("timeout_seconds", fallback=7200)
            self.poll_interval = sec.getint("poll_interval_seconds", fallback=60)
            if not self.base_url or not self.username or not self.password:
                raise ValueError("In [dremio], base_url/username/password are required")
            log_step("Loaded Dremio config from [dremio]", "debug")
            return
        
        raise KeyError(
            "No valid Dremio config found. Use [dremio] OR [server]+[auth] style."
        )

    def _login(self):
        """
        Robust login:
        - Try /apiv3/login, then /apiv2/login.
        - Parse JSON only on 200.
        - If all fail, raise clear error with snippet.
        """
        login_paths = ["/apiv3/login", "/apiv2/login"]
        last_error = None

        for path in login_paths:
            url = f"{self.base_url}{path}"
            try:
                r = self.session.post(
                    url,
                    json={"userName": self.username, "password": self.password},
                    timeout=self.timeout,
                )
            except Exception as e:
                last_error = f"Request error to {url}: {e}"
                continue

            if r.status_code != 200:
                snippet = r.text[:300].replace("\n", " ")
                last_error = f"Login failed at {url} (status={r.status_code}, body='{snippet}')"
                continue

            try:
                data = r.json()
            except ValueError as e:
                snippet = r.text[:300].replace("\n", " ")
                last_error = f"Non-JSON response from {url}: {e}, body='{snippet}'"
                continue

            token = data.get("token") or data.get("sessionToken")
            if not token:
                last_error = f"No token in login response from {url}: {data}"
                continue

            self.session.headers.update({"Authorization": f"_dremio{token}"})
            log_step(f"Authenticated to Dremio API via {path}", "success")
            return

        raise RuntimeError(f"Failed to login to Dremio. Details: {last_error}")

    # --- generic job helpers ---

    def _submit_sql(self, sql):
        sql = sql.strip().rstrip(";")
        if not sql:
            return None
        url = f"{self.base_url}/api/v3/sql"
        r = self.session.post(url, json={"sql": sql}, timeout=self.timeout)
        if r.status_code != 200:
            snippet = r.text[:300].replace("\n", " ")
            raise RuntimeError(
                f"SQL submit failed (status={r.status_code}, body='{snippet}')"
            )
        job_id = r.json().get("id")
        if not job_id:
            raise RuntimeError("No job id returned from SQL submit")
        return job_id

    def _wait_job(self, job_id):
        url = f"{self.base_url}/api/v3/job/{job_id}"
        start = time.time()
        while True:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                snippet = r.text[:300].replace("\n", " ")
                raise RuntimeError(
                    f"Job status failed (status={r.status_code}, body='{snippet}')"
                )
            data = r.json()
            state = data.get("jobState")
            if state in ("COMPLETED", "FAILED", "CANCELED"):
                break
            if time.time() - start > self.timeout:
                raise TimeoutError(f"Job {job_id} timed out (last state={state})")
            time.sleep(self.poll_interval)

        if state != "COMPLETED":
            raise RuntimeError(f"Job {job_id} ended with state={state}")
        return state

    def _fetch_rows(self, job_id, limit=10):
        url = f"{self.base_url}/api/v3/job/{job_id}/results?offset=0&limit={limit}"
        r = self.session.get(url, timeout=self.timeout)
        if r.status_code != 200:
            snippet = r.text[:300].replace("\n", " ")
            raise RuntimeError(
                f"Fetch results failed (status={r.status_code}, body='{snippet}')"
            )
        data = r.json()
        return data.get("rows", [])

    # --- public helpers with detailed logging/timing ---

    def run_sql(self, sql, label=None):
        start = time.time()
        try:
            if label:
                log_step(f"[SQL-START] {label}", "info")
            log_step(f"[SQL] {sql}", "debug")

            job_id = self._submit_sql(sql)
            self._wait_job(job_id)

            log_step(
                f"[SQL-SUCCESS] {label or ''} (job={job_id}, elapsed={fmt_sec(start)})",
                "success",
            )
        except Exception as e:
            log_step(
                f"[SQL-FAILED] {label or ''} (elapsed={fmt_sec(start)}): {e}",
                "error",
            )
            log_step(f"[SQL] {sql}", "error")
            raise

    def run_sql_has_rows(self, sql, label=None):
        start = time.time()
        try:
            if label:
                log_step(f"[CHECK-START] {label}", "debug")
            log_step(f"[SQL] {sql}", "debug")

            job_id = self._submit_sql(sql)
            self._wait_job(job_id)
            rows = self._fetch_rows(job_id, limit=1)
            has = len(rows) > 0

            log_step(
                f"[CHECK-RESULT] {label or ''}: {'FOUND' if has else 'NOT FOUND'} "
                f"(elapsed={fmt_sec(start)})",
                "debug",
            )
            return has
        except Exception as e:
            log_step(
                f"[CHECK-FAILED] {label or ''} (elapsed={fmt_sec(start)}): {e}",
                "error",
            )
            log_step(f"[SQL] {sql}", "error")
            raise

    def run_sql_fetch_rows(self, sql, label=None, limit=100):
        start = time.time()
        try:
            if label:
                log_step(f"[QUERY-START] {label}", "debug")
            log_step(f"[SQL] {sql}", "debug")

            job_id = self._submit_sql(sql)
            self._wait_job(job_id)

            url = f"{self.base_url}/api/v3/job/{job_id}/results?offset=0&limit={limit}"
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code != 200:
                snippet = r.text[:300].replace("\n", " ")
                raise RuntimeError(
                    f"Fetch results failed (status={r.status_code}, body='{snippet}')"
                )
            data = r.json()
            rows = data.get("rows", [])

            log_step(
                f"[QUERY-SUCCESS] {label or ''}: {len(rows)} row(s) "
                f"(elapsed={fmt_sec(start)})",
                "debug",
            )
            return rows
        except Exception as e:
            log_step(
                f"[QUERY-FAILED] {label or ''} (elapsed={fmt_sec(start)}): {e}",
                "error",
            )
            log_step(f"[SQL] {sql}", "error")
            raise

    # --- reflection helpers ---

    def get_reflection_status(self, refl_name):
        sql = f"""
            SELECT status
            FROM sys.reflections
            WHERE reflection_name = '{refl_name}'
        """
        rows = self.run_sql_fetch_rows(
            sql, f"Get reflection status: {refl_name}", limit=5
        )
        if not rows:
            return None
        row = rows[0]
        status = None
        if isinstance(row, dict):
            status = row.get("status") or row.get("STATUS")
        elif isinstance(row, (list, tuple)) and row:
            status = row[0]
        return str(status).upper() if status else None

    def wait_for_reflection_ready(self, refl_name, timeout_seconds=None):
        """
        Wait until reflection is ready or failed.

        Success: ACTIVE, CAN_ACCELERATE, OK
        Fail:    FAILED, INVALID, DEPRECATED
        Other:   treated as in-progress until timeout.
        """
        ready = {"ACTIVE", "CAN_ACCELERATE", "OK"}
        failed = {"FAILED", "INVALID", "DEPRECATED"}
        transient = {"OUT_OF_DATE", "REFRESHING", "NONE"}

        max_wait = timeout_seconds or self.timeout
        start = time.time()

        log_step(
            f"Waiting for reflection '{refl_name}' to become ready...",
            "info",
        )

        while True:
            status = self.get_reflection_status(refl_name)

            if status in ready:
                log_step(
                    f"Reflection '{refl_name}' is READY (status={status}, "
                    f"elapsed={fmt_sec(start)})",
                    "success",
                )
                return

            if status in failed:
                raise RuntimeError(
                    f"Reflection '{refl_name}' in FAILED state: {status}"
                )

            elapsed = time.time() - start
            if elapsed > max_wait:
                raise TimeoutError(
                    f"Timeout while waiting for reflection '{refl_name}' "
                    f"(last status={status})"
                )

            if status is None:
                log_step(
                    f"Reflection '{refl_name}' not visible yet, waiting...",
                    "debug",
                )
            elif status in transient:
                log_step(
                    f"Reflection '{refl_name}' status={status}, waiting...",
                    "debug",
                )
            else:
                log_step(
                    f"Reflection '{refl_name}' status={status}, "
                    f"treating as in-progress...",
                    "debug",
                )

            time.sleep(self.poll_interval)


# =========================
# Helper Functions
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


def tbl_dt_int_str(date_str):
    if not date_str:
        raise ValueError("Empty date string for tbl_dt conversion")
    s = date_str.strip().replace("-", "")
    if not s.isdigit() or len(s) != 8:
        raise ValueError(f"Invalid date format for tbl_dt int: {date_str}")
    return s


def build_filter_clause_int(start_date, end_date):
    start_int = tbl_dt_int_str(start_date)
    if end_date:
        end_int = tbl_dt_int_str(end_date)
        return f"tbl_dt BETWEEN {start_int} AND {end_int}", start_int, end_int
    else:
        return f"tbl_dt = {start_int}", start_int, None


def load_columns_from_file(columns_file, table_name):
    data = load_json(columns_file, f"Columns config ({columns_file})")

    if isinstance(data, dict) and table_name in data:
        inner = data[table_name]
        if isinstance(inner, dict) and "columns" in inner:
            cols = inner["columns"]
        else:
            raise ValueError(
                f"{columns_file} has entry for {table_name} but no 'columns' array"
            )
    elif isinstance(data, dict) and "columns" in data:
        cols = data["columns"]
    elif isinstance(data, list):
        cols = data
    else:
        raise ValueError(
            f"Unexpected structure in {columns_file}: "
            f"expected 'columns' or '{table_name}'"
        )

    selected = [c["name"] for c in cols if normalize_bool(c.get("display", False))]
    if not selected:
        raise ValueError(
            f"No display=true columns found for table '{table_name}' "
            f"in {columns_file}"
        )
    return selected


def build_view_and_reflection_names(ref_view_name, start_int, end_int=None):
    if end_int:
        view_name = f"{ref_view_name}_{start_int}_{end_int}"
        refl_name = f"rfl_{ref_view_name}_{start_int}_{end_int}"
    else:
        view_name = f"{ref_view_name}_{start_int}"
        refl_name = f"rfl_{ref_view_name}_{start_int}"
    return view_name, refl_name


# =========================
# Core Orchestrator
# =========================
class ELTOrchestrator:
    def __init__(self, mode, tables_cfg_path, dates_cfg_path, output_dir):
        self.mode = mode  # "plan" or "execute"
        self.tables_cfg = load_json(tables_cfg_path, "Tables config")
        self.dates_cfg = load_json(dates_cfg_path, "Dates config")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.dremio = None
        if self.mode == "execute":
            self.dremio = DremioClient()
            log_step(
                "Running in EXECUTION mode: will validate objects, "
                "wait for reflections, and load S3.",
                "warning",
            )
        else:
            log_step(
                "Running in PLAN mode: generating SQL scripts only.",
                "info",
            )

    # ----- existence checks -----
    def view_exists(self, space, schema, view_name):
        # Note: using your adjusted schema format space.schema
        sql = textwrap.dedent(
            f"""
            SELECT 1
            FROM INFORMATION_SCHEMA."VIEWS"
            WHERE table_schema  = '{space}.{schema}'
              AND table_name    = '{view_name}'
            """
        )
        return self.dremio.run_sql_has_rows(
            sql, f"View exists? {space}.{schema}.{view_name}"
        )

    def table_exists(self, space, schema, table_name):
        sql = textwrap.dedent(
            f"""
            SELECT 1
            FROM INFORMATION_SCHEMA."TABLES"
            WHERE table_schema  = '{space}.{schema}'
              AND table_name    = '{table_name}'
            """
        )
        return self.dremio.run_sql_has_rows(
            sql, f"Table exists? {space}.{schema}.{table_name}"
        )

    def reflection_exists(self, refl_name):
        sql = textwrap.dedent(
            f"""
            SELECT 1
            FROM sys.reflections
            WHERE reflection_name = '{refl_name}'
            """
        )
        return self.dremio.run_sql_has_rows(
            sql, f"Reflection exists? {refl_name}"
        )

    # ----- main runner -----
    def run(self):
        overall_start = time.time()
        log_step("Starting ELT orchestration run...", "info")

        for date_entry in self.dates_cfg.get("dates", []):
            if not isinstance(date_entry, dict):
                continue

            date_key, defn = list(date_entry.items())[0]
            start_date = defn.get("start_date", "").strip()
            end_date = defn.get("end_date", "").strip()
            tables = defn.get("tables", [])

            if not start_date or not tables:
                log_step(f"Skipping invalid date block: {defn}", "warning")
                continue

            if self.mode == "plan":
                self._generate_plan_script(date_key, start_date, end_date, tables)
            else:
                self._execute_for_date(date_key, start_date, end_date, tables)

        log_step(
            f"ELT orchestration completed in {fmt_sec(overall_start)}",
            "success",
        )

    # =========================
    # PLAN MODE
    # =========================
    def _generate_plan_script(self, date_key, start_date, end_date, tables):
        script_name = f"run_etl_{date_key}.sql"
        script_path = os.path.join(self.output_dir, script_name)
        start = time.time()
        log_step(f"[PLAN] Generating script {script_path}", "info")

        lines = [
            "-- =====================================================================",
            f"-- Auto-generated ELT SQL for date key {date_key}",
            f"-- Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "-- NOTE: tbl_dt is INT (no quotes).",
            "-- =====================================================================",
            "",
        ]

        for table_name in tables:
            self._append_plan_block(lines, table_name, start_date, end_date)

        with open(script_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        log_step(
            f"[PLAN] Script written: {script_path} "
            f"(elapsed={fmt_sec(start)})",
            "success",
        )

    def _append_plan_block(self, lines, table_name, start_date, end_date):
        table_cfg = self.tables_cfg.get(table_name)
        if not table_cfg:
            log_step(f"[PLAN] Table '{table_name}' not in config_elt_tables.json", "error")
            return
        if not normalize_bool(table_cfg.get("is_active", True)):
            log_step(f"[PLAN] Table '{table_name}' inactive; skipping block.", "info")
            return

        hive_source = table_cfg["hive_source"]
        hive_schema = table_cfg["hive_schema_name"]
        hive_table = table_cfg["hive_table_name"]

        ref_space = table_cfg["ref_space_name"]
        ref_schema = table_cfg["ref_schema_name"]
        ref_view_name = table_cfg["ref_view_name"]
        ref_view_limit=table_cfg["limit"]
        
        limit_clause=""
        if not ref_view_limit==0:
            limit_clause=f"limit {ref_view_limit}"

        s3_space = table_cfg["s3_source"]
        s3_schema = table_cfg["s3_schema_name"]
        s3_table = table_cfg["s3_table_name"]
        

        all_columns = normalize_bool(table_cfg.get("all_columns", False))
        columns_file = table_cfg.get("columns_file")
        s3_partition = normalize_bool(table_cfg.get("s3_partition", False))

        filter_clause, start_int, end_int = build_filter_clause_int(start_date, end_date)
        view_name, refl_name = build_view_and_reflection_names(
            ref_view_name, start_int, end_int
        )

        source_table = f"\"{hive_source}\".\"{hive_schema}\".\"{hive_table}\""
        full_view = f"\"{ref_space}\".\"{ref_schema}\".\"{view_name}\""
        full_s3 = f"\"{s3_space}\".\"{s3_schema}\".\"{s3_table}\""

        if all_columns:
            select_cols = "*"
        else:
            if not columns_file:
                log_step(f"[PLAN] {table_name}: all_columns=false but no columns_file", "error")
                return
            col_list = load_columns_from_file(columns_file, table_name)
            quoted_cols = [f'"{col}"' for col in col_list]
            select_cols = ", ".join(quoted_cols)
            # Quote each column name: "column"
            
        lines.extend(
            [
                "-- =====================================================================",
                f"-- Table: {table_name} | tbl_dt range: "
                f"{start_int}{(' - ' + end_int) if end_int else ''}",
                "-- =====================================================================",
                "",
                "-- 1) Check if view exists",
                "SELECT table_schema, table_name",
                "FROM INFORMATION_SCHEMA.\"VIEWS\"",
                f"WHERE table_schema  = '{ref_space}.{ref_schema}'",
                f"  AND table_name    = '{view_name}';",
                "-- If no rows, run:",
                f"CREATE VIEW {full_view} AS",
                f"SELECT {select_cols}",
                f"FROM {source_table}",
                f"WHERE {filter_clause}",
                f"{limit_clause};",
                "",
                "-- 2) Check if reflection exists",
                "SELECT reflection_id, reflection_name, status",
                "FROM sys.reflections",
                f"WHERE reflection_name = '{refl_name}';",
                "-- If no rows, run:",
                f"ALTER TABLE {full_view}",
                f"CREATE RAW REFLECTION \"{refl_name}\"",
                f"USING DISPLAY ({select_cols});",
                "",
                "-- 3) Check if target S3 table exists",
                "SELECT table_schema, table_name",
                "FROM INFORMATION_SCHEMA.\"TABLES\"",
                f"WHERE table_schema  = '{s3_space}.{s3_schema}'",
                f"  AND table_name    = '{s3_table}';",
                "-- If no rows, run (empty CTAS):",
                f"CREATE TABLE IF NOT EXISTS {full_s3} AS",
                f"SELECT {select_cols}",
                f"FROM {full_view}",
                "WHERE 1 = 0;",
                "",
                "-- 4) Insert data into S3 table",
                f"INSERT INTO {full_s3}",
                f"SELECT {select_cols}",
                f"FROM {full_view};",
                "",
            ]
        )

        if s3_partition:
            if end_int:
                lines.append(
                    f"-- 5) TODO: partition {full_s3} for tbl_dt BETWEEN {start_int} AND {end_int}"
                )
            else:
                lines.append(
                    f"-- 5) TODO: partition {full_s3} for tbl_dt = {start_int}"
                )
        else:
            lines.append("-- 5) s3_partition=false, no partition ops.")
        lines.append("")

    # =========================
    # EXECUTE MODE
    # =========================
    def _execute_for_date(self, date_key, start_date, end_date, tables):
        start = time.time()
        log_step(
            f"=== [DATE-START] {date_key} | start={start_date}, end={end_date or 'N/A'} ===",
            "info",
        )
        for table_name in tables:
            self._execute_for_table(table_name, start_date, end_date)
        log_step(
            f"=== [DATE-END] {date_key} completed in {fmt_sec(start)} ===",
            "success",
        )

    def _execute_for_table(self, table_name, start_date, end_date):
        start_table = time.time()
        table_cfg = self.tables_cfg.get(table_name)
        if not table_cfg:
            log_step(f"Table '{table_name}' not found in config_elt_tables.json", "error")
            return
        if not normalize_bool(table_cfg.get("is_active", True)):
            log_step(f"Table '{table_name}' inactive. Skipping.", "info")
            return

        hive_source = table_cfg["hive_source"]
        hive_schema = table_cfg["hive_schema_name"]
        hive_table = table_cfg["hive_table_name"]

        ref_space = table_cfg["ref_space_name"]
        ref_schema = table_cfg["ref_schema_name"]
        ref_view_name = table_cfg["ref_view_name"]
        ref_view_limit=table_cfg["limit"]
        
        limit_clause=""
        if not ref_view_limit==0:
            limit_clause=f"limit {ref_view_limit}"

        s3_space = table_cfg["s3_source"]
        s3_schema = table_cfg["s3_schema_name"]
        s3_table = table_cfg["s3_table_name"]

        all_columns = normalize_bool(table_cfg.get("all_columns", False))
        columns_file = table_cfg.get("columns_file")
        s3_partition = normalize_bool(table_cfg.get("s3_partition", False))

        filter_clause, start_int, end_int = build_filter_clause_int(
            start_date, end_date
        )
        view_name, refl_name = build_view_and_reflection_names(
            ref_view_name, start_int, end_int
        )

        source_table = f"\"{hive_source}\".\"{hive_schema}\".\"{hive_table}\""
        full_view = f"\"{ref_space}\".\"{ref_schema}\".\"{view_name}\""
        full_s3 = f"\"{s3_space}\".\"{s3_schema}\".\"{s3_table}\""

        if all_columns:
            select_cols = "*"
        else:
            if not columns_file:
                log_step(
                    f"{table_name}: all_columns=false but no columns_file. Skipping.",
                    "error",
                )
                return
            col_list = load_columns_from_file(columns_file, table_name)
            quoted_cols = [f'"{col}"' for col in col_list]
            select_cols = ", ".join(quoted_cols)
        log_step(
            f"[TABLE-START] {table_name} | view={full_view} | "
            f"reflection={refl_name} | target={full_s3}",
            "info",
        )

        # 1) View
        step_start = time.time()
        log_step(f"Step 1: Check/create view {full_view}", "info")
        if self.view_exists(ref_space, ref_schema, view_name):
            log_step(f"View exists: {full_view}", "info")
        else:
            sql_view = textwrap.dedent(
                f"""
                CREATE VIEW {full_view} AS
                SELECT {select_cols}
                FROM {source_table}
                WHERE {filter_clause}
                {limit_clause}
                """
            ).strip()
            self.dremio.run_sql(sql_view, f"Create view {full_view}")
        log_step(
            f"Step 1 completed for {full_view} in {fmt_sec(step_start)}",
            "success",
        )

        # 2) Reflection
        step_start = time.time()
        log_step(f"Step 2: Check/create reflection {refl_name}", "info")
        if self.reflection_exists(refl_name):
            status = self.dremio.get_reflection_status(refl_name)
            log_step(
                f"Reflection exists: {refl_name} (status={status})",
                "info",
            )
        else:
            sql_refl = textwrap.dedent(
                f"""
                ALTER TABLE {full_view}
                CREATE RAW REFLECTION "{refl_name}"
                USING DISPLAY ({select_cols})
                """
            ).strip()
            self.dremio.run_sql(sql_refl, f"Create reflection {refl_name}")

        try:
            self.dremio.wait_for_reflection_ready(refl_name)
        except Exception as e:
            log_step(
                f"Reflection '{refl_name}' not ready / failed: {e}. "
                f"Continuing may use source instead of reflection.",
                "warning",
            )
        log_step(
            f"Step 2 completed for reflection {refl_name} in {fmt_sec(step_start)}",
            "success",
        )

        # 3) S3 table
        step_start = time.time()
        log_step(f"Step 3: Check/create S3 table {full_s3}", "info")
        if self.table_exists(s3_space, s3_schema, s3_table):
            log_step(f"S3 table exists: {full_s3}", "info")
        else:
            sql_ctas = textwrap.dedent(
                f"""
                CREATE TABLE IF NOT EXISTS {full_s3} AS
                SELECT {select_cols}
                FROM {full_view}
                WHERE 1 = 0
                """
            ).strip()
            self.dremio.run_sql(sql_ctas, f"Create S3 table {full_s3} (empty CTAS)")
        log_step(
            f"Step 3 completed for {full_s3} in {fmt_sec(step_start)}",
            "success",
        )

        # 4) Insert data
        step_start = time.time()
        log_step(
            f"Step 4: Insert data {full_view} --> {full_s3}",
            "info",
        )
        sql_insert = textwrap.dedent(
            f"""
            INSERT INTO {full_s3}
            SELECT {select_cols}
            FROM {full_view}
            """
        ).strip()
        self.dremio.run_sql(sql_insert, f"Insert into {full_s3} from {full_view}")
        log_step(
            f"Step 4 completed (insert) in {fmt_sec(step_start)}",
            "success",
        )

        # 5) Partition placeholder
        step_start = time.time()
        if s3_partition:
            if end_int:
                log_step(
                    f"[{table_name}] TODO: partition {full_s3} "
                    f"for tbl_dt BETWEEN {start_int} AND {end_int}",
                    "warning",
                )
            else:
                log_step(
                    f"[{table_name}] TODO: partition {full_s3} "
                    f"for tbl_dt = {start_int}",
                    "warning",
                )
        else:
            log_step(
                f"[{table_name}] s3_partition=false. No partition DDL executed.",
                "debug",
            )
        log_step(
            f"Step 5 (partition placeholder) completed in {fmt_sec(step_start)}",
            "success",
        )

        log_step(
            f"[TABLE-END] {table_name} completed in {fmt_sec(start_table)}",
            "success",
        )


# =========================
# CLI
# =========================
def parse_args():
    p = argparse.ArgumentParser(
        description=(
            "ELT Orchestrator for Hive -> Dremio views/reflections -> S3\n"
            "PLAN: generate run_etl_YYYYMMDD.sql\n"
            "EXECUTE: check/create/wait/insert with detailed logging"
        )
    )
    p.add_argument(
        "--mode",
        choices=["plan", "execute"],
        default="execute",
        help="plan = generate SQL scripts; execute = run against Dremio",
    )
    p.add_argument(
        "--tables-config",
        default=TABLES_CONFIG_FILE,
        help="Path to config_elt_tables.json",
    )
    p.add_argument(
        "--dates-config",
        default=DATES_CONFIG_FILE,
        help="Path to config_elt_dates.json",
    )
    p.add_argument(
        "--output-dir",
        default=OUTPUT_DIR,
        help="Directory for run_etl_*.sql in plan mode",
    )
    return p.parse_args()


def main():
    setup_logger()
    args = parse_args()
    try:
        orchestrator = ELTOrchestrator(
            mode=args.mode,
            tables_cfg_path=args.tables_config,
            dates_cfg_path=args.dates_config,
            output_dir=args.output_dir,
        )
        orchestrator.run()
    except Exception as e:
        log_step(f"ELT orchestrator failed: {e}", "error")
        sys.exit(1)


if __name__ == "__main__":
    main()

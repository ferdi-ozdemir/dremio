#!/usr/bin/env python3
import os
import sys
import json
import argparse
import logging
from datetime import datetime, timedelta
import configparser
import textwrap
import time
import requests

# =========================
# Constants / Defaults
# =========================
# Resolve directory where this script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.ini")
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "sql_scripts")
WORKING_PATH = "minio.nyc"




# =========================
# Logging
# =========================
def setup_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_filename = os.path.join(
        LOG_DIR, f"elt_main_daily_{datetime.now():%Y%m%d_%H%M%S}.log"
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
        wait_first=2
        url = f"{self.base_url}/api/v3/job/{job_id}"
        start = time.time()
        wait_count=1
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
            if wait_count==1:
                time.sleep(wait_first)    
            else:
                time.sleep(self.poll_interval)
            wait_count +=1
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

    def run_sql_old(self, sql, label=None):
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
    def run_sql(self, sql, label=None, raise_on_error: bool = True) -> bool:
        """
        Run a SQL statement.

        :param sql: SQL string to execute
        :param label: Optional label for logging
        :param raise_on_error: 
            - True  -> log as error and raise exception
            - False -> log as warning and DO NOT raise
        :return: True if success, False if failed
        """
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
            return True

        except Exception as e:
            level = "error" if raise_on_error else "warning"

            log_step(
                f"[SQL-FAILED] {label or ''} (elapsed={fmt_sec(start)}): {e}",
                level,
            )
            log_step(f"[SQL] {sql}", level)

            if raise_on_error:
                raise

            # swallow exception, just signal failure
            return False

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

        wait_count=1
        wait_first=5
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
            
            if wait_count==1:
                log_step(
                f"Waiting {wait_first} secs for reflection '{refl_name}' to become ready...",
                "info",
                )
                time.sleep(wait_first)
            else:
                log_step(
                f"Waiting {self.poll_interval} secs for reflection '{refl_name}' to become ready...",
                "info",
                )
                time.sleep(self.poll_interval)
            wait_count+=1

def list_parquet_files(client, path=WORKING_PATH):
    rows = client.run_sql_fetch_rows(f"SHOW TABLES IN {path}", limit=500)
    parquet_files = [r["TABLE_NAME"] for r in rows if r.get("TABLE_NAME", "").endswith(".parquet")]
    log_step(f"Parquet files in {path}: {parquet_files}", "info")
    return parquet_files


def test_connection(config_path=CONFIG_FILE):
    client = DremioClient(config_path=config_path)
    rows = client.run_sql_fetch_rows("SELECT 1 AS test_col", label="connection test", limit=1)
    log_step(f"Connection test result: {rows}", "success")


def main():
    setup_logger()
    client = DremioClient()
    test_connection()
    list_parquet_files(client)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import sys
import time
import json
import logging
import configparser
import requests
from datetime import datetime

# === Default filenames ===
CONFIG_FILE = "config.ini"
LOG_DIR = "logs"
# === Determine SQL file from args ===
if len(sys.argv) > 1:
    SQL_FILE = sys.argv[1]
else:
    SQL_FILE = "test.sql"
    
# === Setup logging ===
def setup_logger():
    os.makedirs(LOG_DIR, exist_ok=True)
    log_filename = os.path.join(LOG_DIR, f"run_sql_{datetime.now():%Y%m%d_%H%M%S}.log")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_filename, encoding="utf-8"),
            logging.StreamHandler(sys.stdout)
        ],
    )
    logging.info(f"Logging initialized → {log_filename}")
    return log_filename


# === Config reader ===
def load_config():
    if not os.path.isfile(CONFIG_FILE):
        sys.exit(f"❌ Config file not found: {CONFIG_FILE}")

    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_FILE)

    try:
        return {
            "base_url": cfg.get("server", "base_url").rstrip("/"),
            "verify_tls": cfg.getboolean("server", "verify_tls", fallback=True),
            "username": cfg.get("auth", "username"),
            "password": cfg.get("auth", "password"),
            "poll_interval": cfg.getint("defaults", "poll_interval_seconds", fallback=30),
            "poll_timeout": cfg.getint("defaults", "poll_timeout_seconds", fallback=7200),
        }
    except Exception as e:
        logging.error(f"❌ Invalid config file format: {e}")
        sys.exit(1)


# === Read SQL file ===
def read_sql_file():
    if not os.path.isfile(SQL_FILE):
        sys.exit(f"❌ SQL file not found: {SQL_FILE}")

    with open(SQL_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    statements = [s.strip() for s in content.split(";") if s.strip()]
    if not statements:
        sys.exit(f"❌ No SQL statements found in {SQL_FILE}")

    logging.info(f"Loaded {len(statements)} SQL statements from {SQL_FILE}")
    return statements


# === Dremio API helpers ===
def dremio_login(base_url, username, password, verify_tls):
    url = f"{base_url}/apiv2/login"
    resp = requests.post(url, json={"userName": username, "password": password}, verify=verify_tls)
    if not resp.ok:
        logging.error(f"Login failed → {resp.status_code}: {resp.text}")
        sys.exit(1)

    token = resp.json().get("token")
    if not token:
        sys.exit("❌ No token returned from login response")

    logging.info("✅ Successfully authenticated with Dremio API")
    return {"Authorization": f"_dremio{token}", "Content-Type": "application/json"}


def submit_sql(base_url, headers, sql, verify_tls):
    url = f"{base_url}/api/v3/sql"
    resp = requests.post(url, headers=headers, json={"sql": sql}, verify=verify_tls)
    if not resp.ok:
        raise RuntimeError(f"SQL submission failed ({resp.status_code}): {resp.text}")

    job_id = resp.json().get("id") or resp.json().get("jobId")
    if not job_id:
        raise RuntimeError(f"No job ID in response: {resp.text}")

    logging.info(f"📤 Submitted SQL job → {job_id}")
    return job_id


def wait_for_job(base_url, headers, job_id, verify_tls, poll_interval, poll_timeout):
    url = f"{base_url}/api/v3/job/{job_id}"
    end_time = time.time() + poll_timeout
    while True:
        resp = requests.get(url, headers=headers, verify=verify_tls)
        if not resp.ok:
            raise RuntimeError(f"Error polling job {job_id}: {resp.text}")

        state = resp.json().get("jobState")
        if state in ("COMPLETED", "FAILED", "CANCELED"):
            logging.info(f"🏁 Job {job_id} finished with state: {state}")
            return state, resp.json()

        if time.time() > end_time:
            raise TimeoutError(f"Job {job_id} timed out after {poll_timeout}s")

        logging.info(f"⏳ Waiting ({state})... next check in {poll_interval}s")
        time.sleep(poll_interval)


def fetch_results(base_url, headers, job_id, verify_tls):
    url = f"{base_url}/api/v3/job/{job_id}/results"
    resp = requests.get(url, headers=headers, verify=verify_tls)
    if not resp.ok:
        raise RuntimeError(f"Fetching results failed ({resp.status_code}): {resp.text}")

    data = resp.json()
    rows = data.get("rows", [])
    cols = [c.get("name") for c in data.get("schema", [])]
    return cols, rows


# === Main ===
def main():
    setup_logger()
    cfg = load_config()
    headers = dremio_login(cfg["base_url"], cfg["username"], cfg["password"], cfg["verify_tls"])
    statements = read_sql_file()

    for idx, sql in enumerate(statements, start=1):
        logging.info(f"▶️ Running statement #{idx}:\n{sql}")

        try:
            job_id = submit_sql(cfg["base_url"], headers, sql, cfg["verify_tls"])
            time.sleep(2)
            state, info = wait_for_job(
                cfg["base_url"],
                headers,
                job_id,
                cfg["verify_tls"],
                cfg["poll_interval"],
                cfg["poll_timeout"],
            )

            if state != "COMPLETED":
                logging.error(f"❌ Job failed: {info.get('errorMessage') or info.get('failureInfo')}")
                continue

            cols, rows = fetch_results(cfg["base_url"], headers, job_id, cfg["verify_tls"])
            if rows:
                logging.info(f"✅ {len(rows)} rows returned, columns: {cols}")
                for r in rows:
                    logging.debug(json.dumps(r, ensure_ascii=False))
            else:
                logging.info("ℹ️ No rows returned (DDL/DML).")

        except Exception as e:
            logging.exception(f"❌ Error executing statement #{idx}: {e}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
dremio_client.py
Simple Dremio REST helper to login, run SQL, poll job state and fetch results.
Reads server and credentials from config.ini (see example).

Usage example at bottom of file (if __name__ == "__main__":).
"""

import configparser
import json
import logging
import os
import time
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dremio_client")

# --- Exceptions ---
class DremioError(Exception):
    pass

# --- Config loader ---
def load_config(path: str = "config.ini") -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    read_files = cfg.read(path)
    if not read_files:
        raise FileNotFoundError(f"Config file not found at: {path}")
    return cfg

# --- HTTP session with retries ---
def make_session(retries: int = 3, backoff: float = 1.0, verify: bool = True) -> requests.Session:
    s = requests.Session()
    s.verify = verify
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

# --- Auth ---
def dremio_login(session: requests.Session, base_url: str, username: str, password: str, timeout: int = 30) -> None:
    """
    Login to Dremio and set Authorization header on the session.
    Raises on failure.
    """
    url = f"{base_url}/apiv2/login"
    payload = {"userName": username, "password": password}
    logger.info("Logging into Dremio: %s", base_url)
    resp = session.post(url, json=payload, timeout=timeout)
    try:
        resp.raise_for_status()
    except Exception as ex:
        raise DremioError(f"Login failed ({resp.status_code}): {resp.text}") from ex

    data = resp.json()
    token = data.get("token")
    if not token:
        raise DremioError("Login succeeded but token missing in response.")
    session.headers.update({"Authorization": f"_dremio{token}"})
    logger.info("Login OK, token applied to session.")

# --- Run SQL (returns job id) ---
def run_sql(session: requests.Session, base_url: str, sql: str, timeout: int = 30) -> str:
    """
    Submit SQL to Dremio and return job id.
    """
    url = f"{base_url}/api/v3/sql"
    logger.debug("Submitting SQL: %s", sql if len(sql) < 200 else sql[:200] + "...")
    resp = session.post(url, json={"sql": sql}, timeout=timeout)
    try:
        resp.raise_for_status()
    except Exception as ex:
        raise DremioError(f"SQL submission failed ({resp.status_code}): {resp.text}") from ex

    data = resp.json()
    job_id = data.get("id")
    if not job_id:
        raise DremioError(f"No job id returned for SQL submission. Response: {data}")
    logger.info("SQL submitted. jobId=%s", job_id)
    return job_id

# --- Poll job ---
def wait_for_job(session: requests.Session, base_url: str, job_id: str, poll_interval: int = 5, timeout: int = 3600) -> Dict[str, Any]:
    """
    Poll /api/v3/job/{job_id} until terminal state (COMPLETED/FAILED/CANCELED) or timeout.
    Returns full job JSON when finished.
    """
    url = f"{base_url}/api/v3/job/{job_id}"
    start = time.time()
    last_state = None
    logger.info("Polling job %s every %ds (timeout=%ds)", job_id, poll_interval, timeout)

    while True:
        resp = session.get(url, timeout=30)
        try:
            resp.raise_for_status()
        except Exception as ex:
            raise DremioError(f"Failed fetching job status for {job_id}: {resp.text}") from ex

        job = resp.json()
        # Dremio may present the state in different places depending on response structure
        state = job.get("jobState") or job.get("jobAttempt", {}).get("state") or job.get("state")
        if state != last_state:
            logger.info("Job %s state -> %s", job_id, state)
            last_state = state

        if state in ("COMPLETED", "FAILED", "CANCELED"):
            logger.info("Job %s ended with state: %s", job_id, state)
            return job

        if (time.time() - start) > timeout:
            raise TimeoutError(f"Job {job_id} did not reach terminal state within {timeout} seconds")

        time.sleep(poll_interval)

# --- Fetch job results (if applicable) ---
def fetch_job_results(session: requests.Session, base_url: str, job_id: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Fetch job results (first page). The API for results may be /api/v3/job/{id}/results or similar.
    We attempt to retrieve /api/v3/job/{id}/results; adjust if your Dremio version differs.
    """
    url = f"{base_url}/api/v3/job/{job_id}/results"
    resp = session.get(url, timeout=timeout)
    try:
        resp.raise_for_status()
    except Exception as ex:
        raise DremioError(f"Failed fetching results for job {job_id}: {resp.text}") from ex
    return resp.json()

# --- Convenience wrapper: run SQL and wait, optionally fetch results ---
def run_sql_and_wait(session: requests.Session, base_url: str, sql: str, poll_interval: int = 5, timeout: int = 3600, fetch_results: bool = False):
    job_id = run_sql(session, base_url, sql)
    job = wait_for_job(session, base_url, job_id, poll_interval=poll_interval, timeout=timeout)

    state = job.get("jobState") or job.get("jobAttempt", {}).get("state") or job.get("state")
    if state != "COMPLETED":
        # try to include failure info
        failure = job.get("failureInfo") or job.get("errorMessage") or job
        raise DremioError(f"Job {job_id} finished with state={state}. details={failure}")

    results = None
    if fetch_results:
        results = fetch_job_results(session, base_url, job_id)
    return {"job_id": job_id, "job": job, "results": results}

def get_latest_reflection_job_id(session, base_url, dataset, timeout=60):
    """
    Returns latest ACCELERATOR_CREATE job_id for given dataset path using sys.jobs_recent.
    Example dataset format: mtn_ba_refs.flare_8.cis_cdr_20250901
    """
    sql = f"""
    SELECT job_id
    FROM sys.jobs_recent
    WHERE queried_datasets LIKE '%{dataset}%'
      AND query_type = 'ACCELERATOR_CREATE'
    ORDER BY submitted_ts DESC
    LIMIT 1;
    """

    # Run the SQL and wait for metadata only (no long job expected here)
    result = run_sql_and_wait(session, base_url, sql, fetch_results=True, timeout=timeout)

    rows = result.get("results", {}).get("rows", [])
    if not rows:
        raise RuntimeError(f"No reflection job found yet for dataset: {dataset}")

    return rows[0]["job_id"]
# --- Main CLI example ---
def main(config_path: str = "config.ini"):
    cfg = load_config(config_path)

    base_url = cfg.get("server", "base_url")
    verify_tls = cfg.getboolean("server", "verify_tls", fallback=True)

    username = cfg.get("auth", "username", fallback=os.getenv("DREMIO_USERNAME"))
    password = cfg.get("auth", "password", fallback=os.getenv("DREMIO_PASSWORD"))
    if not username or not password:
        raise ValueError("Missing Dremio credentials. Provide in config.ini or via DREMIO_USERNAME/DREMIO_PASSWORD env vars.")

    poll_interval = cfg.getint("defaults", "poll_interval_seconds", fallback=5)
    poll_timeout = cfg.getint("defaults", "poll_timeout_seconds", fallback=3600)

    session = make_session(retries=3, backoff=1.0, verify=verify_tls)
    dremio_login(session, base_url, username, password)

    # Example: create/update a reflection (replace with your SQL)
    create_reflection_sql = """
    /* idempotent reflection DDL example - adjust to your dataset and columns */
    ALTER DATASET "mtn_ba_refs"."flare_8"."cis_cdr_20250901" CREATE RAW REFLECTION "rfl_cis_cdr_20250901" USING DISPLAY (
"msisdn",
"beneficiary_msisdn",
"consumer_msisdn",
"dt",
"transaction_date_time",
"channel_name",
"short_code",
"keyword",
"product_id",
"product_name",
"product_type",
"product_subtype",
"renewal_adhoc",
"action",
"activation_time",
"expiry_time",
"grace_period",
"offer_id",
"cug_id",
"f3pp_transactionid",
"request_id",
"correlation_id",
"charging_amount",
"charging_node",
"transaction_charges",
"f3pp_chargedamount",
"auto_renewal_consent",
"provisioning_type",
"status",
"failure_reason",
"notification_sent",
"ipaddress",
"current_sc",
"new_sc",
"agent_id",
"user_id",
"alternate_number",
"imei_number",
"faf_id",
"faf_number",
"mifi_msisdn",
"source_action",
"goody_bag",
"response_time",
"product_flag",
"carte_prod_list",
"transfer_volume",
"voucher_code",
"gds_company_name",
"parameter_1",
"file_name",
"file_offset",
"kamanja_loaded_date",
"file_mod_date",
"msisdn_key",
"date_key",
"event_timestamp_enrich",
"original_timestamp_enrich",
"msg_unique_id_enrich",
"base_file_name",
"path",
"line_number",
"file_id",
"processed_timestamp",
"ltz_event_timestamp_enrich",
"parameter_2",
"parameter_3",
"parameter_4",
"parameter_5",
"parameter_6",
"parameter_7",
"parameter_8",
"parameter_9",
"parameter_10",
"tbl_dt"
)
    """
    # Submit reflection DDL and wait
    logger.info("Submitting reflection DDL...")
    reflection_out=run_sql_and_wait(session, base_url, create_reflection_sql, poll_interval, poll_timeout, fetch_results=False)
    logger.info("Reflection started: job=%s", reflection_out["job_id"])
    # ✅ Sleep 5 seconds before starting job polling or next action
    time.sleep(15)
    
    job_id = get_latest_reflection_job_id(
    session,
    base_url,
    dataset="cis_cdr_20250901",
    )
    print("Reflection materialization job=", job_id)

    # 3️⃣ Wait for completion
    wait_for_job(session, base_url, job_id, poll_interval=5, timeout=3600)
    print("Reflection completed ✅")   

if __name__ == "__main__":
    # Run using default config.ini in cwd
    try:
        main("config.ini")
    except Exception as e:
        logger.exception("Script failed: %s", e)
        raise

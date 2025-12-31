import os, json, time, logging
from typing import Dict, List, Optional
import configparser
import json
import logging
import os
import time
from typing import Optional, Dict, Any
from datetime import datetime
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("dremio_batch")
logger.setLevel(logging.INFO)

def setup_logging():
    # Create logs directory if not exist
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)

    # Timestamped file name
    ts = datetime.now().strftime("%Y%m%d%H%M%S")
    log_file = os.path.join(log_dir, f"log_reflection_{ts}.log")

    # Configure logging: file + console
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler()  # prints to console
        ]
    )
    logger = logging.getLogger("reflection_logger")
    logger.info("Logging started. Output file: %s", log_file)
    return logger, log_file

# --- helpers you already have (assumed imported) ---
# load_config, make_session, dremio_login, run_sql_and_wait, wait_for_job

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
def wait_for_job(session: requests.Session, base_url: str, job_id: str, poll_interval: int = 30, timeout: int = 7200) -> Dict[str, Any]:
    """
    Poll /api/v3/job/{job_id} until terminal state (COMPLETED/FAILED/CANCELED) or timeout.
    Returns full job JSON when finished.
    """
    url = f"{base_url}/api/v3/job/{job_id}"
    start = time.time()
    last_state = None
    logger.info("Wait for 5 seconds to complete metadata retrieval...)", job_id, poll_interval, timeout)
    time.sleep(5)
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

# --- find job id via sys.jobs_recent (stable) ---
def get_latest_reflection_job_id(session, base_url, dotted_dataset: str, timeout=60):
    """
    dotted_dataset: e.g. mtn_ba_refs.flare_8.cis_cdr_20250901
    Returns the latest ACCELERATOR_CREATE job_id for the dataset.
    """
    sql = f"""
    SELECT job_id
    FROM sys.jobs_recent
    WHERE queried_datasets LIKE '%{dotted_dataset}%'
      AND query_type = 'ACCELERATOR_CREATE'
    ORDER BY submitted_ts DESC
    LIMIT 1;
    """
    out = run_sql_and_wait(session, base_url, sql, fetch_results=True, poll_interval=2, timeout=timeout)
    rows = (out.get("results") or {}).get("rows", [])
    if not rows:
        raise RuntimeError(f"No reflection creation job found yet for dataset: {dotted_dataset}")
    return rows[0]["job_id"]

# --- build SQL snippets ---
def _q_ident(*parts: str) -> str:
    """Return a fully quoted identifier path for SQL (e.g., "space"."schema"."table")."""
    return ".".join(f'"{p}"' for p in parts)

def _list_sql(cols: Optional[List[str]]) -> str:
    if not cols: return "()"
    return "(" + ",".join(f'"{c}"' for c in cols) + ")"

def build_create_reflection_sql(
    space: str, schema: str, table_base: str, date_str: str,
    reflection_prefix: str,
    display_cols: List[str],
    partition_by: Optional[List[str]] = None,
    local_sort: Optional[List[str]] = None,
    distribute_by: Optional[List[str]] = None
) -> (str, str, str, str):
    """
    Returns (dataset_sql_path, dotted_dataset, create_sql).
    Dataset actual name is f"{table_base}_{date_str}".
    Reflection name is f"{reflection_prefix}_{table_base}_{date_str}".
    """
    dataset_name  = f"{table_base}_{date_str}"
    reflection_nm = f'{reflection_prefix}_{table_base}_{date_str}'
    dataset_sql   = _q_ident(space, schema, dataset_name)  # "mtn_ba_refs"."flare_8"."cis_cdr_20250901"
    dotted        = f"{space}.{schema}.{dataset_name}"

    parts = [
        f'ALTER DATASET {dataset_sql} CREATE RAW REFLECTION "{reflection_nm}" USING',
        f'  DISPLAY {_list_sql(display_cols)}'
    ]
    if partition_by:  parts.append(f'  PARTITION BY {_list_sql(partition_by)}')
    if local_sort:    parts.append(f'  LOCALSORT {_list_sql(local_sort)}')
    if distribute_by: parts.append(f'  DISTRIBUTE BY {_list_sql(distribute_by)}')

    create_sql = "\n".join(parts) + ";"
    return dataset_sql, dotted, create_sql, reflection_nm

def load_table_specs(json_path: str) -> Dict[str, Dict]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("JSON root must be an object mapping table_name -> spec.")
    return data
def reflection_exists(session, base_url, reflection_name):
    sql = f"""
    SELECT COUNT(*) > 0 AS existed
    FROM sys.reflections
    WHERE reflection_name = '{reflection_name}'
    """
    result = run_sql_and_wait(session, base_url, sql, fetch_results=True)
    rows = result.get("results", {}).get("rows", [])
    return bool(rows and rows[0]["existed"])

def view_exists(session, base_url, space: str, schema: str, view_name: str) -> bool:
    """
    Returns True if the view "<space>"."<schema>"."<view_name>" exists in Dremio.
    Uses INFORMATION_SCHEMA.VIEWS with case-insensitive match.
    """
    table_schema = f"{space}.{schema}"
    sql = f"""
    SELECT COUNT(*) > 0 AS existed
    FROM INFORMATION_SCHEMA.VIEWS
    WHERE UPPER(table_schema) = UPPER('{table_schema}')
      AND UPPER(table_name)   = UPPER('{view_name}');
    """
    out = run_sql_and_wait(session, base_url, sql, fetch_results=True, poll_interval=2, timeout=60)
    rows = (out.get("results") or {}).get("rows", [])
    return bool(rows and rows[0]["existed"])

def main(config_path: str = "config.ini"):
    logger, log_file = setup_logging()
    logger.info("Starting reflection batch automation...")
    
    cfg = load_config(config_path)
    base_url   = cfg.get("server", "base_url")
    verify_tls = cfg.getboolean("server", "verify_tls", fallback=True)

    username = cfg.get("auth", "username", fallback=os.getenv("DREMIO_USERNAME"))
    password = cfg.get("auth", "password", fallback=os.getenv("DREMIO_PASSWORD"))
    if not username or not password:
        raise ValueError("Missing Dremio credentials. Provide in config.ini or via env vars.")

    poll_interval = cfg.getint("defaults", "poll_interval_seconds", fallback=60)
    poll_timeout  = cfg.getint("defaults", "poll_timeout_seconds",  fallback=7200)

    # --- Project-level constants (adjust as needed) ---
    SPACE            = "mtn_ba_refs"
    SCHEMA           = "flare_8"
    REFLECTION_PREFX = "rfl"
    TABLE_SPECS_JSON = "columns.json"

    # Dates to process (YYYYMMDD strings)
    DATES = [
        "20251101",
        "20251102", 
        "20251103",
        "20251104"
    ]

    # --- prepare session ---
    session = make_session(retries=3, backoff=1.0, verify=verify_tls)
    dremio_login(session, base_url, username, password)

    # --- load per-table specs (columns + optional partition/sort/distribute) ---
    table_specs = load_table_specs(TABLE_SPECS_JSON)
    # table_specs keys are table base names: e.g., "cis_cdr", "dpi_cdr"

    # --- iterate dates, then tables ---
    for date_str in DATES:
        logger.info("=== Processing date %s ===", date_str)

        for table_name, spec in table_specs.items():
            # Filter by display: true
            logger.info("=== Processing table/view %s ===", table_name )
            columns = spec.get("columns", [])
            display_cols = [col["name"] for col in columns if col.get("display", False)]
            partition_by  = spec.get("partition_by")
            local_sort    = spec.get("local_sort")
            distribute_by = spec.get("distribute_by")

            if not display_cols:
                logger.warning("No display columns for table %s; skipping.", table_name)
                continue

            dataset_sql, dotted_dataset, create_sql, reflection_nm = build_create_reflection_sql(
                SPACE, SCHEMA, table_name, date_str, REFLECTION_PREFX,
                display_cols,
                partition_by=partition_by,
                local_sort=local_sort,
                distribute_by=distribute_by
            )
            
            view_name = f"{table_name}_{date_str}"
            logger.info('Check if exists source view : "%s"', view_name)
            if not view_exists(session, base_url, SPACE, SCHEMA, view_name):
                logger.info('View not found: "%s"."%s"."%s" — skipping.', SPACE, SCHEMA, view_name)
                continue
        
            logger.info('Check if reflection exists : "%s"', reflection_nm)
            if reflection_exists(session, base_url, reflection_nm):
                logger.warning("Reflection already exists. Skipping.")
                continue
            else:
                logger.info("Reflection not found. Creating new one...")

            logger.info("Submitting reflection DDL for %s ...", dotted_dataset)
            out = run_sql_and_wait(session, base_url, create_sql,poll_interval=poll_interval, timeout=poll_timeout, fetch_results=False)
            logger.info("DDL submitted, job=%s", out["job_id"])

            # Give the materialization job a moment to appear in jobs tables
            time.sleep(5)

            # Find the reflection creation job id from sys.jobs_recent
            try:
                job_id = get_latest_reflection_job_id(session, base_url, dotted_dataset)
                logger.info("Materialization job found: %s", job_id)
            except Exception as e:
                logger.error("Could not find reflection job for %s: %s", dotted_dataset, e)
                continue

            # Wait for completion
            try:
                wait_for_job(session, base_url, job_id, poll_interval=poll_interval, timeout=poll_timeout)
                logger.info("Reflection COMPLETED for %s ✅", dotted_dataset)
            except Exception as e:
                logger.exception("Reflection job failed for %s (job=%s): %s", dotted_dataset, job_id, e)

    logger.info("All done.")
if __name__ == "__main__":
    # Run using default config.ini in cwd
    try:
        main("config.ini")
    except Exception as e:
        logger.exception("Script failed: %s", e)
        raise

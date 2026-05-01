import requests
from urllib.parse import quote
import time


class DremioService:
    def __init__(self, dremio_url, username, password, logger, verify_ssl=False):
        self.dremio_url = dremio_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None
        self.logger = logger

    def login(self):
        url = f"{self.dremio_url}/apiv2/login"

        self.logger.info("Logging in to Dremio: %s", self.dremio_url)

        payload = {
            "userName": self.username,
            "password": self.password
        }

        response = requests.post(
            url,
            json=payload,
            verify=self.verify_ssl,
            timeout=30
        )

        if response.status_code != 200:
            self.logger.error("Login failed. Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        data = response.json()
        self.token = data["token"]

        self.logger.info("Login successful")
        return self.token

    def validate_connection(self):
        """
        Validates Dremio connection by logging in and calling catalog root.
        """

        self.logger.info("Validating Dremio connection")

        self.login()

        url = f"{self.dremio_url}/api/v3/catalog"

        response = requests.get(
            url,
            headers=self._headers(),
            verify=self.verify_ssl,
            timeout=30
        )

        if response.status_code != 200:
            self.logger.error("Connection validation failed")
            self.logger.error("Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        self.logger.info("Connection validation successful")
        return True

    def _headers(self):
        if not self.token:
            self.login()

        return {
            "Authorization": f"_dremio{self.token}",
            "Content-Type": "application/json"
        }

    def get_catalog_by_path(self, path_parts):
        encoded_path = "/".join(quote(part, safe="") for part in path_parts)

        url = f"{self.dremio_url}/api/v3/catalog/by-path/{encoded_path}"

        self.logger.info("Checking catalog path: %s", "/".join(path_parts))

        response = requests.get(
            url,
            headers=self._headers(),
            verify=self.verify_ssl,
            timeout=30
        )

        if response.status_code == 404:
            self.logger.warning("Path not found: %s", "/".join(path_parts))
            return None

        if response.status_code != 200:
            self.logger.error("Failed to check path")
            self.logger.error("Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        self.logger.info("Path exists: %s", "/".join(path_parts))
        return response.json()

    def format_folder_as_table(
        self,
        path_parts,
        file_format="Parquet",
        extract_header=True,
        field_delimiter=","
    ):
        catalog_entity = self.get_catalog_by_path(path_parts)

        if not catalog_entity:
            raise ValueError(f"Path does not exist: {'/'.join(path_parts)}")

        entity_id = catalog_entity["id"]
        encoded_id = quote(entity_id, safe="")

        url = f"{self.dremio_url}/api/v3/catalog/{encoded_id}"

        self.logger.info("Formatting path as table")
        self.logger.info("Path: %s", "/".join(path_parts))
        self.logger.info("Format: %s", file_format)

        if file_format.lower() == "parquet":
            payload = {
                "entityType": "dataset",
                "type": "PHYSICAL_DATASET",
                "path": path_parts,
                "format": {
                    "type": "Parquet",
                    "fullPath": path_parts,
                    "isFolder": True
                }
            }

        elif file_format.lower() in ("csv", "text"):
            payload = {
                "entityType": "dataset",
                "type": "PHYSICAL_DATASET",
                "path": path_parts,
                "format": {
                    "type": "Text",
                    "fullPath": path_parts,
                    "isFolder": True,
                    "fieldDelimiter": field_delimiter,
                    "skipFirstLine": False,
                    "extractHeader": extract_header,
                    "quote": "\"",
                    "comment": "#",
                    "escape": "\"",
                    "lineDelimiter": "\n",
                    "autoGenerateColumnNames": not extract_header,
                    "trimHeader": True
                }
            }

        else:
            raise ValueError(f"Unsupported file format: {file_format}")

        response = requests.post(
            url,
            headers=self._headers(),
            json=payload,
            verify=self.verify_ssl,
            timeout=60
        )

        if response.status_code not in (200, 201):
            self.logger.error("Formatting failed")
            self.logger.error("Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        self.logger.info("Formatting completed successfully")
        return response.json()

    def run_sql_command(
        self,
        sql,
        context=None,
        poll_interval_seconds=5,
        timeout_seconds=3600,
        fetch_results=True,
        result_limit=100
    ):
        """
        Submits SQL to Dremio, follows job status until completion,
        and returns final job status/result.

        Useful for CTAS, DROP, SELECT, ALTER, etc.
        """

        if context is None:
            context = []

        self.logger.info("Submitting SQL command")
        self.logger.info("SQL: %s", sql)

        submit_url = f"{self.dremio_url}/api/v3/sql"

        payload = {
            "sql": sql,
            "context": context
        }

        response = requests.post(
            submit_url,
            headers=self._headers(),
            json=payload,
            verify=self.verify_ssl,
            timeout=60
        )

        if response.status_code not in (200, 202):
            self.logger.error("SQL submission failed")
            self.logger.error("Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        submit_result = response.json()
        job_id = submit_result.get("id") or submit_result.get("jobId")

        if not job_id:
            raise RuntimeError(f"SQL submitted but job id not found: {submit_result}")

        self.logger.info("SQL job submitted successfully")
        self.logger.info("Job ID: %s", job_id)

        final_status = self.wait_for_job_completion(
            job_id=job_id,
            poll_interval_seconds=poll_interval_seconds,
            timeout_seconds=timeout_seconds
        )

        result = {
            "job_id": job_id,
            "status": final_status.get("jobState"),
            "job_details": final_status,
            "rows": []
        }

        if final_status.get("jobState") == "COMPLETED":
            self.logger.info("SQL job completed successfully: %s", job_id)

            if fetch_results:
                result["rows"] = self.get_job_results(
                    job_id=job_id,
                    limit=result_limit
                )

        else:
            self.logger.error("SQL job failed or was cancelled")
            self.logger.error("Final status: %s", final_status)
            raise RuntimeError(
                f"SQL job did not complete successfully. "
                f"Job ID: {job_id}, State: {final_status.get('jobState')}"
            )

        return result

    def wait_for_job_completion(
        self,
        job_id,
        poll_interval_seconds=5,
        timeout_seconds=3600
    ):
        """
        Polls Dremio job status until terminal state.
        """

        self.logger.info("Waiting for job completion")
        self.logger.info("Job ID: %s", job_id)

        start_time = time.time()

        terminal_states = {
            "COMPLETED",
            "FAILED",
            "CANCELED",
            "CANCELLATION_REQUESTED"
        }

        while True:
            elapsed = time.time() - start_time

            if elapsed > timeout_seconds:
                self.logger.error("Job timeout reached")
                self.logger.error("Job ID: %s", job_id)
                raise TimeoutError(
                    f"Dremio job timeout after {timeout_seconds} seconds. "
                    f"Job ID: {job_id}"
                )

            job_status = self.get_job_status(job_id)
            job_state = job_status.get("jobState")

            self.logger.info(
                "Job status | job_id=%s | state=%s | elapsed=%.0fs",
                job_id,
                job_state,
                elapsed
            )

            if job_state in terminal_states:
                return job_status

            time.sleep(poll_interval_seconds)

    def get_job_status(self, job_id):
        """
        Gets current Dremio job status.
        """

        url = f"{self.dremio_url}/api/v3/job/{job_id}"

        response = requests.get(
            url,
            headers=self._headers(),
            verify=self.verify_ssl,
            timeout=30
        )

        if response.status_code != 200:
            self.logger.error("Failed to get job status")
            self.logger.error("Job ID: %s", job_id)
            self.logger.error("Status: %s", response.status_code)
            self.logger.error("Response: %s", response.text)
            response.raise_for_status()

        return response.json()

    def get_job_results(self, job_id, offset=0, limit=100):
        """
        Fetches result rows from completed Dremio job.
        Useful mostly for SELECT queries.
        CTAS usually returns no meaningful rows.
        """

        self.logger.info("Fetching job results")
        self.logger.info("Job ID: %s", job_id)

        url = f"{self.dremio_url}/api/v3/job/{job_id}/results"

        params = {
            "offset": offset,
            "limit": limit
        }

        response = requests.get(
            url,
            headers=self._headers(),
            params=params,
            verify=self.verify_ssl,
            timeout=60
        )

        if response.status_code != 200:
            self.logger.warning("Could not fetch job results")
            self.logger.warning("Job ID: %s", job_id)
            self.logger.warning("Status: %s", response.status_code)
            self.logger.warning("Response: %s", response.text)
            return []

        data = response.json()
        rows = data.get("rows", [])

        self.logger.info("Fetched %s result rows", len(rows))

        return rows
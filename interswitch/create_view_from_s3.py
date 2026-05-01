import json
from dremio_service import DremioService
from logger_config import setup_logger


CONFIG_FILE = "config.json"

S3_PATH = [
    "minio",
    "test",
    "nyc",
    "2026"
]

VIEW_PATH = [
    "NYC"
]

FILE_FORMAT = "Parquet"


def load_config(config_file):
    with open(config_file, "r", encoding="utf-8") as file:
        return json.load(file)


def quote_path(path_parts):
    return ".".join(f'"{part}"' for part in path_parts)


def generate_view_name(s3_path):
    return f"vw_{s3_path[-1]}"


def build_refresh_metadata_sql(s3_path):
    return f"ALTER TABLE {quote_path(s3_path)} REFRESH METADATA"


def build_create_view_sql(s3_path, view_path):
    view_name = generate_view_name(s3_path)

    full_view_path = view_path + [view_name]

    return f"""
CREATE OR REPLACE VIEW {quote_path(full_view_path)} AS
SELECT *
FROM {quote_path(s3_path)}
""".strip()


def is_promoted_dataset(catalog_entity, logger=None):
    if logger:
        logger.info("Catalog Entity (Pretty):\n%s",
                    json.dumps(catalog_entity, indent=2))
    else:
        print(json.dumps(catalog_entity, indent=2))

    if not catalog_entity:
        return False

    return (
        catalog_entity.get("entityType") == "dataset"
    )
    
def main():
    logger = setup_logger()

    try:
        logger.info("Starting Dremio promote/refresh/view automation")
        logger.info("S3_PATH: %s", S3_PATH)
        logger.info("VIEW_PATH: %s", VIEW_PATH)

        config = load_config(CONFIG_FILE)

        dremio = DremioService(
            dremio_url=config["dremio_url"],
            username=config["username"],
            password=config["password"],
            verify_ssl=config.get("verify_ssl", False),
            logger=logger
        )

        logger.info("Step 1: Validate Dremio connection")
        dremio.validate_connection()

        logger.info("Step 2: Check S3 catalog path")
        catalog_entity = dremio.get_catalog_by_path(S3_PATH)

        if not catalog_entity:
            logger.error("S3 path does not exist in Dremio catalog: %s", quote_path(S3_PATH))
            return

        logger.info("Catalog path exists")
        logger.info("Entity ID: %s", catalog_entity.get("id"))
        logger.info("Entity Type: %s", catalog_entity.get("type"))
        logger.info("Dataset Type: %s", catalog_entity.get("datasetType"))

        if is_promoted_dataset(catalog_entity):
            logger.info("Path is already promoted as dataset/table")

            refresh_sql = build_refresh_metadata_sql(S3_PATH)
            logger.info("Step 3: Refresh metadata")
            logger.info("Refresh SQL: %s", refresh_sql)

            refresh_result = dremio.run_sql_command(
                sql=refresh_sql,
                poll_interval_seconds=5,
                timeout_seconds=3600,
                fetch_results=False
            )

            logger.info("Refresh metadata completed")
            logger.info("Refresh Job ID: %s", refresh_result["job_id"])
            logger.info("Refresh Status: %s", refresh_result["status"])

        else:
            logger.info("Path is not promoted yet")
            logger.info("Step 3: Format/promote folder as table")

            promote_result = dremio.format_folder_as_table(
                path_parts=S3_PATH,
                file_format=FILE_FORMAT
            )

            logger.info("Folder promoted successfully")
            logger.info("Promote result: %s", json.dumps(promote_result, indent=2))

        logger.info("Step 4: Create or replace view")

        view_sql = build_create_view_sql(S3_PATH, VIEW_PATH)
        logger.info("View SQL: %s", view_sql)

        view_result = dremio.run_sql_command(
            sql=view_sql,
            poll_interval_seconds=5,
            timeout_seconds=3600,
            fetch_results=False
        )

        final_view_name = ".".join(VIEW_PATH + [generate_view_name(S3_PATH)])

        logger.info("View created/refreshed successfully")
        logger.info("View Path: %s", final_view_name)
        logger.info("View Job ID: %s", view_result["job_id"])
        logger.info("View Status: %s", view_result["status"])

        logger.info("Process completed successfully")

    except Exception as error:
        logger.exception("Process failed: %s", error)


if __name__ == "__main__":
    main()
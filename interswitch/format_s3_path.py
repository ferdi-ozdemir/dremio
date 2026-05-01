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

FILE_FORMAT = "Parquet"

# Safety switch
# Set True only when you really want to format/promote the folder.
CONFIRM_FORMAT = True


def load_config(config_file):
    with open(config_file, "r", encoding="utf-8") as file:
        return json.load(file)


def main():
    logger = setup_logger()

    try:
        logger.info("Starting Dremio S3 folder formatter")

        config = load_config(CONFIG_FILE)

        dremio = DremioService(
            dremio_url=config["dremio_url"],
            username=config["username"],
            password=config["password"],
            verify_ssl=config.get("verify_ssl", False),
            logger=logger
        )

        dremio.validate_connection()

        existing_path = dremio.get_catalog_by_path(S3_PATH)

        if not existing_path:
            logger.error("Stopping process because path does not exist")
            return

        logger.info("Catalog entity type: %s", existing_path.get("entityType"))
        logger.info("Catalog entity id: %s", existing_path.get("id"))

        if not CONFIRM_FORMAT:
            logger.warning("CONFIRM_FORMAT is False")
            logger.warning("Format operation skipped")
            logger.warning("Set CONFIRM_FORMAT = True to format this path as a table")
            return

        result = dremio.format_folder_as_table(
            path_parts=S3_PATH,
            file_format=FILE_FORMAT
        )

        logger.info("Result:")
        logger.info(json.dumps(result, indent=2))

    except Exception as error:
        logger.exception("Process failed: %s", error)


if __name__ == "__main__":
    main()
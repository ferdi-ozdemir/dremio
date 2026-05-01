from datetime import date, timedelta

OUTPUT_FILE = "create_daily_january_2026_tables.sql"

SOURCE_TABLE = 'minio.test.nyc."2026"'
TARGET_BASE = '"minio"."test"."nyc"."exports"."d202601"'
TABLE_PREFIX = "yellow_tripdata"


def generate_ctas_sql(day: date) -> str:
    current_day = day.strftime("%Y-%m-%d")
    next_day = (day + timedelta(days=1)).strftime("%Y-%m-%d")
    table_suffix = day.strftime("%Y%m%d")

    target_table = f'{TARGET_BASE}.{TABLE_PREFIX}_{table_suffix}'

    return f"""
-- {current_day}
CREATE TABLE {target_table}
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM {SOURCE_TABLE}
WHERE tpep_pickup_datetime >= TIMESTAMP '{current_day} 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '{next_day} 00:00:00';
""".strip()


def main():
    start_date = date(2026, 1, 1)
    end_date = date(2026, 2, 1)

    statements = []

    current = start_date
    while current < end_date:
        statements.append(generate_ctas_sql(current))
        current += timedelta(days=1)

    sql_content = "\n\n".join(statements)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        file.write(sql_content)

    print(f"SQL file created: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
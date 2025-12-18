-- =====================================================================
-- Auto-generated ELT SQL for date key 20251106
-- Generated at 2025-11-14 13:25:20
-- NOTE: tbl_dt is INT (no quotes).
-- =====================================================================

-- =====================================================================
-- Table: cis_cdr | tbl_dt range: 20251106
-- =====================================================================

-- 1) Check if view exists
SELECT table_schema, table_name
FROM INFORMATION_SCHEMA."VIEWS"
WHERE table_schema  = 'mtn_ba_refs.flare_8'
  AND table_name    = 'cis_cdr_20251106';
-- If no rows, run:
CREATE VIEW "mtn_ba_refs"."flare_8"."cis_cdr_20251106" AS
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, tbl_dt
FROM "mtn_hive"."flare_8"."cis_cdr"
WHERE tbl_dt = 20251106
 limit 100;

-- 2) Check if reflection exists
SELECT reflection_id, reflection_name, status
FROM sys.reflections
WHERE reflection_name = 'rfl_cis_cdr_20251106';
-- If no rows, run:
ALTER TABLE "mtn_ba_refs"."flare_8"."cis_cdr_20251106"
CREATE RAW REFLECTION "rfl_cis_cdr_20251106"
USING DISPLAY (msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, tbl_dt);

-- 3) Check if target S3 table exists
SELECT table_schema, table_name
FROM INFORMATION_SCHEMA."TABLES"
WHERE table_schema  = 'mtn-s3.flare_8'
  AND table_name    = 'cis_cdr_cst';
-- If no rows, run (empty CTAS):
CREATE TABLE IF NOT EXISTS "mtn-s3"."flare_8"."cis_cdr_cst" AS
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, tbl_dt
FROM "mtn_ba_refs"."flare_8"."cis_cdr_20251106"
WHERE 1 = 0;

-- 4) Insert data into S3 table
INSERT INTO "mtn-s3"."flare_8"."cis_cdr_cst"
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, tbl_dt
FROM "mtn_ba_refs"."flare_8"."cis_cdr_20251106";

-- 5) TODO: partition "mtn-s3"."flare_8"."cis_cdr_cst" for tbl_dt = 20251106


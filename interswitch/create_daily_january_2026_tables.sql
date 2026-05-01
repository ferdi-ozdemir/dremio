-- 2026-01-02
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260102
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-02 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-03 00:00:00';

-- 2026-01-03
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260103
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-03 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-04 00:00:00';

-- 2026-01-04
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260104
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-04 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-05 00:00:00';

-- 2026-01-05
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260105
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-05 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-06 00:00:00';

-- 2026-01-06
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260106
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-06 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-07 00:00:00';

-- 2026-01-07
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260107
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-07 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-08 00:00:00';

-- 2026-01-08
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260108
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-08 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-09 00:00:00';

-- 2026-01-09
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260109
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-09 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-10 00:00:00';

-- 2026-01-10
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260110
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-10 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-11 00:00:00';

-- 2026-01-11
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260111
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-11 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-12 00:00:00';

-- 2026-01-12
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260112
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-12 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-13 00:00:00';

-- 2026-01-13
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260113
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-13 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-14 00:00:00';

-- 2026-01-14
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260114
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-14 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-15 00:00:00';

-- 2026-01-15
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260115
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-15 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-16 00:00:00';

-- 2026-01-16
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260116
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-16 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-17 00:00:00';

-- 2026-01-17
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260117
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-17 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-18 00:00:00';

-- 2026-01-18
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260118
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-18 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-19 00:00:00';

-- 2026-01-19
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260119
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-19 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-20 00:00:00';

-- 2026-01-20
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260120
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-20 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-21 00:00:00';

-- 2026-01-21
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260121
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-21 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-22 00:00:00';

-- 2026-01-22
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260122
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-22 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-23 00:00:00';

-- 2026-01-23
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260123
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-23 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-24 00:00:00';

-- 2026-01-24
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260124
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-24 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-25 00:00:00';

-- 2026-01-25
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260125
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-25 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-26 00:00:00';

-- 2026-01-26
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260126
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-26 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-27 00:00:00';

-- 2026-01-27
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260127
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-27 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-28 00:00:00';

-- 2026-01-28
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260128
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-28 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-29 00:00:00';

-- 2026-01-29
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260129
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-29 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-30 00:00:00';

-- 2026-01-30
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260130
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-30 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-01-31 00:00:00';

-- 2026-01-31
CREATE TABLE "minio"."test"."nyc"."exports"."d202601".yellow_tripdata_20260131
STORE AS (type => 'parquet')
AS
SELECT
    DATE_TRUNC('DAY', tpep_pickup_datetime) AS pickup_day,
    *
FROM minio.test.nyc."2026"
WHERE tpep_pickup_datetime >= TIMESTAMP '2026-01-31 00:00:00'
  AND tpep_pickup_datetime <  TIMESTAMP '2026-02-01 00:00:00';
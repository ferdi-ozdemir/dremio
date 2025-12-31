-- =====================================================================
-- Auto-generated ELT SQL for date key 20251107
-- Generated at 2025-11-09 14:07:29
-- =====================================================================


-- =====================================================================
-- ELT steps for table cis_cdr | tbl_dt range: 20251107 - 20251108
-- =====================================================================

-- 3.0 Check if the view already exists
SELECT table_catalog, table_schema, table_name
FROM INFORMATION_SCHEMA."VIEWS"
WHERE table_catalog = 'mtn_ba_refs'
  AND table_schema  = 'flare_8'
  AND table_name    = 'cis_cdr_20251107_20251108';

-- If no rows are returned above, run the CREATE VIEW below:
CREATE VIEW "mtn_ba_refs"."flare_8"."cis_cdr_20251107_20251108" AS
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, channel_name, short_code, keyword, product_id, product_name, product_type, product_subtype, renewal_adhoc, action, activation_time, expiry_time, grace_period, offer_id, cug_id, f3pp_transactionid, request_id, correlation_id, charging_amount, charging_node, transaction_charges, f3pp_chargedamount, auto_renewal_consent, provisioning_type, status, failure_reason, notification_sent, ipaddress, current_sc, new_sc, agent_id, user_id, alternate_number, imei_number, faf_id, faf_number, mifi_msisdn, source_action, goody_bag, response_time, product_flag, carte_prod_list, transfer_volume, voucher_code, gds_company_name, parameter_1, file_name, file_offset, kamanja_loaded_date, file_mod_date, msisdn_key, date_key, event_timestamp_enrich, original_timestamp_enrich, msg_unique_id_enrich, base_file_name, path, line_number, file_id, processed_timestamp, ltz_event_timestamp_enrich, parameter_2, parameter_3, parameter_4, parameter_5, parameter_6, parameter_7, parameter_8, parameter_9, parameter_10, tbl_dt
FROM "mtn_hive"."flare_8"."cis_cdr"
WHERE tbl_dt BETWEEN 20251107 AND 20251108;

-- 3.2 Create RAW reflection on the view
ALTER TABLE "mtn_ba_refs"."flare_8"."cis_cdr_20251107_20251108"
CREATE RAW REFLECTION "rfl_cis_cdr_20251107_20251108"
USING DISPLAY (msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, channel_name, short_code, keyword, product_id, product_name, product_type, product_subtype, renewal_adhoc, action, activation_time, expiry_time, grace_period, offer_id, cug_id, f3pp_transactionid, request_id, correlation_id, charging_amount, charging_node, transaction_charges, f3pp_chargedamount, auto_renewal_consent, provisioning_type, status, failure_reason, notification_sent, ipaddress, current_sc, new_sc, agent_id, user_id, alternate_number, imei_number, faf_id, faf_number, mifi_msisdn, source_action, goody_bag, response_time, product_flag, carte_prod_list, transfer_volume, voucher_code, gds_company_name, parameter_1, file_name, file_offset, kamanja_loaded_date, file_mod_date, msisdn_key, date_key, event_timestamp_enrich, original_timestamp_enrich, msg_unique_id_enrich, base_file_name, path, line_number, file_id, processed_timestamp, ltz_event_timestamp_enrich, parameter_2, parameter_3, parameter_4, parameter_5, parameter_6, parameter_7, parameter_8, parameter_9, parameter_10, tbl_dt);

-- 4.1 Create S3 table if not exists (using CTAS with no rows)
CREATE TABLE IF NOT EXISTS "mtn-s3"."flare_8"."cis_cdr_cst" AS
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, channel_name, short_code, keyword, product_id, product_name, product_type, product_subtype, renewal_adhoc, action, activation_time, expiry_time, grace_period, offer_id, cug_id, f3pp_transactionid, request_id, correlation_id, charging_amount, charging_node, transaction_charges, f3pp_chargedamount, auto_renewal_consent, provisioning_type, status, failure_reason, notification_sent, ipaddress, current_sc, new_sc, agent_id, user_id, alternate_number, imei_number, faf_id, faf_number, mifi_msisdn, source_action, goody_bag, response_time, product_flag, carte_prod_list, transfer_volume, voucher_code, gds_company_name, parameter_1, file_name, file_offset, kamanja_loaded_date, file_mod_date, msisdn_key, date_key, event_timestamp_enrich, original_timestamp_enrich, msg_unique_id_enrich, base_file_name, path, line_number, file_id, processed_timestamp, ltz_event_timestamp_enrich, parameter_2, parameter_3, parameter_4, parameter_5, parameter_6, parameter_7, parameter_8, parameter_9, parameter_10, tbl_dt
FROM "mtn_ba_refs"."flare_8"."cis_cdr_20251107_20251108"
WHERE 1 = 0;

-- 4.2 Insert data from view into S3 table
INSERT INTO "mtn-s3"."flare_8"."cis_cdr_cst"
SELECT msisdn, beneficiary_msisdn, consumer_msisdn, dt, transaction_date_time, channel_name, short_code, keyword, product_id, product_name, product_type, product_subtype, renewal_adhoc, action, activation_time, expiry_time, grace_period, offer_id, cug_id, f3pp_transactionid, request_id, correlation_id, charging_amount, charging_node, transaction_charges, f3pp_chargedamount, auto_renewal_consent, provisioning_type, status, failure_reason, notification_sent, ipaddress, current_sc, new_sc, agent_id, user_id, alternate_number, imei_number, faf_id, faf_number, mifi_msisdn, source_action, goody_bag, response_time, product_flag, carte_prod_list, transfer_volume, voucher_code, gds_company_name, parameter_1, file_name, file_offset, kamanja_loaded_date, file_mod_date, msisdn_key, date_key, event_timestamp_enrich, original_timestamp_enrich, msg_unique_id_enrich, base_file_name, path, line_number, file_id, processed_timestamp, ltz_event_timestamp_enrich, parameter_2, parameter_3, parameter_4, parameter_5, parameter_6, parameter_7, parameter_8, parameter_9, parameter_10, tbl_dt
FROM "mtn_ba_refs"."flare_8"."cis_cdr_20251107_20251108";

-- 4.3 Partition handling (to be implemented)
-- TODO: implement partitioning on "mtn-s3"."flare_8"."cis_cdr_cst" for tbl_dt BETWEEN 20251107 AND 20251108


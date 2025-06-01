--
-- YSQL database dump
--

-- Dumped from database version 15.12-YB-2.27.0.0-b0
-- Dumped by ysql_dump version 15.12-YB-2.27.0.0-b0

SET yb_binary_restore = true;
SET yb_ignore_pg_class_oids = false;
SET yb_ignore_relfilenode_ids = false;
SET yb_non_ddl_txn_for_sys_tables_allowed = true;
SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

-- Set variable use_tablespaces (if not already set)
\if :{?use_tablespaces}
\else
\set use_tablespaces true
\endif

-- Set variable use_roles (if not already set)
\if :{?use_roles}
\else
\set use_roles true
\endif

-- YB: disable auto analyze to avoid conflicts with catalog changes
DO $$
BEGIN
IF EXISTS (SELECT 1 FROM pg_settings WHERE name = 'yb_disable_auto_analyze') THEN
EXECUTE format('ALTER DATABASE %I SET yb_disable_auto_analyze TO on', current_database());
END IF;
END $$;

--
-- Name: profile_2_failed; Type: PROFILE; Schema: -; Owner: -
--

CREATE PROFILE profile_2_failed LIMIT
  FAILED_LOGIN_ATTEMPTS 2;


--
-- Name: profile_3_failed; Type: PROFILE; Schema: -; Owner: -
--

CREATE PROFILE profile_3_failed LIMIT
  FAILED_LOGIN_ATTEMPTS 3;


--
-- Name: 16390; Type: ROLE PROFILE DATA; Schema: -; Owner: -
--

ALTER ROLE test_user WITH PROFILE profile_3_failed;
UPDATE pg_catalog.pg_yb_role_profile
SET rolprfstatus = 'l',
    rolprffailedloginattempts = 4,
    rolprflockeduntil = ''
WHERE rolprfrole = 16387 AND rolprfprofile = 16385;


--
-- Name: 16391; Type: ROLE PROFILE DATA; Schema: -; Owner: -
--

ALTER ROLE test_user2 WITH PROFILE profile_3_failed;
UPDATE pg_catalog.pg_yb_role_profile
SET rolprfstatus = 'o',
    rolprffailedloginattempts = 0,
    rolprflockeduntil = ''
WHERE rolprfrole = 16388 AND rolprfprofile = 16385;


--
-- Name: 16392; Type: ROLE PROFILE DATA; Schema: -; Owner: -
--

ALTER ROLE test_user3 WITH PROFILE profile_2_failed;
UPDATE pg_catalog.pg_yb_role_profile
SET rolprfstatus = 'o',
    rolprffailedloginattempts = 1,
    rolprflockeduntil = ''
WHERE rolprfrole = 16389 AND rolprfprofile = 16386;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

\if :use_roles
REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;
\endif


--
-- Name: FUNCTION pg_stat_statements_reset(userid oid, dbid oid, queryid bigint); Type: ACL; Schema: pg_catalog; Owner: postgres
--

\if :use_roles
SELECT pg_catalog.binary_upgrade_set_record_init_privs(true);
REVOKE ALL ON FUNCTION pg_catalog.pg_stat_statements_reset(userid oid, dbid oid, queryid bigint) FROM PUBLIC;
SELECT pg_catalog.binary_upgrade_set_record_init_privs(false);
\endif


--
-- Name: TABLE pg_stat_statements; Type: ACL; Schema: pg_catalog; Owner: postgres
--

\if :use_roles
SELECT pg_catalog.binary_upgrade_set_record_init_privs(true);
GRANT SELECT ON TABLE pg_catalog.pg_stat_statements TO PUBLIC;
SELECT pg_catalog.binary_upgrade_set_record_init_privs(false);
\endif


--
-- Name: TABLE pg_stat_statements_info; Type: ACL; Schema: pg_catalog; Owner: postgres
--

\if :use_roles
SELECT pg_catalog.binary_upgrade_set_record_init_privs(true);
GRANT SELECT ON TABLE pg_catalog.pg_stat_statements_info TO PUBLIC;
SELECT pg_catalog.binary_upgrade_set_record_init_privs(false);
\endif


-- YB: re-enable auto analyze after all catalog changes
DO $$
BEGIN
IF EXISTS (SELECT 1 FROM pg_settings WHERE name = 'yb_disable_auto_analyze') THEN
EXECUTE format('ALTER DATABASE %I SET yb_disable_auto_analyze TO off', current_database());
END IF;
END $$;

--
-- YSQL database dump complete
--


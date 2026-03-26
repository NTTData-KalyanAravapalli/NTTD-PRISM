-- PRISM Master Installer v2.0.0
-- Run: Edit config.sql first, then execute this file

EXECUTE IMMEDIATE FROM 'config.sql';
USE ROLE ACCOUNTADMIN;
USE WAREHOUSE IDENTIFIER($PRISM_WAREHOUSE);

EXECUTE IMMEDIATE FROM '01_prerequisites.sql';
EXECUTE IMMEDIATE FROM '02_databases.sql';
EXECUTE IMMEDIATE FROM '03_tables.sql';
EXECUTE IMMEDIATE FROM '04_seed_data.sql';
EXECUTE IMMEDIATE FROM '05_views.sql';
EXECUTE IMMEDIATE FROM '06_procedures.sql';
EXECUTE IMMEDIATE FROM '07_governance.sql';
EXECUTE IMMEDIATE FROM '08_streamlit.sql';
EXECUTE IMMEDIATE FROM '09_tasks.sql';
EXECUTE IMMEDIATE FROM '10_post_install.sql';

SELECT 'PRISM v' || $PRISM_VERSION || ' installed!' AS STATUS;

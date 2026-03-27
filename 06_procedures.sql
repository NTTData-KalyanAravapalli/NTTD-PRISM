-- ============================================================
-- PRISM Deployment - Step 6: Stored Procedures
-- Auto-generated from live installation
-- ============================================================

USE ROLE PRISM_APP_ROLE;
USE SCHEMA PRISM_SECURITY.ACCESS_CONTROL;

-- SP_VALIDATE_IDENTIFIER
CREATE OR REPLACE PROCEDURE SP_VALIDATE_IDENTIFIER(P_VALUE VARCHAR)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import re
def run(session, p_value):
    if not p_value:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p_value))
';

-- SP_SYNC_PRIVILEGE_CATALOG
CREATE OR REPLACE PROCEDURE SP_SYNC_PRIVILEGE_CATALOG()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS '
BEGIN
    CALL EXPLAIN_GRANTABLE_PRIVILEGES();

    MERGE INTO PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG AS tgt
    USING (
        WITH raw AS (
            SELECT PARSE_JSON(EXPLAIN_GRANTABLE_PRIVILEGES) AS j
            FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))
        )
        SELECT
            f.value:singular::STRING AS OBJECT_TYPE,
            f.value:plural::STRING AS OBJECT_TYPE_PLURAL,
            f.value:parent::STRING AS PARENT_SCOPE,
            p.key::STRING AS PRIVILEGE,
            ARRAY_CONTAINS(''ALL''::VARIANT, p.value) AS SUPPORTS_ALL,
            ARRAY_CONTAINS(''FUTURE''::VARIANT, p.value) AS SUPPORTS_FUTURE,
            ARRAY_CONTAINS(''INHERITED''::VARIANT, p.value) AS SUPPORTS_INHERITED
        FROM raw,
            LATERAL FLATTEN(input => raw.j) AS f,
            LATERAL FLATTEN(input => f.value:privileges) AS p
        WHERE p.key::STRING != ''OWNERSHIP''
    ) AS src
    ON tgt.OBJECT_TYPE = src.OBJECT_TYPE
       AND tgt.PRIVILEGE = src.PRIVILEGE
       AND tgt.PARENT_SCOPE = src.PARENT_SCOPE
    WHEN MATCHED THEN UPDATE SET
        tgt.OBJECT_TYPE_PLURAL = src.OBJECT_TYPE_PLURAL,
        tgt.SUPPORTS_ALL = src.SUPPORTS_ALL,
        tgt.SUPPORTS_FUTURE = src.SUPPORTS_FUTURE,
        tgt.SUPPORTS_INHERITED = src.SUPPORTS_INHERITED,
        tgt.LAST_SYNCED_AT = CURRENT_TIMESTAMP(),
        tgt.SYNCED_BY = CURRENT_USER()
    WHEN NOT MATCHED THEN INSERT (
        OBJECT_TYPE, OBJECT_TYPE_PLURAL, PARENT_SCOPE, PRIVILEGE,
        SUPPORTS_ALL, SUPPORTS_FUTURE, SUPPORTS_INHERITED,
        LAST_SYNCED_AT, SYNCED_BY
    ) VALUES (
        src.OBJECT_TYPE, src.OBJECT_TYPE_PLURAL, src.PARENT_SCOPE, src.PRIVILEGE,
        src.SUPPORTS_ALL, src.SUPPORTS_FUTURE, src.SUPPORTS_INHERITED,
        CURRENT_TIMESTAMP(), CURRENT_USER()
    );

    LET row_count INTEGER := (SELECT COUNT(*) FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG);
    RETURN ''Sync complete. Catalog now contains '' || :row_count || '' privilege entries.'';
END;
';

-- SP_DATABASE_CONTROLLER
CREATE OR REPLACE PROCEDURE SP_DATABASE_CONTROLLER(P_ENV VARCHAR, P_DB_CSV VARCHAR DEFAULT '', P_CLONE_DB VARCHAR DEFAULT '', P_FUNCTION_NAME VARCHAR DEFAULT '', P_ROLE_TYPE VARCHAR DEFAULT '', P_TARGET_DB_NAME_NO_PREFIX VARCHAR DEFAULT '', P_DB_ROLE_SUFFIX_TO_MAP VARCHAR DEFAULT '', P_SCHEMA_CSV VARCHAR DEFAULT '')
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  ID INTEGER;
  RES RESULTSET;
  MESSAGE STRING;
  INVOKED_BY STRING := CURRENT_USER();
BEGIN
  SELECT PRISM_OPERATIONS.LOGS.SEQ_AUDIT_LOG.NEXTVAL INTO :ID;

  -- If only ENV is provided (no DB, no function), set up environment roles
  IF (:P_DB_CSV = '''' AND :P_FUNCTION_NAME = '''') THEN
    CALL SP_SETUP_ENVIRONMENT(:P_ENV);
    RETURN ''Environment roles created for '' || :P_ENV;
  END IF;

  IF (:P_DB_CSV <> '''') THEN
    CALL SP_MANAGE_DATABASE_PERMISSIONS(:ID, :P_ENV, :P_DB_CSV, :P_CLONE_DB);
    IF (:P_SCHEMA_CSV <> '''') THEN
      CALL SP_MANAGE_SCHEMA_PERMISSIONS(:ID, :P_ENV, :P_DB_CSV, :P_SCHEMA_CSV);
    END IF;
  END IF;
  IF (:P_FUNCTION_NAME <> '''') THEN
    CALL SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER(
      :P_ENV,
      :P_FUNCTION_NAME,
      :P_ROLE_TYPE,
      :P_TARGET_DB_NAME_NO_PREFIX,
      :P_DB_ROLE_SUFFIX_TO_MAP,
      ''''
    );
  END IF;
  RETURN ''Completed successfully'';
END;
';

-- SP_SETUP_ENVIRONMENT
CREATE OR REPLACE PROCEDURE SP_SETUP_ENVIRONMENT(P_ENV VARCHAR)
RETURNS TABLE (ROLE_NAME VARCHAR, PARENT_ROLE VARCHAR, STATUS VARCHAR, MESSAGE VARCHAR)
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'def run(session, p_env):
    q = chr(39)
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]

    env_exists = session.sql(
        "SELECT COUNT(*) FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENTS WHERE ENVIRONMENT_NAME = " + q + p_env + q
    ).collect()[0][0]
    if env_exists == 0:
        return session.create_dataframe([("", "", "ERROR", "Environment " + p_env + " not found in ENVIRONMENTS table")],
            schema=["ROLE_NAME", "PARENT_ROLE", "STATUS", "MESSAGE"])

    audit_id = session.sql("SELECT PRISM_OPERATIONS.LOGS.SEQ_AUDIT_LOG.NEXTVAL").collect()[0][0]

    role_templates = session.sql(
        "SELECT ROLE_TEMPLATE, PARENT_SYSTEM_ROLE, DESCRIPTION, HIERARCHY_ORDER "
        "FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA "
        "WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
    ).collect()

    results = []

    created_roles = {}
    for tmpl in role_templates:
        template = tmpl[0]
        parent_template = tmpl[1]
        desc = tmpl[2]

        role_name = template.replace("<ENV>", p_env)
        parent_role = parent_template.replace("<ENV>", p_env)
        created_roles[template] = role_name

        try:
            session.sql("CREATE ROLE IF NOT EXISTS " + role_name).collect()
            safe_desc = desc.replace(q, q+q)
            try:
                session.sql("ALTER ROLE " + role_name + " SET COMMENT = " + q + safe_desc + q).collect()
            except:
                pass
            session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(audit_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + "CREATE_ENV_ROLE" + q + ", " + q + role_name + q + ", " + q + "CREATE ROLE IF NOT EXISTS " + role_name + q + ", " + q + "SUCCESS" + q + ", " + q + q + ")").collect()
            results.append((role_name, parent_role, "CREATED", "Role created successfully"))
        except Exception as e:
            results.append((role_name, parent_role, "ERROR", str(e)[:200]))
            continue

        try:
            session.sql("GRANT ROLE " + role_name + " TO ROLE " + parent_role).collect()
            session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(audit_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + "GRANT_ENV_ROLE_TO_PARENT" + q + ", " + q + role_name + q + ", " + q + "GRANT ROLE " + role_name + " TO ROLE " + parent_role + q + ", " + q + "SUCCESS" + q + ", " + q + q + ")").collect()
            results.append((role_name, parent_role, "GRANTED", "Granted to " + parent_role))
        except Exception as e:
            results.append((role_name, parent_role, "GRANT_ERROR", str(e)[:200]))

    sysadmin_role = None
    useradmin_role = None
    for tmpl in role_templates:
        rn = tmpl[0].replace("<ENV>", p_env)
        if "SYSADMIN" in tmpl[0] and tmpl[1] == "SYSADMIN":
            sysadmin_role = rn
        if "USERADMIN" in tmpl[0] and tmpl[1] == "USERADMIN":
            useradmin_role = rn

    if sysadmin_role:
        try:
            session.sql("GRANT CREATE DATABASE ON ACCOUNT TO ROLE " + sysadmin_role).collect()
            results.append((sysadmin_role, "", "PRIVILEGE", "Granted CREATE DATABASE"))
        except:
            pass

    if useradmin_role:
        try:
            session.sql("GRANT CREATE ROLE ON ACCOUNT TO ROLE " + useradmin_role).collect()
            results.append((useradmin_role, "", "PRIVILEGE", "Granted CREATE ROLE"))
        except:
            pass

    return session.create_dataframe(results, schema=["ROLE_NAME", "PARENT_ROLE", "STATUS", "MESSAGE"])
';

-- SP_CREATE_DB_ROLE
CREATE OR REPLACE PROCEDURE SP_CREATE_DB_ROLE(P_ID NUMBER(38,0), P_ROLE_NAME VARCHAR, P_DB_NAME VARCHAR, P_OWNER_ROLE VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  SUCCESS BOOLEAN DEFAULT TRUE;
  V_LINE STRING;
BEGIN
  EXECUTE IMMEDIATE ''CREATE OR REPLACE DATABASE ROLE '' || :P_DB_NAME || ''.'' || :P_ROLE_NAME;
  INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''CREATE_ROLE'', :P_ROLE_NAME,
    ''CREATE OR REPLACE DATABASE ROLE '' || :P_DB_NAME || ''.'' || :P_ROLE_NAME, ''SUCCESS'', '''');
  EXCEPTION WHEN OTHER THEN
    SUCCESS := FALSE;
    V_LINE := SQLCODE || '': '' || SQLERRM;
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''CREATE_DATABASE_ROLE'', :P_ROLE_NAME,
      ''CREATE OR REPLACE DATABASE ROLE '' || :P_DB_NAME || ''.'' || :P_ROLE_NAME, ''ERROR'', :V_LINE);
  RETURN :SUCCESS;
END;
';

-- SP_CREATE_ROLE_AND_SET_OWNERSHIP
CREATE OR REPLACE PROCEDURE SP_CREATE_ROLE_AND_SET_OWNERSHIP(P_ID NUMBER(38,0), P_ROLE_NAME VARCHAR, P_OWNER_ROLE VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  SUCCESS BOOLEAN DEFAULT TRUE;
  V_LINE STRING;
BEGIN
  EXECUTE IMMEDIATE ''CREATE ROLE IF NOT EXISTS "'' || :P_ROLE_NAME || ''"'';
  INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''CREATE_ROLE'', :P_ROLE_NAME,
    ''CREATE ROLE IF NOT EXISTS "'' || :P_ROLE_NAME || ''"'', ''SUCCESS'', '''');

  IF (:P_OWNER_ROLE IS NOT NULL) THEN
    BEGIN
      EXECUTE IMMEDIATE ''GRANT OWNERSHIP ON ROLE '' || :P_ROLE_NAME || '' TO ROLE '' || :P_OWNER_ROLE || '' REVOKE CURRENT GRANTS'';
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_ROLE_OWNER'', :P_ROLE_NAME,
        ''GRANT OWNERSHIP ON ROLE '' || :P_ROLE_NAME || '' TO ROLE '' || :P_OWNER_ROLE || '' REVOKE CURRENT GRANTS'', ''SUCCESS'', '''');
    EXCEPTION WHEN OTHER THEN
      V_LINE := SQLCODE || '': '' || SQLERRM;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_ROLE_OWNER'', :P_ROLE_NAME,
        ''GRANT OWNERSHIP ON ROLE '' || :P_ROLE_NAME || '' TO ROLE '' || :P_OWNER_ROLE, ''ERROR'', :V_LINE);
    END;
  END IF;
  RETURN :SUCCESS;
  EXCEPTION WHEN OTHER THEN
    V_LINE := SQLCODE || '': '' || SQLERRM;
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''CREATE_ROLE'', :P_ROLE_NAME, ''CREATE ROLE'', ''ERROR'', :V_LINE);
    RETURN FALSE;
END;
';

-- SP_APPLY_PRIVILEGES
CREATE OR REPLACE PROCEDURE SP_APPLY_PRIVILEGES(P_ID NUMBER(38,0), P_TARGET_ROLE VARCHAR, P_DB_NAME VARCHAR, P_ACCESS_CODE VARCHAR, P_USER VARCHAR, P_GRANT_TARGET VARCHAR DEFAULT 'DATABASE', P_SCHEMA_NAME VARCHAR DEFAULT null)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_target_role, p_db_name, p_access_code, p_user, p_grant_target, p_schema_name):
    q = chr(39)
    fq_role = p_db_name + "." + p_target_role
    is_schema = p_grant_target == "SCHEMA"
    scope_obj = p_db_name + "." + p_schema_name if is_schema and p_schema_name else p_db_name
    event_type = "GRANT_SCHEMA_PRIVILEGE" if is_schema else "GRANT_PRIVILEGE"

    rows = session.sql(
        "SELECT pp.OBJECT_TYPE, c.OBJECT_TYPE_PLURAL, pp.PRIVILEGE "
        "FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILE_PRIVILEGES pp "
        "JOIN PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG c "
        "ON pp.OBJECT_TYPE = c.OBJECT_TYPE AND c.PARENT_SCOPE IN (" + q + "SCHEMA" + q + "," + q + "DATABASE" + q + ") "
        "WHERE pp.ACCESS_CODE = " + q + str(p_access_code) + q + " "
        "AND pp.GRANT_TARGET = " + q + str(p_grant_target) + q + " "
        "AND pp.IS_ACTIVE = TRUE "
        "AND pp.PRIVILEGE != " + q + "OWNERSHIP" + q + " "
        "GROUP BY pp.OBJECT_TYPE, c.OBJECT_TYPE_PLURAL, pp.PRIVILEGE"
    ).collect()

    stmts = []
    if is_schema and p_schema_name:
        stmts.append("GRANT USAGE ON SCHEMA " + scope_obj + " TO DATABASE ROLE " + fq_role)

    for r in rows:
        ot, otp, pr = r[0], r[1], r[2]
        if ot == "DATABASE":
            stmts.append("GRANT " + pr + " ON DATABASE " + p_db_name + " TO DATABASE ROLE " + fq_role)
        elif ot == "SCHEMA":
            if is_schema:
                stmts.append("GRANT " + pr + " ON SCHEMA " + scope_obj + " TO DATABASE ROLE " + fq_role)
            else:
                stmts.append("GRANT " + pr + " ON ALL SCHEMAS IN DATABASE " + p_db_name + " TO DATABASE ROLE " + fq_role)
                stmts.append("GRANT " + pr + " ON FUTURE SCHEMAS IN DATABASE " + p_db_name + " TO DATABASE ROLE " + fq_role)
        else:
            scope_clause = "IN SCHEMA " + scope_obj if is_schema else "IN DATABASE " + p_db_name
            stmts.append("GRANT " + pr + " ON ALL " + otp + " " + scope_clause + " TO DATABASE ROLE " + fq_role)
            stmts.append("GRANT " + pr + " ON FUTURE " + otp + " " + scope_clause + " TO DATABASE ROLE " + fq_role)

    ok = 0
    def do_grant(s):
        try:
            session.sql(s).collect()
            return ("SUCCESS", s, "")
        except Exception as e:
            return ("ERROR", s, str(e)[:200])

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(do_grant, s) for s in stmts]
        for f in concurrent.futures.as_completed(futs):
            st, sql_s, msg = f.result()
            if st == "SUCCESS":
                ok += 1
            try:
                ss = sql_s.replace(q, q+q)
                mm = msg.replace(q, q+q)
                session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + str(p_user) + q + ", " + q + event_type + q + ", " + q + str(p_target_role) + q + ", " + q + ss + q + ", " + q + st + q + ", " + q + mm + q + ")").collect()
            except:
                pass
    return ok > 0
';

-- SP_SET_DB_ROLE_OWNERSHIP
CREATE OR REPLACE PROCEDURE SP_SET_DB_ROLE_OWNERSHIP(P_ID NUMBER(38,0), P_ROLE_NAME VARCHAR, P_DB_NAME VARCHAR, P_ENV VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  SUCCESS BOOLEAN DEFAULT TRUE;
  V_LINE STRING;
  V_GRANT_SQL STRING;
  V_DB_ROLE_OWNER STRING;
  V_DB_OWNER STRING;
  CUR_HIERARCHY CURSOR FOR
    SELECT child.ROLE_SUFFIX AS CHILD_SUFFIX, parent.ROLE_SUFFIX AS PARENT_SUFFIX
    FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES child
    JOIN PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES parent
      ON child.HIERARCHY_PARENT = parent.ACCESS_CODE
    WHERE child.IS_ACTIVE = TRUE AND parent.IS_ACTIVE = TRUE
    ORDER BY child.HIERARCHY_ORDER;
  CUR_PROFILES CURSOR FOR
    SELECT ROLE_SUFFIX
    FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES
    WHERE IS_ACTIVE = TRUE
    ORDER BY HIERARCHY_ORDER;
  V_SUFFIX STRING;
  V_CHILD STRING;
  V_PARENT STRING;
BEGIN
  -- Get ownership roles from ENVIRONMENT_ROLE_METADATA
  V_DB_ROLE_OWNER := (
    SELECT REPLACE(ROLE_TEMPLATE, ''<ENV>'', :P_ENV)
    FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA
    WHERE OWNS_DB_ROLES = TRUE AND IS_ACTIVE = TRUE
    LIMIT 1
  );
  V_DB_OWNER := (
    SELECT REPLACE(ROLE_TEMPLATE, ''<ENV>'', :P_ENV)
    FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA
    WHERE OWNS_DATABASES = TRUE AND IS_ACTIVE = TRUE
    LIMIT 1
  );

  IF (:V_DB_ROLE_OWNER IS NULL) THEN
    V_DB_ROLE_OWNER := :P_ENV || ''_USERADMIN'';
  END IF;
  IF (:V_DB_OWNER IS NULL) THEN
    V_DB_OWNER := :P_ENV || ''_SYSADMIN'';
  END IF;

  -- Set ownership of each database role
  OPEN CUR_PROFILES;
  FOR rec IN CUR_PROFILES DO
    V_SUFFIX := rec.ROLE_SUFFIX;
    BEGIN
      V_GRANT_SQL := ''GRANT OWNERSHIP ON DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_SUFFIX || '' TO ROLE '' || :V_DB_ROLE_OWNER || '' COPY CURRENT GRANTS'';
      EXECUTE IMMEDIATE :V_GRANT_SQL;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''SET_DB_ROLE_OWNERSHIP'', :V_SUFFIX, :V_GRANT_SQL, ''SUCCESS'', '''');
    EXCEPTION WHEN OTHER THEN
      V_LINE := SQLCODE || '': '' || SQLERRM;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''SET_DB_ROLE_OWNERSHIP'', :V_SUFFIX, :V_GRANT_SQL, ''ERROR'', :V_LINE);
    END;
  END FOR;

  -- Set hierarchy: grant child roles to parent roles (metadata-driven)
  OPEN CUR_HIERARCHY;
  FOR rec IN CUR_HIERARCHY DO
    V_CHILD := rec.CHILD_SUFFIX;
    V_PARENT := rec.PARENT_SUFFIX;
    BEGIN
      V_GRANT_SQL := ''GRANT DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_CHILD || '' TO DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_PARENT;
      EXECUTE IMMEDIATE :V_GRANT_SQL;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''SET_DB_ROLE_HIERARCHY'', :V_CHILD, :V_GRANT_SQL, ''SUCCESS'', '''');
    EXCEPTION WHEN OTHER THEN
      V_LINE := SQLCODE || '': '' || SQLERRM;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''SET_DB_ROLE_HIERARCHY'', :V_CHILD, :V_GRANT_SQL, ''ERROR'', :V_LINE);
    END;
  END FOR;

  -- Grant top-level OWN_AR to <ENV>_SYSADMIN (from metadata)
  BEGIN
    V_GRANT_SQL := ''GRANT DATABASE ROLE '' || :P_DB_NAME || ''.'' || (
      SELECT ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES
      WHERE HIERARCHY_PARENT IS NULL AND IS_SYSTEM_ONLY = TRUE AND IS_ACTIVE = TRUE
      ORDER BY HIERARCHY_ORDER LIMIT 1
    ) || '' TO ROLE '' || :V_DB_OWNER;
    EXECUTE IMMEDIATE :V_GRANT_SQL;
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_TOP_ROLE_TO_SYSADMIN'', :P_DB_NAME, :V_GRANT_SQL, ''SUCCESS'', '''');
  EXCEPTION WHEN OTHER THEN
    V_LINE := SQLCODE || '': '' || SQLERRM;
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_TOP_ROLE_TO_SYSADMIN'', :P_DB_NAME, :V_GRANT_SQL, ''ERROR'', :V_LINE);
  END;

  RETURN :SUCCESS;
END;
';

-- SP_SET_SCHEMA_ROLE_HIERARCHY
CREATE OR REPLACE PROCEDURE SP_SET_SCHEMA_ROLE_HIERARCHY(P_ID NUMBER(38,0), P_DB_NAME VARCHAR, P_SCHEMA_NAME VARCHAR, P_ENV VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  SUCCESS BOOLEAN DEFAULT TRUE;
  V_LINE STRING;
  V_SCHEMA_ROLE_PREFIX STRING;
  CUR_HIERARCHY CURSOR FOR
    SELECT child.ROLE_SUFFIX AS CHILD_SUFFIX, parent.ROLE_SUFFIX AS PARENT_SUFFIX
    FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES child
    JOIN PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES parent
      ON child.HIERARCHY_PARENT = parent.ACCESS_CODE
    WHERE child.IS_ACTIVE = TRUE AND parent.IS_ACTIVE = TRUE
    ORDER BY child.HIERARCHY_ORDER;
  V_CHILD STRING;
  V_PARENT STRING;
  V_GRANT_SQL STRING;
BEGIN
  V_SCHEMA_ROLE_PREFIX := :P_SCHEMA_NAME || ''_'';

  OPEN CUR_HIERARCHY;
  FOR rec IN CUR_HIERARCHY DO
    V_CHILD := rec.CHILD_SUFFIX;
    V_PARENT := rec.PARENT_SUFFIX;
    V_GRANT_SQL := ''GRANT DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_SCHEMA_ROLE_PREFIX || :V_CHILD ||
                   '' TO DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_SCHEMA_ROLE_PREFIX || :V_PARENT;
    BEGIN
      EXECUTE IMMEDIATE :V_GRANT_SQL;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_SCHEMA_ROLE_HIERARCHY'',
        :V_SCHEMA_ROLE_PREFIX || :V_CHILD, :V_GRANT_SQL, ''SUCCESS'', '''');
    EXCEPTION WHEN OTHER THEN
      SUCCESS := FALSE;
      V_LINE := SQLCODE || '': '' || SQLERRM;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_SCHEMA_ROLE_HIERARCHY'',
        :V_SCHEMA_ROLE_PREFIX || :V_CHILD, :V_GRANT_SQL, ''ERROR'', :V_LINE);
    END;
  END FOR;
  RETURN :SUCCESS;
END;
';

-- SP_GRANT_SCHEMA_ROLES_TO_DB_ROLES
CREATE OR REPLACE PROCEDURE SP_GRANT_SCHEMA_ROLES_TO_DB_ROLES(P_ID NUMBER(38,0), P_DB_NAME VARCHAR, P_SCHEMA_NAME VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
  SUCCESS BOOLEAN DEFAULT TRUE;
  V_LINE STRING;
  V_SCHEMA_ROLE_PREFIX STRING;
  V_GRANT_SQL STRING;
  CUR_AC CURSOR FOR
    SELECT ACCESS_CODE, ROLE_SUFFIX
    FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES
    WHERE IS_ACTIVE = TRUE
    ORDER BY HIERARCHY_ORDER;
  V_AC_CODE STRING;
  V_SUFFIX STRING;
BEGIN
  V_SCHEMA_ROLE_PREFIX := :P_SCHEMA_NAME || ''_'';

  OPEN CUR_AC;
  FOR rec IN CUR_AC DO
    V_SUFFIX := rec.ROLE_SUFFIX;
    V_GRANT_SQL := ''GRANT DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_SCHEMA_ROLE_PREFIX || :V_SUFFIX ||
                   '' TO DATABASE ROLE '' || :P_DB_NAME || ''.'' || :V_SUFFIX;
    BEGIN
      EXECUTE IMMEDIATE :V_GRANT_SQL;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_SCHEMA_ROLE_TO_DB_ROLE'',
        :V_SCHEMA_ROLE_PREFIX || :V_SUFFIX, :V_GRANT_SQL, ''SUCCESS'', '''');
    EXCEPTION WHEN OTHER THEN
      SUCCESS := FALSE;
      V_LINE := SQLCODE || '': '' || SQLERRM;
      INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_ID, CURRENT_TIMESTAMP(), :P_USER, ''GRANT_SCHEMA_ROLE_TO_DB_ROLE'',
        :V_SCHEMA_ROLE_PREFIX || :V_SUFFIX, :V_GRANT_SQL, ''ERROR'', :V_LINE);
    END;
  END FOR;
  RETURN :SUCCESS;
END;
';

-- SP_GRANT_USAGE_ON_DATABASE_AND_SCHEMAS
CREATE OR REPLACE PROCEDURE SP_GRANT_USAGE_ON_DATABASE_AND_SCHEMAS(P_ID NUMBER(38,0), P_DB_NAME VARCHAR, P_ROLE VARCHAR, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_db_name, p_role, p_user):
    q = chr(39)
    profiles = session.sql(
        "SELECT ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES "
        "WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
    ).collect()
    stmts = []
    for p in profiles:
        suf = p[0]
        dr = p_db_name + "." + suf
        stmts.append("GRANT USAGE ON DATABASE " + p_db_name + " TO DATABASE ROLE " + dr)
        stmts.append("GRANT USAGE ON ALL SCHEMAS IN DATABASE " + p_db_name + " TO DATABASE ROLE " + dr)
        stmts.append("GRANT USAGE ON FUTURE SCHEMAS IN DATABASE " + p_db_name + " TO DATABASE ROLE " + dr)
    ok = 0
    def do_grant(s):
        try:
            session.sql(s).collect()
            return ("SUCCESS", s, "")
        except Exception as e:
            return ("ERROR", s, str(e)[:200])
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(do_grant, s) for s in stmts]
        for f in concurrent.futures.as_completed(futs):
            st, sql_s, msg = f.result()
            if st == "SUCCESS":
                ok += 1
            try:
                ss = sql_s.replace(q, q+q)
                mm = msg.replace(q, q+q)
                session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + str(p_user) + q + ", " + q + "GRANT_USAGE" + q + ", " + q + p_db_name + q + ", " + q + ss + q + ", " + q + st + q + ", " + q + mm + q + ")").collect()
            except:
                pass
    return ok > 0
';

-- SP_GRANT_FUTURE_OBJECT_OWNERSHIP_IN_DATABASE
CREATE OR REPLACE PROCEDURE SP_GRANT_FUTURE_OBJECT_OWNERSHIP_IN_DATABASE(P_ID NUMBER(38,0), P_DB_NAME VARCHAR, P_OWNER_ROLE VARCHAR, P_OBJ_TYPES ARRAY, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_db_name, p_owner_role, p_obj_types, p_user):
    q = chr(39)
    rows = session.sql(
        "SELECT DISTINCT OBJECT_TYPE, OBJECT_TYPE_PLURAL "
        "FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG "
        "WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_FUTURE = TRUE "
        "ORDER BY OBJECT_TYPE"
    ).collect()
    stmts = []
    for r in rows:
        otp = r[1]
        stmts.append("GRANT OWNERSHIP ON FUTURE " + otp + " IN DATABASE " + p_db_name + " TO ROLE " + p_owner_role + " COPY CURRENT GRANTS")
    ok = 0
    def do_grant(s):
        try:
            session.sql(s).collect()
            return ("SUCCESS", s, "")
        except Exception as e:
            return ("ERROR", s, str(e)[:200])
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(do_grant, s) for s in stmts]
        for f in concurrent.futures.as_completed(futs):
            st, sql_s, msg = f.result()
            if st == "SUCCESS":
                ok += 1
            try:
                ss = sql_s.replace(q, q+q)
                mm = msg.replace(q, q+q)
                session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + str(p_user) + q + ", " + q + "GRANT_FUTURE_OWNERSHIP" + q + ", " + q + p_db_name + q + ", " + q + ss + q + ", " + q + st + q + ", " + q + mm + q + ")").collect()
            except:
                pass
    return ok > 0
';

-- SP_GRANT_OBJECT_OWNERSHIP_IN_SCHEMAS
CREATE OR REPLACE PROCEDURE SP_GRANT_OBJECT_OWNERSHIP_IN_SCHEMAS(P_ID NUMBER(38,0), P_DB_NAME VARCHAR, P_OWNER_ROLE VARCHAR, P_OBJ_TYPES ARRAY, P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_db_name, p_owner_role, p_obj_types, p_user):
    q = chr(39)
    schemas = session.sql(
        "SELECT SCHEMA_NAME FROM " + p_db_name + ".INFORMATION_SCHEMA.SCHEMATA "
        "WHERE SCHEMA_NAME NOT IN (" + q + "PUBLIC" + q + "," + q + "INFORMATION_SCHEMA" + q + ")"
    ).collect()
    obj_types = session.sql(
        "SELECT DISTINCT OBJECT_TYPE, OBJECT_TYPE_PLURAL "
        "FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG "
        "WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_ALL = TRUE "
        "ORDER BY OBJECT_TYPE"
    ).collect()
    stmts = []
    for s in schemas:
        sname = s[0]
        for o in obj_types:
            otp = o[1]
            stmts.append("GRANT OWNERSHIP ON ALL " + otp + " IN SCHEMA " + p_db_name + "." + sname + " TO ROLE " + p_owner_role + " COPY CURRENT GRANTS")
    ok = 0
    def do_grant(stmt):
        try:
            session.sql(stmt).collect()
            return ("SUCCESS", stmt, "")
        except Exception as e:
            return ("ERROR", stmt, str(e)[:200])
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(do_grant, s) for s in stmts]
        for f in concurrent.futures.as_completed(futs):
            st, sql_s, msg = f.result()
            if st == "SUCCESS":
                ok += 1
            try:
                ss = sql_s.replace(q, q+q)
                mm = msg.replace(q, q+q)
                session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + str(p_user) + q + ", " + q + "GRANT_OBJ_OWNERSHIP" + q + ", " + q + p_db_name + q + ", " + q + ss + q + ", " + q + st + q + ", " + q + mm + q + ")").collect()
            except:
                pass
    return ok > 0
';

-- SP_MANAGE_DATABASE_PERMISSIONS
CREATE OR REPLACE PROCEDURE SP_MANAGE_DATABASE_PERMISSIONS(P_ID NUMBER(38,0) DEFAULT '', P_ENV VARCHAR DEFAULT '', P_DB_CSV VARCHAR DEFAULT '', P_CLONE_DB VARCHAR DEFAULT '')
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_env, p_db_csv, p_clone_db):
    q = chr(39)
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    clone_str = "" if not p_clone_db else " CLONE " + p_clone_db

    app_role = "PRISM_APP_ROLE"
    try:
        ar = session.sql("SELECT SETTING_VALUE FROM PRISM_SECURITY.ACCESS_CONTROL.PRISM_SETTINGS WHERE SETTING_KEY = " + q + "APP_ROLE" + q).collect()
        if ar:
            app_role = ar[0][0]
    except: pass

    profiles = session.sql(
        "SELECT ACCESS_CODE, ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
    ).collect()

    env_roles = session.sql(
        "SELECT ROLE_TEMPLATE, OWNS_DATABASES, OWNS_SCHEMAS, OWNS_DB_ROLES "
        "FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA WHERE IS_ACTIVE = TRUE"
    ).collect()

    db_owner = p_env + "_SYSADMIN"
    db_role_owner = p_env + "_USERADMIN"
    for er in env_roles:
        rn = er[0].replace("<ENV>", p_env)
        if er[1]: db_owner = rn
        if er[3]: db_role_owner = rn

    dbs = [d.strip() for d in p_db_csv.split(",") if d.strip()]
    for db_name in dbs:
        full_db = p_env + "_" + db_name
        exists = session.sql("SELECT COUNT(*) FROM INFORMATION_SCHEMA.DATABASES WHERE DATABASE_NAME = " + q + full_db + q).collect()[0][0]
        if exists == 0:
            try:
                session.sql("CREATE DATABASE " + full_db + clone_str).collect()
                log(session, p_id, user, "CREATE_DATABASE", full_db, "CREATE DATABASE " + full_db + clone_str, "SUCCESS", "")
            except Exception as e:
                log(session, p_id, user, "CREATE_DATABASE", full_db, "CREATE DATABASE " + full_db, "ERROR", str(e)[:200])

        for prof in profiles:
            session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_CREATE_DB_ROLE", p_id, prof[1], full_db, db_role_owner, user)

        def apply_privs(ac, suf):
            session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_APPLY_PRIVILEGES", p_id, suf, full_db, ac, user, "DATABASE", "")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(apply_privs, p[0], p[1]) for p in profiles]
            concurrent.futures.wait(futs)

        session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_SET_DB_ROLE_OWNERSHIP", p_id, full_db, full_db, p_env, user)
        session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_GRANT_USAGE_ON_DATABASE_AND_SCHEMAS", p_id, full_db, "", user)
        try:
            obj_types = session.sql("SELECT DISTINCT OBJECT_TYPE_PLURAL FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_FUTURE = TRUE").collect()
            for ot in obj_types:
                try:
                    session.sql("GRANT OWNERSHIP ON FUTURE " + ot[0] + " IN DATABASE " + full_db + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                except: pass
        except: pass

        try:
            session.sql("GRANT OWNERSHIP ON DATABASE " + full_db + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
        except: pass
        try:
            session.sql("GRANT USAGE ON DATABASE " + full_db + " TO ROLE " + app_role).collect()
            session.sql("GRANT CREATE SCHEMA ON DATABASE " + full_db + " TO ROLE " + app_role).collect()
            session.sql("GRANT MONITOR ON DATABASE " + full_db + " TO ROLE " + app_role).collect()
        except: pass
        try:
            session.sql("GRANT OWNERSHIP ON ALL SCHEMAS IN DATABASE " + full_db + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
        except: pass
        try:
            session.sql("GRANT USAGE ON ALL SCHEMAS IN DATABASE " + full_db + " TO ROLE " + app_role).collect()
        except: pass

        try:
            schemas_list = session.sql("SELECT SCHEMA_NAME FROM " + full_db + ".INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN (" + q + "PUBLIC" + q + "," + q + "INFORMATION_SCHEMA" + q + ")").collect()
            obj_types2 = session.sql("SELECT DISTINCT OBJECT_TYPE, OBJECT_TYPE_PLURAL FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_ALL = TRUE").collect()
            for s in schemas_list:
                for o in obj_types2:
                    try:
                        session.sql("GRANT OWNERSHIP ON ALL " + o[1] + " IN SCHEMA " + full_db + "." + s[0] + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                    except: pass
        except: pass

    return "Database permissions managed successfully"

def log(session, p_id, user, event_type, obj, sql_cmd, status, msg):
    q = chr(39)
    try:
        s = sql_cmd.replace(q, q+q)[:500]
        m = msg.replace(q, q+q)[:200]
        session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + event_type + q + ", " + q + obj + q + ", " + q + s + q + ", " + q + status + q + ", " + q + m + q + ")").collect()
    except: pass
';

-- SP_MANAGE_SCHEMA_PERMISSIONS
CREATE OR REPLACE PROCEDURE SP_MANAGE_SCHEMA_PERMISSIONS(P_ID NUMBER(38,0), P_ENV VARCHAR, P_DB_NAME VARCHAR, P_SCHEMA_CSV VARCHAR)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import concurrent.futures
def run(session, p_id, p_env, p_db_name, p_schema_csv):
    q = chr(39)
    full_db = p_env + "_" + p_db_name
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]

    app_role = "PRISM_APP_ROLE"
    try:
        ar = session.sql("SELECT SETTING_VALUE FROM PRISM_SECURITY.ACCESS_CONTROL.PRISM_SETTINGS WHERE SETTING_KEY = " + q + "APP_ROLE" + q).collect()
        if ar:
            app_role = ar[0][0]
    except: pass

    db_exists = session.sql("SELECT COUNT(*) FROM INFORMATION_SCHEMA.DATABASES WHERE DATABASE_NAME = " + q + full_db + q).collect()[0][0]
    if db_exists == 0:
        return "Database " + full_db + " does not exist"

    profiles = session.sql(
        "SELECT ACCESS_CODE, ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
    ).collect()

    env_roles = session.sql(
        "SELECT ROLE_TEMPLATE, OWNS_SCHEMAS, OWNS_DB_ROLES FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA WHERE IS_ACTIVE = TRUE"
    ).collect()
    schema_owner = p_env + "_SYSADMIN"
    db_role_owner = p_env + "_USERADMIN"
    for er in env_roles:
        rn = er[0].replace("<ENV>", p_env)
        if er[1]: schema_owner = rn
        if er[2]: db_role_owner = rn

    obj_types = session.sql(
        "SELECT DISTINCT OBJECT_TYPE_PLURAL FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_FUTURE = TRUE ORDER BY 1"
    ).collect()

    schemas = [s.strip() for s in p_schema_csv.split(",") if s.strip()]
    for schema_name in schemas:
        fsp = full_db + "." + schema_name
        try:
            session.sql("CREATE SCHEMA IF NOT EXISTS " + fsp).collect()
            log(session, p_id, user, "CREATE_SCHEMA", fsp, "CREATE SCHEMA IF NOT EXISTS " + fsp, "SUCCESS", "")
        except Exception as e:
            log(session, p_id, user, "CREATE_SCHEMA", fsp, "CREATE SCHEMA", "ERROR", str(e)[:200])

        for prof in profiles:
            srn = schema_name + "_" + prof[1]
            try:
                session.sql("CREATE DATABASE ROLE IF NOT EXISTS " + full_db + "." + srn).collect()
            except: pass

        def apply_profile(ac_code, suffix, sname):
            srn = sname + "_" + suffix
            session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_APPLY_PRIVILEGES", p_id, srn, full_db, ac_code, user, "SCHEMA", sname)
            try:
                session.sql("GRANT OWNERSHIP ON DATABASE ROLE " + full_db + "." + srn + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
            except: pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(apply_profile, p[0], p[1], schema_name) for p in profiles]
            concurrent.futures.wait(futs)

        session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_SET_SCHEMA_ROLE_HIERARCHY", p_id, full_db, schema_name, p_env, user)
        session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_GRANT_SCHEMA_ROLES_TO_DB_ROLES", p_id, full_db, schema_name, user)

        try:
            session.sql("GRANT OWNERSHIP ON SCHEMA " + fsp + " TO ROLE " + schema_owner + " COPY CURRENT GRANTS").collect()
        except: pass
        try:
            session.sql("GRANT USAGE ON SCHEMA " + fsp + " TO ROLE " + app_role).collect()
        except: pass

        def set_future_own(otp):
            try:
                session.sql("GRANT OWNERSHIP ON FUTURE " + otp + " IN SCHEMA " + fsp + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
            except: pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(set_future_own, ot[0]) for ot in obj_types]
            concurrent.futures.wait(futs)

    try:
        schemas_list = session.sql("SELECT SCHEMA_NAME FROM " + full_db + ".INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN (" + q + "PUBLIC" + q + "," + q + "INFORMATION_SCHEMA" + q + ")").collect()
        obj_types2 = session.sql("SELECT DISTINCT OBJECT_TYPE, OBJECT_TYPE_PLURAL FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_ALL = TRUE").collect()
        for s in schemas_list:
            for o in obj_types2:
                try:
                    session.sql("GRANT OWNERSHIP ON ALL " + o[1] + " IN SCHEMA " + full_db + "." + s[0] + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                except: pass
    except: pass
    return "Schema permissions managed successfully"

def log(session, p_id, user, event_type, obj, sql_cmd, status, msg):
    q = chr(39)
    try:
        s = sql_cmd.replace(q, q+q)[:500]
        m = msg.replace(q, q+q)[:200]
        session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + event_type + q + ", " + q + obj + q + ", " + q + s + q + ", " + q + status + q + ", " + q + m + q + ")").collect()
    except: pass
';

-- SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER
CREATE OR REPLACE PROCEDURE SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER(P_ENV_NAME VARCHAR, P_FUNCTION_NAME VARCHAR, P_ROLE_TYPE VARCHAR, P_TARGET_DB_NAME_NO_PREFIX VARCHAR, P_DB_ROLE_SUFFIX_TO_MAP VARCHAR, P_FUNCTION_NAME_PREFIX VARCHAR DEFAULT '')
RETURNS TABLE (OPERATION_STATUS VARCHAR, DETAIL_MESSAGE VARCHAR, LOG_REFERENCE_ID NUMBER(38,0))
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
    V_AUDIT_EVENT_ID INTEGER;
    V_INVOKED_BY STRING := CURRENT_USER();
    V_SP_CALL_RESULT STRING;
    V_CONSTRUCTED_FULL_DB_NAME STRING;    -- e.g., DEV_SALES_DATA
    V_QUALIFIED_DB_ROLE_TO_MAP STRING; -- e.g., DEV_SALES_DATA.RO_AR
    V_OWNER_ACCOUNT_ROLE STRING;         -- e.g., DEV_USERADMIN
    V_OPERATION_STATUS STRING;
    V_DETAIL_MESSAGE STRING;
    V_LINE  STRING;

    -- For returning results
    RES RESULTSET;

BEGIN
    SELECT PRISM_OPERATIONS.LOGS.seq_audit_log.NEXTVAL INTO :V_AUDIT_EVENT_ID;

    -- Log initiation of this controller action in PRISM_OPERATIONS.LOGS.AUDIT_LOG
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG (AUDIT_ID, EXECUTED_AT, INVOKED_BY, EVENT_TYPE, TARGET_OBJECT, SQL_COMMAND, STATUS, MESSAGE)
    VALUES (:V_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :V_INVOKED_BY, ''CONTROLLER_INIT_MAP_FT_ROLE'', :P_FUNCTION_NAME,
            ''Params: ENV='' || :P_ENV_NAME || '', FUNC_PREFIX='' || :P_FUNCTION_NAME_PREFIX || '', FUNC='' || :P_FUNCTION_NAME || '', TYPE='' || :P_ROLE_TYPE || '', DBNAME='' || :P_TARGET_DB_NAME_NO_PREFIX || '', DBROLE_SUFFIX='' || :P_DB_ROLE_SUFFIX_TO_MAP,
            ''INFO'', ''Controller SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER started.'');

    -- Validate Environment
    IF ((SELECT COUNT(*) FROM ENVIRONMENTS WHERE ENVIRONMENT_NAME = :P_ENV_NAME) = 0) THEN
        V_OPERATION_STATUS := ''ERROR'';
        V_DETAIL_MESSAGE := ''Invalid environment specified: '' || :P_ENV_NAME;
        INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG (AUDIT_ID, EXECUTED_AT, INVOKED_BY, EVENT_TYPE, TARGET_OBJECT, SQL_COMMAND, STATUS, MESSAGE)
        VALUES (:V_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :V_INVOKED_BY, ''CONTROLLER_ERROR_MAP_FT_ROLE'', :P_FUNCTION_NAME, ''Environment Validation'', ''ERROR'', V_DETAIL_MESSAGE);
        RES := (SELECT :V_OPERATION_STATUS AS OPERATION_STATUS, :V_DETAIL_MESSAGE AS DETAIL_MESSAGE, :V_AUDIT_EVENT_ID AS LOG_REFERENCE_ID);
        RETURN TABLE(RES);
    END IF;

    -- Construct the full database name (e.g., DEV_SALES_DATA)
    V_CONSTRUCTED_FULL_DB_NAME := P_ENV_NAME || ''_'' || P_TARGET_DB_NAME_NO_PREFIX;

    -- Construct the fully qualified database role name to map
    -- Database roles are named <DB_NAME>.<ROLE_SUFFIX_FROM_METADATA> as per SP_APPLY_METADATA_PRIVILEGES_TO_ROLE
    -- Example: DEV_SALES_DATA.RO_AR
    V_QUALIFIED_DB_ROLE_TO_MAP := ''"'' || V_CONSTRUCTED_FULL_DB_NAME || ''"."'' || P_DB_ROLE_SUFFIX_TO_MAP || ''"'';

    -- Determine the owner account role for the new functional/technical role (e.g., DEV_USERADMIN)
    -- This role should have been created by SP_MANAGE_DATABASE_PERMISSIONs
    V_OWNER_ACCOUNT_ROLE := P_ENV_NAME || ''_USERADMIN'';

    -- Call the stored procedure to create and map the role
    CALL SP_CREATE_MAPPED_ROLE(
        :V_AUDIT_EVENT_ID,
        :P_ENV_NAME,
        :P_FUNCTION_NAME,
        :P_ROLE_TYPE,
        :V_QUALIFIED_DB_ROLE_TO_MAP,
        :V_OWNER_ACCOUNT_ROLE,
        :V_INVOKED_BY,
        :P_FUNCTION_NAME_PREFIX
    );
    -- Get the return value (status message) from SP_CREATE_MAPPED_ROLE
    V_SP_CALL_RESULT := (SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())));


    IF (V_SP_CALL_RESULT LIKE ''SUCCESS:%'') THEN
        V_OPERATION_STATUS := ''SUCCESS'';
    ELSE
        V_OPERATION_STATUS := ''ERROR'';
    END IF;
    V_DETAIL_MESSAGE := V_SP_CALL_RESULT;

    -- Log completion in PRISM_OPERATIONS.LOGS.AUDIT_LOG
    INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG (AUDIT_ID, EXECUTED_AT, INVOKED_BY, EVENT_TYPE, TARGET_OBJECT, SQL_COMMAND, STATUS, MESSAGE)
    VALUES (:V_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :V_INVOKED_BY, ''CONTROLLER_END_MAP_FT_ROLE'', :P_FUNCTION_NAME_PREFIX||:P_FUNCTION_NAME,
            ''Called SP_CREATE_MAPPED_ROLE'', :V_OPERATION_STATUS, :V_DETAIL_MESSAGE);

    RES := (SELECT :V_OPERATION_STATUS AS OPERATION_STATUS, :V_DETAIL_MESSAGE AS DETAIL_MESSAGE, :V_AUDIT_EVENT_ID AS LOG_REFERENCE_ID);
    RETURN TABLE(RES);

EXCEPTION
    WHEN OTHER THEN
        V_LINE := SQLCODE || '': '' || SQLERRM;
        V_OPERATION_STATUS := ''ERROR'';
        V_DETAIL_MESSAGE := ''Critical error in SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER: '' || :V_LINE;
       
        -- Ensure AUDIT_EVENT_ID is available, if error happened before its assignment, it might be null.
        -- For robustness, one might initialize V_AUDIT_EVENT_ID to a default or handle null if it can occur before SELECT PRISM_OPERATIONS.LOGS.seq_audit_log.NEXTVAL.
        -- However, in this structure, its assigned early.
        INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG (AUDIT_ID, EXECUTED_AT, INVOKED_BY, EVENT_TYPE, TARGET_OBJECT, SQL_COMMAND, STATUS, MESSAGE)
        VALUES (COALESCE(:V_AUDIT_EVENT_ID, -1), CURRENT_TIMESTAMP(), :V_INVOKED_BY, ''CONTROLLER_CRITICAL_ERROR'', :P_FUNCTION_NAME_PREFIX||:P_FUNCTION_NAME,
                ''Controller execution failed'', ''ERROR'', :V_DETAIL_MESSAGE);
       
        RES := (SELECT :V_OPERATION_STATUS AS OPERATION_STATUS, :V_DETAIL_MESSAGE AS DETAIL_MESSAGE, COALESCE(:V_AUDIT_EVENT_ID, -1) AS LOG_REFERENCE_ID);
        RETURN TABLE(RES);
END;
';

-- SP_CREATE_MAPPED_ROLE
CREATE OR REPLACE PROCEDURE SP_CREATE_MAPPED_ROLE(P_AUDIT_EVENT_ID NUMBER(38,0), P_ENV_NAME VARCHAR, P_FUNCTION_NAME VARCHAR, P_ROLE_TYPE VARCHAR, P_DATABASE_ROLE_TO_MAP VARCHAR, P_OWNER_ACCOUNT_ROLE VARCHAR, P_INVOKED_BY VARCHAR, P_FUNCTION_NAME_PREFIX VARCHAR DEFAULT '')
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS '
DECLARE
    V_PREFIX_PATTERN STRING;
    V_SUFFIX STRING;
    V_CONSTRUCTED_ROLE_NAME STRING;
    V_SQL_CREATE_ROLE STRING;       -- To store the generated SQL for logging
    V_SQL_GRANT_DB_ROLE STRING;     -- To store the generated SQL for logging
    V_LOG_STATUS STRING DEFAULT ''SUCCESS'';
    V_LOG_MESSAGE STRING DEFAULT ''Role created and mapped successfully.'';
    V_LINE STRING;                  -- For capturing SQLCODE and SQLERRM
    SUCCESS BOOLEAN DEFAULT TRUE;   -- Internal success tracking for multi-step PRISM_OPERATIONS
BEGIN
    -- Validate P_ROLE_TYPE parameter
    IF (:P_ROLE_TYPE NOT IN (''Functional'', ''Technical'')) THEN
        V_LOG_STATUS := ''ERROR'';
        V_LOG_MESSAGE := ''Invalid P_ROLE_TYPE: "'' || :P_ROLE_TYPE || ''". Must be ''''Functional'''' or ''''Technical''''.'';
        INSERT INTO PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG (AUDIT_EVENT_ID, INVOKED_BY, ENVIRONMENT_NAME, CREATED_ROLE_NAME, CREATED_ROLE_TYPE, MAPPED_DATABASE_ROLE, PARENT_ACCOUNT_ROLE, SQL_COMMAND_CREATE_ROLE, SQL_COMMAND_GRANT_DB_ROLE, STATUS, MESSAGE)
        VALUES (:P_AUDIT_EVENT_ID, :P_INVOKED_BY, :P_ENV_NAME, NULL, :P_ROLE_TYPE, :P_DATABASE_ROLE_TO_MAP, :P_OWNER_ACCOUNT_ROLE, NULL, NULL, :V_LOG_STATUS, :V_LOG_MESSAGE);
        RETURN ''ERROR: '' || :V_LOG_MESSAGE;
    END IF;

    -- Fetch role naming metadata from FUNCTIONAL_TECHNICAL_ROLE_METADATA
    SELECT
        REGEXP_REPLACE(ROLE_NAME_PATTERN, ''[^_]+$'', '''') AS prefix_part,
        ''_'' || REGEXP_SUBSTR(ROLE_NAME_PATTERN, ''[^_]+$'') AS suffix_part
    INTO :V_PREFIX_PATTERN, :V_SUFFIX
    FROM FUNCTIONAL_TECHNICAL_ROLE_METADATA
    WHERE ROLE_TYPE = :P_ROLE_TYPE
    LIMIT 1;

    IF (:V_PREFIX_PATTERN IS NULL OR :V_SUFFIX IS NULL) THEN
        V_LOG_STATUS := ''ERROR'';
        V_LOG_MESSAGE := ''Metadata not found in FUNCTIONAL_TECHNICAL_ROLE_METADATA for FUNCTION_NAME='' || :P_FUNCTION_NAME || '' and ROLE_TYPE='' || :P_ROLE_TYPE || ''.'';
        INSERT INTO PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG (AUDIT_EVENT_ID, INVOKED_BY, ENVIRONMENT_NAME, CREATED_ROLE_NAME, CREATED_ROLE_TYPE, MAPPED_DATABASE_ROLE, PARENT_ACCOUNT_ROLE, SQL_COMMAND_CREATE_ROLE, SQL_COMMAND_GRANT_DB_ROLE, STATUS, MESSAGE)
        VALUES (:P_AUDIT_EVENT_ID, :P_INVOKED_BY, :P_ENV_NAME, NULL, :P_ROLE_TYPE, :P_DATABASE_ROLE_TO_MAP, :P_OWNER_ACCOUNT_ROLE, NULL, NULL, :V_LOG_STATUS, :V_LOG_MESSAGE);
        RETURN ''ERROR: '' || :V_LOG_MESSAGE;
    END IF;
IF (:P_FUNCTION_NAME_PREFIX ='''')
THEN
P_FUNCTION_NAME :=:P_FUNCTION_NAME;
ELSE P_FUNCTION_NAME := (:P_FUNCTION_NAME_PREFIX||''_''||:P_FUNCTION_NAME) ;
END IF;
    -- Construct the full functional/technical role name
    -- Replace <ENV> placeholder in prefix_pattern with actual P_ENV_NAME
    V_CONSTRUCTED_ROLE_NAME := REPLACE(:V_PREFIX_PATTERN, ''<ENV>'', :P_ENV_NAME) || :P_FUNCTION_NAME || :V_SUFFIX;
    V_SQL_CREATE_ROLE := ''CREATE ROLE IF NOT EXISTS "'' || :V_CONSTRUCTED_ROLE_NAME || ''"''; -- For logging

    -- Step 1: Create the account-level functional/technical role and set its ownership
    -- This uses your existing helper SP_CREATE_ROLE_AND_SET_OWNERSHIP, which also logs to PRISM_OPERATIONS.LOGS.AUDIT_LOG
    BEGIN
        CALL SP_CREATE_ROLE_AND_SET_OWNERSHIP(:P_AUDIT_EVENT_ID, :V_CONSTRUCTED_ROLE_NAME, :P_OWNER_ACCOUNT_ROLE, :P_INVOKED_BY);
        -- SP_CREATE_ROLE_AND_SET_OWNERSHIP returns BOOLEAN, but we handle errors via EXCEPTION here for overall status.
        -- It also inserts into PRISM_OPERATIONS.LOGS.AUDIT_LOG.
    EXCEPTION
        WHEN OTHER THEN
            SUCCESS := FALSE;
            V_LINE := SQLCODE || '': '' || SQLERRM;
            V_LOG_STATUS := ''ERROR'';
            V_LOG_MESSAGE := ''Failed during SP_CREATE_ROLE_AND_SET_OWNERSHIP for role '' || :V_CONSTRUCTED_ROLE_NAME || ''. Owner: '' || :P_OWNER_ACCOUNT_ROLE || ''. Details: '' || :V_LINE;
            -- PRISM_OPERATIONS.LOGS.AUDIT_LOG entry for this specific failure might be duplicated if SP_CREATE_ROLE_AND_SET_OWNERSHIP also logs its own failure.
            -- However, this ensures a log if the CALL itself fails before the SP''s internal logging.
            INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :P_INVOKED_BY, ''CALL_SP_CREATE_ROLE_OWNERSHIP_FAIL'', :V_CONSTRUCTED_ROLE_NAME,
                ''CALL SP_CREATE_ROLE_AND_SET_OWNERSHIP('' || :P_AUDIT_EVENT_ID || '', '' || :V_CONSTRUCTED_ROLE_NAME || '', '' || :P_OWNER_ACCOUNT_ROLE || '', '' || :P_INVOKED_BY || '')'', ''ERROR'', :V_LINE);
    END;

    IF (NOT SUCCESS) THEN
        -- Log failure to PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG and return
        INSERT INTO PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG (AUDIT_EVENT_ID, INVOKED_BY, ENVIRONMENT_NAME, CREATED_ROLE_NAME, CREATED_ROLE_TYPE, MAPPED_DATABASE_ROLE, PARENT_ACCOUNT_ROLE, SQL_COMMAND_CREATE_ROLE, SQL_COMMAND_GRANT_DB_ROLE, STATUS, MESSAGE)
        VALUES (:P_AUDIT_EVENT_ID, :P_INVOKED_BY, :P_ENV_NAME, :V_CONSTRUCTED_ROLE_NAME, :P_ROLE_TYPE, :P_DATABASE_ROLE_TO_MAP, :P_OWNER_ACCOUNT_ROLE, :V_SQL_CREATE_ROLE, NULL, :V_LOG_STATUS, :V_LOG_MESSAGE);
        RETURN ''ERROR: '' || :V_LOG_MESSAGE;
    END IF;

    -- Step 2: Grant the specified database role to the newly created functional/technical role
    V_SQL_GRANT_DB_ROLE := ''GRANT DATABASE ROLE '' || :P_DATABASE_ROLE_TO_MAP || '' TO ROLE "'' || :V_CONSTRUCTED_ROLE_NAME || ''"'';

    BEGIN
        EXECUTE IMMEDIATE :V_SQL_GRANT_DB_ROLE;
        INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :P_INVOKED_BY, ''GRANT_DB_ROLE_TO_MAPPED_ROLE'', :V_CONSTRUCTED_ROLE_NAME,
            :V_SQL_GRANT_DB_ROLE, ''SUCCESS'', ''Granted database role '' || :P_DATABASE_ROLE_TO_MAP || '' to account role '' || :V_CONSTRUCTED_ROLE_NAME);
    EXCEPTION
        WHEN OTHER THEN
            SUCCESS := FALSE;
            V_LINE := SQLCODE || '': '' || SQLERRM;
            V_LOG_STATUS := ''ERROR'';
            V_LOG_MESSAGE := ''Failed to grant database role '' || :P_DATABASE_ROLE_TO_MAP || '' to '' || :V_CONSTRUCTED_ROLE_NAME || ''. Details: '' || :V_LINE;
            INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :P_INVOKED_BY, ''GRANT_DB_ROLE_TO_MAPPED_ROLE_FAIL'', :V_CONSTRUCTED_ROLE_NAME,
                :V_SQL_GRANT_DB_ROLE, ''ERROR'', :V_LINE);
    END;

     IF (:P_FUNCTION_NAME IN (''AI'',''PROTOTYPING'')) THEN
    -- Step 3: Grant the CORTEX database role to the LAB role
    V_SQL_GRANT_DB_ROLE := ''GRANT DATABASE ROLE SNOWFLAKE.CORTEX_USER TO ROLE "'' || :V_CONSTRUCTED_ROLE_NAME || ''"'';
    

    BEGIN
        EXECUTE IMMEDIATE :V_SQL_GRANT_DB_ROLE;
        INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :P_INVOKED_BY, ''GRANT_CORTEX_ROLE_TO_MAPPED_ROLE'', :V_CONSTRUCTED_ROLE_NAME,
            :V_SQL_GRANT_DB_ROLE, ''SUCCESS'', ''Granted database role SNOWFLAKE.CORTEX_USER to account role '' || :V_CONSTRUCTED_ROLE_NAME);
    EXCEPTION
        WHEN OTHER THEN
            SUCCESS := FALSE;
            V_LINE := SQLCODE || '': '' || SQLERRM;
            V_LOG_STATUS := ''ERROR'';
            V_LOG_MESSAGE := ''Failed to grant database role SNOWFLAKE.CORTEX_USER to '' || :V_CONSTRUCTED_ROLE_NAME || ''. Details: '' || :V_LINE;
            INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (:P_AUDIT_EVENT_ID, CURRENT_TIMESTAMP(), :P_INVOKED_BY, ''GRANT_CORTEX_ROLE_TO_MAPPED_ROLE_FAIL'', :V_CONSTRUCTED_ROLE_NAME,
                :V_SQL_GRANT_DB_ROLE, ''ERROR'', :V_LINE);
    END;
    END IF;
    -- Log the overall operation outcome to PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG
    INSERT INTO PRISM_OPERATIONS.LOGS.ROLE_HIERARCHY_LOG (
        AUDIT_EVENT_ID, INVOKED_BY, ENVIRONMENT_NAME,
        CREATED_ROLE_NAME, CREATED_ROLE_TYPE, MAPPED_DATABASE_ROLE, PARENT_ACCOUNT_ROLE,
        SQL_COMMAND_CREATE_ROLE, SQL_COMMAND_GRANT_DB_ROLE,
        STATUS, MESSAGE
    ) VALUES (
        :P_AUDIT_EVENT_ID, :P_INVOKED_BY, :P_ENV_NAME,
        :V_CONSTRUCTED_ROLE_NAME, :P_ROLE_TYPE, :P_DATABASE_ROLE_TO_MAP, :P_OWNER_ACCOUNT_ROLE,
        :V_SQL_CREATE_ROLE, :V_SQL_GRANT_DB_ROLE,
        :V_LOG_STATUS, :V_LOG_MESSAGE -- This reflects the final status of both steps
    );

    IF (NOT SUCCESS) THEN
        RETURN ''ERROR: '' || :V_LOG_MESSAGE;
    END IF;

    RETURN ''SUCCESS: Role '' || :V_CONSTRUCTED_ROLE_NAME || '' processed. Status: '' || :V_LOG_STATUS || ''. Mapped to '' || :P_DATABASE_ROLE_TO_MAP || ''.'';
END;
';

-- SP_CLONE_DATABASE
CREATE OR REPLACE PROCEDURE SP_CLONE_DATABASE(P_SOURCE_DB VARCHAR, P_TARGET_DB VARCHAR, P_TARGET_ENV VARCHAR, P_CLONE_MODE VARCHAR DEFAULT 'CURRENT', P_TIMESTAMP VARCHAR DEFAULT null, P_OFFSET_SECONDS NUMBER(38,0) DEFAULT null, P_STATEMENT_ID VARCHAR DEFAULT null, P_IGNORE_INSUFFICIENT_RETENTION BOOLEAN DEFAULT FALSE, P_IGNORE_HYBRID_TABLES BOOLEAN DEFAULT FALSE, P_INCLUDE_INTERNAL_STAGES BOOLEAN DEFAULT FALSE, P_SETUP_RBAC BOOLEAN DEFAULT TRUE, P_REATTACH_ROLES BOOLEAN DEFAULT TRUE)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json
import concurrent.futures
from datetime import datetime

def run(session, p_source_db, p_target_db, p_target_env, p_clone_mode, p_timestamp, p_offset_seconds, p_statement_id, p_ignore_insufficient_retention, p_ignore_hybrid_tables, p_include_internal_stages, p_setup_rbac, p_reattach_roles):
    q = chr(39)
    result = {"status": "SUCCESS", "steps": [], "warnings": [], "role_mappings_captured": 0, "role_mappings_restored": 0}
    app_role = "PRISM_APP_ROLE"
    try:
        ar = session.sql("SELECT SETTING_VALUE FROM PRISM_SECURITY.ACCESS_CONTROL.PRISM_SETTINGS WHERE SETTING_KEY = " + q + "APP_ROLE" + q).collect()
        if ar:
            app_role = ar[0][0]
    except: pass
    import re
    id_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for param_name, param_val in [("source", p_source_db), ("target", p_target_db), ("env", p_target_env)]:
        if not id_pattern.match(str(param_val)):
            result["status"] = "FAILED"
            result["warnings"].append("Invalid identifier: " + param_name + " = " + str(param_val))
            return result
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_OPERATIONS.LOGS.SEQ_AUDIT_LOG.NEXTVAL").collect()[0][0]

    # ============================================================
    # STEP 1: Capture account role -> database role mappings BEFORE clone
    # ============================================================
    role_mappings = []
    if p_reattach_roles:
        try:
            mappings = session.sql(
                "SELECT NAME AS DB_ROLE, GRANTEE_NAME AS ACCOUNT_ROLE "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = " + q + "DATABASE_ROLE" + q + " "
                "AND PRIVILEGE = " + q + "USAGE" + q + " "
                "AND GRANTED_TO = " + q + "ROLE" + q + " "
                "AND TABLE_CATALOG = " + q + p_source_db + q + " "
                "AND DELETED_ON IS NULL"
            ).collect()
            for m in mappings:
                role_mappings.append({"db_role": m[0], "account_role": m[1]})
            result["role_mappings_captured"] = len(role_mappings)
            result["steps"].append({"step": "CAPTURE_ROLE_MAPPINGS", "status": "SUCCESS", "detail": str(len(role_mappings)) + " account role -> database role mappings captured"})
            log(session, audit_id, user, "CLONE_CAPTURE_ROLES", p_source_db, "Captured " + str(len(role_mappings)) + " role mappings", "SUCCESS", "")
        except Exception as e:
            result["warnings"].append("Could not capture role mappings from ACCOUNT_USAGE (may have latency): " + str(e)[:200])
            try:
                live_mappings = session.sql("SHOW GRANTS OF DATABASE ROLE " + p_source_db + ".RO_AR").collect()
            except:
                pass

    # Also capture direct grants on the source database
    db_grants = []
    if p_reattach_roles:
        try:
            grants = session.sql("SHOW GRANTS ON DATABASE " + p_source_db).collect()
            for g in grants:
                priv = g[1]
                granted_to = g[4]
                grantee = g[5]
                if priv != "OWNERSHIP" and granted_to == "ROLE":
                    db_grants.append({"privilege": priv, "grantee": grantee})
            result["steps"].append({"step": "CAPTURE_DB_GRANTS", "status": "SUCCESS", "detail": str(len(db_grants)) + " database-level grants captured"})
        except Exception as e:
            result["warnings"].append("Could not capture database grants: " + str(e)[:200])

    # ============================================================
    # STEP 2: Build and execute the CLONE statement
    # ============================================================
    clone_sql = "CREATE DATABASE " + p_target_db + " CLONE " + p_source_db

    if p_clone_mode == "TIMESTAMP" and p_timestamp:
        clone_sql += " AT (TIMESTAMP => " + q + p_timestamp + q + "::TIMESTAMP_LTZ)"
    elif p_clone_mode == "OFFSET" and p_offset_seconds is not None:
        clone_sql += " AT (OFFSET => " + str(int(p_offset_seconds * -1)) + ")"
    elif p_clone_mode == "STATEMENT" and p_statement_id:
        clone_sql += " BEFORE (STATEMENT => " + q + p_statement_id + q + ")"

    if p_ignore_insufficient_retention:
        clone_sql += " IGNORE TABLES WITH INSUFFICIENT DATA RETENTION"
    if p_ignore_hybrid_tables:
        clone_sql += " IGNORE HYBRID TABLES"
    if p_include_internal_stages:
        clone_sql += " INCLUDE INTERNAL STAGES"

    try:
        session.sql(clone_sql).collect()
        result["steps"].append({"step": "CLONE_DATABASE", "status": "SUCCESS", "detail": clone_sql})
        log(session, audit_id, user, "CLONE_DATABASE", p_target_db, clone_sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "FAILED"
        result["steps"].append({"step": "CLONE_DATABASE", "status": "FAILED", "detail": str(e)[:500]})
        log(session, audit_id, user, "CLONE_DATABASE", p_target_db, clone_sql, "ERROR", str(e)[:200])
        return result

    # ============================================================
    # STEP 3: Transfer ownership per ENVIRONMENT_ROLE_METADATA
    # ============================================================
    if p_setup_rbac:
        try:
            env_roles = session.sql(
                "SELECT ROLE_TEMPLATE, OWNS_DATABASES, OWNS_SCHEMAS, OWNS_DB_ROLES "
                "FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA WHERE IS_ACTIVE = TRUE"
            ).collect()
            db_owner = p_target_env + "_SYSADMIN"
            db_role_owner = p_target_env + "_USERADMIN"
            for er in env_roles:
                rn = er[0].replace("<ENV>", p_target_env)
                if er[1]: db_owner = rn
                if er[3]: db_role_owner = rn

            try:
                session.sql("GRANT OWNERSHIP ON DATABASE " + p_target_db + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
                result["steps"].append({"step": "TRANSFER_DB_OWNERSHIP", "status": "SUCCESS", "detail": "To " + db_owner})
            except Exception as e:
                result["warnings"].append("DB ownership transfer: " + str(e)[:200])

            try:
                session.sql("GRANT USAGE ON DATABASE " + p_target_db + " TO ROLE " + app_role).collect()
                session.sql("GRANT CREATE SCHEMA ON DATABASE " + p_target_db + " TO ROLE " + app_role).collect()
                session.sql("GRANT MONITOR ON DATABASE " + p_target_db + " TO ROLE " + app_role).collect()
            except: pass

            try:
                session.sql("GRANT OWNERSHIP ON ALL SCHEMAS IN DATABASE " + p_target_db + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
                result["steps"].append({"step": "TRANSFER_SCHEMA_OWNERSHIP", "status": "SUCCESS", "detail": "To " + db_owner})
            except Exception as e:
                result["warnings"].append("Schema ownership transfer: " + str(e)[:200])

            try:
                session.sql("GRANT USAGE ON ALL SCHEMAS IN DATABASE " + p_target_db + " TO ROLE " + app_role).collect()
            except: pass

            profiles = session.sql(
                "SELECT ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
            ).collect()
            for prof in profiles:
                try:
                    session.sql("GRANT OWNERSHIP ON DATABASE ROLE " + p_target_db + "." + prof[0] + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                except:
                    pass

            schemas = session.sql(
                "SELECT SCHEMA_NAME FROM " + p_target_db + ".INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME NOT IN (" + q + "PUBLIC" + q + "," + q + "INFORMATION_SCHEMA" + q + ")"
            ).collect()
            for s in schemas:
                sname = s[0]
                for prof in profiles:
                    try:
                        session.sql("GRANT OWNERSHIP ON DATABASE ROLE " + p_target_db + "." + sname + "_" + prof[0] + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                    except:
                        pass
                try:
                    session.sql("GRANT OWNERSHIP ON SCHEMA " + p_target_db + "." + sname + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
                except:
                    pass

            result["steps"].append({"step": "TRANSFER_ALL_OWNERSHIP", "status": "SUCCESS", "detail": "DB roles to " + db_role_owner + ", DB/schemas to " + db_owner})
            log(session, audit_id, user, "CLONE_TRANSFER_OWNERSHIP", p_target_db, "Ownership transferred", "SUCCESS", "")
        except Exception as e:
            result["warnings"].append("Ownership setup: " + str(e)[:200])

    # ============================================================
    # STEP 4: Set up RBAC (privileges, hierarchy, future grants) on clone
    # ============================================================
    if p_setup_rbac:
        try:
            profiles = session.sql(
                "SELECT ACCESS_CODE, ROLE_SUFFIX FROM PRISM_SECURITY.ACCESS_CONTROL.ACCESS_PROFILES WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER"
            ).collect()

            def apply_privs(ac, suf):
                session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_APPLY_PRIVILEGES", audit_id, suf, p_target_db, ac, user, "DATABASE", "")

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                futs = [ex.submit(apply_privs, p[0], p[1]) for p in profiles]
                concurrent.futures.wait(futs)

            session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_SET_DB_ROLE_OWNERSHIP", audit_id, p_target_db, p_target_db, p_target_env, user)
            session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_GRANT_USAGE_ON_DATABASE_AND_SCHEMAS", audit_id, p_target_db, "", user)
            try:
                obj_types = session.sql("SELECT DISTINCT OBJECT_TYPE_PLURAL FROM PRISM_SECURITY.ACCESS_CONTROL.SNOWFLAKE_PRIVILEGE_CATALOG WHERE PARENT_SCOPE = " + q + "SCHEMA" + q + " AND SUPPORTS_FUTURE = TRUE").collect()
                for ot in obj_types:
                    try:
                        session.sql("GRANT OWNERSHIP ON FUTURE " + ot[0] + " IN DATABASE " + p_target_db + " TO ROLE " + db_role_owner + " COPY CURRENT GRANTS").collect()
                    except: pass
            except: pass

            for s in schemas:
                sname = s[0]
                for prof in profiles:
                    srn = sname + "_" + prof[1]
                    try:
                        session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_APPLY_PRIVILEGES", audit_id, srn, p_target_db, prof[0], user, "SCHEMA", sname)
                    except:
                        pass
                session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_SET_SCHEMA_ROLE_HIERARCHY", audit_id, p_target_db, sname, p_target_env, user)
                session.call("PRISM_SECURITY.ACCESS_CONTROL.SP_GRANT_SCHEMA_ROLES_TO_DB_ROLES", audit_id, p_target_db, sname, user)

            result["steps"].append({"step": "SETUP_RBAC", "status": "SUCCESS", "detail": "Privileges, hierarchy, and future grants configured"})
            log(session, audit_id, user, "CLONE_SETUP_RBAC", p_target_db, "RBAC setup complete", "SUCCESS", "")
        except Exception as e:
            result["warnings"].append("RBAC setup: " + str(e)[:200])

    # ============================================================
    # STEP 5: Reattach account roles to cloned database roles
    # ============================================================
    restored_count = 0
    if p_reattach_roles and role_mappings:
        for mapping in role_mappings:
            db_role = mapping["db_role"]
            account_role = mapping["account_role"]
            try:
                grant_sql = "GRANT DATABASE ROLE " + p_target_db + "." + db_role + " TO ROLE " + account_role
                session.sql(grant_sql).collect()
                restored_count += 1
                log(session, audit_id, user, "CLONE_REATTACH_ROLE", db_role, grant_sql, "SUCCESS", "")
            except Exception as e:
                result["warnings"].append("Reattach " + db_role + " -> " + account_role + ": " + str(e)[:100])
                log(session, audit_id, user, "CLONE_REATTACH_ROLE", db_role, "GRANT DB ROLE " + db_role + " TO " + account_role, "ERROR", str(e)[:200])

        result["role_mappings_restored"] = restored_count
        result["steps"].append({"step": "REATTACH_ROLES", "status": "SUCCESS", "detail": str(restored_count) + "/" + str(len(role_mappings)) + " role mappings restored"})

    # Also restore database-level grants
    if p_reattach_roles and db_grants:
        for g in db_grants:
            try:
                session.sql("GRANT " + g["privilege"] + " ON DATABASE " + p_target_db + " TO ROLE " + g["grantee"]).collect()
            except:
                pass

    log(session, audit_id, user, "CLONE_COMPLETE", p_target_db, json.dumps(result, default=str), "SUCCESS", "")
    return result

def log(session, p_id, user, event_type, obj, sql_cmd, status, msg):
    q = chr(39)
    try:
        s = sql_cmd.replace(q, q+q)[:500]
        m = msg.replace(q, q+q)[:200]
        session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + event_type + q + ", " + q + obj + q + ", " + q + s + q + ", " + q + status + q + ", " + q + m + q + ")").collect()
    except:
        pass
';

-- SP_CREATE_WAREHOUSE
CREATE OR REPLACE PROCEDURE SP_CREATE_WAREHOUSE(P_ENV VARCHAR, P_WAREHOUSE_TYPE VARCHAR, P_WAREHOUSE_SIZE VARCHAR, P_WAREHOUSE_CLASS VARCHAR DEFAULT 'STANDARD', P_CUSTOM_NAME VARCHAR DEFAULT null, P_AUTO_SUSPEND_SECS NUMBER(38,0) DEFAULT null, P_AUTO_RESUME BOOLEAN DEFAULT null, P_INITIALLY_SUSPENDED BOOLEAN DEFAULT null, P_MIN_CLUSTERS NUMBER(38,0) DEFAULT null, P_MAX_CLUSTERS NUMBER(38,0) DEFAULT null, P_SCALING_POLICY VARCHAR DEFAULT null, P_ENABLE_QUERY_ACCEL BOOLEAN DEFAULT null, P_QUERY_ACCEL_SCALE NUMBER(38,0) DEFAULT null, P_STATEMENT_TIMEOUT NUMBER(38,0) DEFAULT null, P_QUEUED_TIMEOUT NUMBER(38,0) DEFAULT null, P_MAX_CONCURRENCY NUMBER(38,0) DEFAULT null, P_RESOURCE_MONITOR VARCHAR DEFAULT null, P_COMMENT VARCHAR DEFAULT null, P_GRANT_TO_ROLES ARRAY DEFAULT null)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json

def run(session, p_env, p_wh_type, p_wh_size, p_wh_class, p_custom_name, p_auto_suspend, p_auto_resume, p_initially_suspended, p_min_clusters, p_max_clusters, p_scaling_policy, p_enable_qa, p_qa_scale, p_stmt_timeout, p_queued_timeout, p_max_concurrency, p_resource_monitor, p_comment, p_grant_roles):
    q = chr(39)
    result = {"status": "SUCCESS", "warehouse_name": "", "sql": "", "grants": [], "warnings": []}
    import re
    id_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
    for pn, pv in [("env", p_env), ("type", p_wh_type), ("size", p_wh_size)]:
        if not id_pattern.match(str(pv)):
            result["status"] = "FAILED"
            result["warnings"].append("Invalid identifier: " + pn)
            return result
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_OPERATIONS.LOGS.SEQ_AUDIT_LOG.NEXTVAL").collect()[0][0]

    meta = session.sql(
        "SELECT * FROM PRISM_SECURITY.ACCESS_CONTROL.WAREHOUSE_METADATA "
        "WHERE WAREHOUSE_TYPE = " + q + str(p_wh_type) + q + " "
        "AND WAREHOUSE_SIZE = " + q + str(p_wh_size) + q + " "
        "AND WAREHOUSE_CLASS = " + q + str(p_wh_class) + q + " "
        "AND IS_ACTIVE = TRUE LIMIT 1"
    ).collect()

    if not meta:
        result["status"] = "FAILED"
        result["warnings"].append("No matching warehouse metadata found for " + p_wh_type + "/" + p_wh_size + "/" + p_wh_class)
        return result

    m = meta[0]
    pattern = m["WAREHOUSE_NAME_PATTERN"]
    wh_name = pattern.replace("<ENV>", p_env).replace("<TYPE>", p_wh_type).replace("<SIZE>", p_wh_size)
    if p_custom_name:
        wh_name = wh_name.replace("<TYPE>", p_custom_name)
        if "<CUSTOM>" in wh_name:
            wh_name = wh_name.replace("<CUSTOM>", p_custom_name)

    auto_suspend = p_auto_suspend if p_auto_suspend is not None else m["DEFAULT_AUTO_SUSPEND_SECS"]
    auto_resume = p_auto_resume if p_auto_resume is not None else m["DEFAULT_AUTO_RESUME"]
    init_susp = p_initially_suspended if p_initially_suspended is not None else m["DEFAULT_INITIALLY_SUSPENDED"]
    min_cl = p_min_clusters if p_min_clusters is not None else m["DEFAULT_MIN_CLUSTER_COUNT"]
    max_cl = p_max_clusters if p_max_clusters is not None else m["DEFAULT_MAX_CLUSTER_COUNT"]
    scaling = p_scaling_policy if p_scaling_policy else m["DEFAULT_SCALING_POLICY"]
    enable_qa = p_enable_qa if p_enable_qa is not None else m["DEFAULT_ENABLE_QUERY_ACCELERATION"]
    qa_scale = p_qa_scale if p_qa_scale is not None else m["DEFAULT_QUERY_ACCEL_MAX_SCALE"]
    stmt_to = p_stmt_timeout if p_stmt_timeout is not None else m["DEFAULT_STATEMENT_TIMEOUT_SECS"]
    q_to = p_queued_timeout if p_queued_timeout is not None else m["DEFAULT_STMT_QUEUED_TIMEOUT_SECS"]
    max_conc = p_max_concurrency if p_max_concurrency is not None else m["DEFAULT_MAX_CONCURRENCY_LEVEL"]
    res_mon = p_resource_monitor if p_resource_monitor else (m["DEFAULT_RESOURCE_MONITOR"] if m["DEFAULT_RESOURCE_MONITOR"] else None)
    comment = p_comment if p_comment else (m["DEFAULT_COMMENT"] if m["DEFAULT_COMMENT"] else "")

    sql = "CREATE WAREHOUSE IF NOT EXISTS " + wh_name
    sql += " WITH WAREHOUSE_SIZE = " + q + str(p_wh_size) + q
    sql += " WAREHOUSE_TYPE = " + q + str(p_wh_class) + q
    sql += " AUTO_SUSPEND = " + str(int(auto_suspend))
    sql += " AUTO_RESUME = " + ("TRUE" if auto_resume else "FALSE")
    sql += " INITIALLY_SUSPENDED = " + ("TRUE" if init_susp else "FALSE")
    sql += " MIN_CLUSTER_COUNT = " + str(int(min_cl))
    sql += " MAX_CLUSTER_COUNT = " + str(int(max_cl))
    sql += " SCALING_POLICY = " + q + str(scaling) + q
    sql += " ENABLE_QUERY_ACCELERATION = " + ("TRUE" if enable_qa else "FALSE")

    if enable_qa:
        sql += " QUERY_ACCELERATION_MAX_SCALE_FACTOR = " + str(int(qa_scale))

    sql += " STATEMENT_TIMEOUT_IN_SECONDS = " + str(int(stmt_to))
    sql += " STATEMENT_QUEUED_TIMEOUT_IN_SECONDS = " + str(int(q_to))
    sql += " MAX_CONCURRENCY_LEVEL = " + str(int(max_conc))

    if res_mon:
        sql += " RESOURCE_MONITOR = " + q + str(res_mon) + q

    if comment:
        safe_comment = comment.replace(q, q+q)
        sql += " COMMENT = " + q + safe_comment + q

    result["warehouse_name"] = wh_name
    result["sql"] = sql

    try:
        session.sql(sql).collect()
        log(session, audit_id, user, "CREATE_WAREHOUSE", wh_name, sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "FAILED"
        result["warnings"].append("Create failed: " + str(e)[:300])
        log(session, audit_id, user, "CREATE_WAREHOUSE", wh_name, sql, "ERROR", str(e)[:200])
        return result

    if p_grant_roles:
        for role in p_grant_roles:
            try:
                grant_sql = "GRANT USAGE ON WAREHOUSE " + wh_name + " TO ROLE " + str(role)
                session.sql(grant_sql).collect()
                result["grants"].append({"role": str(role), "status": "SUCCESS"})
                log(session, audit_id, user, "GRANT_WAREHOUSE", wh_name + " TO " + str(role), grant_sql, "SUCCESS", "")

                operate_sql = "GRANT OPERATE ON WAREHOUSE " + wh_name + " TO ROLE " + str(role)
                session.sql(operate_sql).collect()
            except Exception as e:
                result["grants"].append({"role": str(role), "status": "ERROR", "message": str(e)[:100]})

    env_roles = session.sql(
        "SELECT ROLE_TEMPLATE FROM PRISM_SECURITY.ACCESS_CONTROL.ENVIRONMENT_ROLE_METADATA WHERE IS_ACTIVE = TRUE"
    ).collect()
    for er in env_roles:
        rn = er[0].replace("<ENV>", p_env)
        try:
            session.sql("GRANT USAGE ON WAREHOUSE " + wh_name + " TO ROLE " + rn).collect()
            session.sql("GRANT OPERATE ON WAREHOUSE " + wh_name + " TO ROLE " + rn).collect()
            result["grants"].append({"role": rn, "status": "SUCCESS"})
        except:
            pass

    try:
        db_owner = None
        for er in env_roles:
            rn = er[0].replace("<ENV>", p_env)
            if "SYSADMIN" in er[0]:
                db_owner = rn
                break
        if db_owner:
            session.sql("GRANT OWNERSHIP ON WAREHOUSE " + wh_name + " TO ROLE " + db_owner + " COPY CURRENT GRANTS").collect()
            result["grants"].append({"role": db_owner, "status": "OWNERSHIP"})
    except Exception as e:
        result["warnings"].append("Ownership transfer: " + str(e)[:100])

    return result

def log(session, p_id, user, event_type, obj, sql_cmd, status, msg):
    q = chr(39)
    try:
        s = sql_cmd.replace(q, q+q)[:500]
        m = msg.replace(q, q+q)[:200]
        session.sql("INSERT INTO PRISM_OPERATIONS.LOGS.AUDIT_LOG VALUES (" + str(p_id) + ", CURRENT_TIMESTAMP(), " + q + user + q + ", " + q + event_type + q + ", " + q + obj + q + ", " + q + s + q + ", " + q + status + q + ", " + q + m + q + ")").collect()
    except:
        pass
';

-- SP_AI_ASSISTANT
CREATE OR REPLACE PROCEDURE SP_AI_ASSISTANT(P_MODE VARCHAR, P_USER_INPUT VARCHAR, P_CONTEXT VARCHAR DEFAULT '')
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json

MODELS = ["llama3.1-70b", "mistral-large2", "mixtral-8x7b", "llama3.1-8b"]

def get_system_prompt(mode):
    dq = chr(34)
    br = chr(123)
    cbr = chr(125)
    if mode == "COMMAND":
        return "You are PRISM AI, the command interface for a Snowflake RBAC management application. Parse the user request and return ONLY a JSON object with: action, params, confirmation_message. VALID ACTIONS AND REQUIRED PARAMS: CREATE_DATABASE(env, db_name, schemas), CLONE_DATABASE(source_db, target_db, target_env, clone_mode), CREATE_WAREHOUSE(env, wh_type, wh_size, wh_class), CREATE_ROLE(env, function_name, role_type, db_name, access_level), SETUP_ENVIRONMENT(env), CREATE_TAG(tag_name, comment), APPLY_TAG(target_type, target_fqn, tag_name, tag_value, column_name), CREATE_MASKING_POLICY(policy_name, data_type, template, authorized_role), APPLY_MASKING_POLICY(table_fqn, column_name, policy_name), ASSIGN_ROLE(role_to_grant, target_role), REVOKE_ROLE(role_to_revoke, from_role), ASSIGN_DB_ROLE(db_name, db_role_suffix, target_role), DELETE_DATABASE(env, db_name), GRANT_WAREHOUSE(warehouse_name, role). ENVIRONMENTS: DEV, SIT, UAT, PROD, LAB. WH_TYPES: GEN, ETL, DATALOADER, ANALYTICS, ML, AI, BI, STREAMLIT. WH_SIZES: XSMALL, SMALL, MEDIUM, LARGE, XLARGE. WH_CLASS: STANDARD, SNOWPARK-OPTIMIZED. ROLE_TYPES: Functional, Technical. ACCESS_LEVELS: RO_AR, RW_AR, FULL_AR, DBA_AR, OWN_AR, DO_AR, GOV_AR, SVC_AR. MASKING_TEMPLATES: FULL_MASK, PARTIAL_EMAIL, LAST_4_DIGITS, SHA256_HASH, NULL_MASK, DATE_YEAR_ONLY. Return ONLY valid JSON, no explanation."
    elif mode == "FORM_FILL":
        return "You are PRISM AI. Extract parameters from the user description for a Snowflake operation. Return ONLY a JSON object with extracted values. Keys should be lowercase."
    elif mode == "RECOMMEND":
        return "You are PRISM AI. Analyze the provided data and return recommendations as a JSON array. Each item must have: recommendation (text), priority (HIGH/MEDIUM/LOW), action (suggested action). CRITICAL RULES: 1) NEVER recommend removing, merging, or restructuring existing roles - the hierarchy is intentional. 2) Focus ONLY on: missing privileges, over-provisioned privileges, unused capabilities, security gaps. 3) Each role serves a distinct purpose - DO is for operations, GOV is for governance, RW is for data writes, SVC is for services. They are NOT redundant. Return ONLY a valid JSON array."
    else:
        return "You are PRISM AI Governance Assistant for Snowflake. Answer questions about RBAC, access profiles, masking policies, tags, and governance. Use the provided context to give accurate, concise answers. If unsure, say so."

def run(session, p_mode, p_user_input, p_context):
    q = chr(39)
    result = {"status": "SUCCESS", "response": "", "model_used": "", "ai_available": True}

    system_prompt = get_system_prompt(p_mode)
    full_prompt = ("Context: " + p_context + " User request: " + p_user_input) if p_context else p_user_input
    safe_sys = system_prompt.replace(q, q+q)
    safe_prompt = full_prompt.replace(q, q+q)

    for model in MODELS:
        try:
            sql = ("SELECT AI_COMPLETE(" + q + model + q + ", "
                "ARRAY_CONSTRUCT("
                "OBJECT_CONSTRUCT(" + q + "role" + q + ", " + q + "system" + q + ", " + q + "content" + q + ", " + q + safe_sys + q + "), "
                "OBJECT_CONSTRUCT(" + q + "role" + q + ", " + q + "user" + q + ", " + q + "content" + q + ", " + q + safe_prompt + q + ")"
                "), OBJECT_CONSTRUCT(" + q + "temperature" + q + ", 0.1, " + q + "max_tokens" + q + ", 2048))")
            response = session.sql(sql).collect()
            if response and response[0][0]:
                raw = response[0][0]
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                    choices = parsed.get("choices", []) if isinstance(parsed, dict) else []
                    if choices:
                        result["response"] = choices[0].get("messages", str(raw))
                    else:
                        result["response"] = str(raw)
                except:
                    result["response"] = str(raw)
                result["model_used"] = model
                return result
        except Exception as e:
            err = str(e)
            if "not available" in err.lower() or "not supported" in err.lower() or "region" in err.lower():
                continue
            result["response"] = "AI processing error with model " + model
            result["model_used"] = model
            result["status"] = "ERROR"
            return result

    result["ai_available"] = False
    result["status"] = "UNAVAILABLE"
    result["response"] = "AI models are not available in your current Snowflake region. Cortex LLM functions require specific regions. Check Snowflake docs for regional availability."
    return result
';

-- SP_CHECK_GOV_ACCESS
CREATE OR REPLACE PROCEDURE SP_CHECK_GOV_ACCESS(P_USER VARCHAR)
RETURNS BOOLEAN
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'def run(session, p_user):
    try:
        grants = session.sql("SHOW GRANTS TO USER " + p_user).collect()
        for g in grants:
            if str(g[3]) == "PRISM_GOV_ROLE":
                return True
            try:
                role_grants = session.sql("SHOW GRANTS TO ROLE " + str(g[3])).collect()
                for rg in role_grants:
                    if str(rg[3]) == "PRISM_GOV_ROLE":
                        return True
            except:
                pass
        return False
    except:
        return False
';

SELECT 'Step 6 complete: 21 stored procedures created.' AS STATUS;

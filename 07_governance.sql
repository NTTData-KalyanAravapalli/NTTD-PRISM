-- PRISM Deployment - Step 7: Governance
USE ROLE PRISM_APP_ROLE;

USE SCHEMA PRISM_HORIZON.TAGS;
CREATE OR REPLACE PROCEDURE SP_GOV_CREATE_TAG(P_TAG_NAME VARCHAR, P_COMMENT VARCHAR DEFAULT '', P_ALLOWED_VALUES ARRAY DEFAULT null)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json
def run(session, p_tag_name, p_comment, p_allowed_values):
    q = chr(39)
    result = {"status": "SUCCESS", "tag_name": "", "sql": ""}
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_HORIZON.AUDIT.SEQ_GOV_AUDIT.NEXTVAL").collect()[0][0]
    fq_tag = "PRISM_HORIZON.TAGS." + p_tag_name

    sql = "CREATE TAG IF NOT EXISTS " + fq_tag
    if p_comment:
        sql += " COMMENT = " + q + p_comment.replace(q, q+q) + q
    if p_allowed_values:
        vals = ", ".join([q + str(v) + q for v in p_allowed_values])
        sql += " ALLOWED_VALUES " + vals

    result["tag_name"] = fq_tag
    result["sql"] = sql

    try:
        session.sql(sql).collect()
        session.sql("INSERT INTO PRISM_HORIZON.TAGS.TAG_REGISTRY (TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_COMMENT, ALLOWED_VALUES, CREATED_BY) VALUES (" + q + "PRISM_HORIZON" + q + ", " + q + "TAGS" + q + ", " + q + p_tag_name + q + ", " + q + p_comment.replace(q,q+q) + q + ", PARSE_JSON(" + q + json.dumps(p_allowed_values if p_allowed_values else []).replace(q,q+q) + q + "), " + q + user + q + ")").collect()
        log(session, audit_id, user, "CREATE_TAG", "PRISM_HORIZON", "TAGS", p_tag_name, "TAG", "Created governance tag", sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "ERROR"
        result["message"] = str(e)[:500]
        log(session, audit_id, user, "CREATE_TAG", "PRISM_HORIZON", "TAGS", p_tag_name, "TAG", "Failed to create tag", sql, "ERROR", str(e)[:500])
    return result

def log(session, aid, user, etype, db, sch, obj, otype, detail, sql, status, msg):
    q = chr(39)
    try:
        session.sql("INSERT INTO PRISM_HORIZON.AUDIT.GOV_AUDIT_LOG (AUDIT_ID, INVOKED_BY, EVENT_TYPE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, OBJECT_TYPE, ACTION_DETAIL, SQL_COMMAND, STATUS, MESSAGE) VALUES (" + str(aid) + ", " + q + user + q + ", " + q + etype + q + ", " + q + db + q + ", " + q + sch + q + ", " + q + obj + q + ", " + q + otype + q + ", " + q + detail.replace(q,q+q) + q + ", " + q + sql.replace(q,q+q)[:2000] + q + ", " + q + status + q + ", " + q + msg.replace(q,q+q)[:500] + q + ")").collect()
    except: pass
';

USE SCHEMA PRISM_HORIZON.TAGS;
CREATE OR REPLACE PROCEDURE SP_GOV_APPLY_TAG(P_TARGET_TYPE VARCHAR, P_TARGET_FQN VARCHAR, P_TAG_NAME VARCHAR, P_TAG_VALUE VARCHAR DEFAULT '', P_COLUMN_NAME VARCHAR DEFAULT null)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json
def run(session, p_target_type, p_target_fqn, p_tag_name, p_tag_value, p_column_name):
    q = chr(39)
    result = {"status": "SUCCESS"}
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_HORIZON.AUDIT.SEQ_GOV_AUDIT.NEXTVAL").collect()[0][0]
    fq_tag = "PRISM_HORIZON.TAGS." + p_tag_name

    if p_column_name:
        sql = "ALTER " + p_target_type + " " + p_target_fqn + " MODIFY COLUMN " + p_column_name + " SET TAG " + fq_tag + " = " + q + p_tag_value + q
    else:
        sql = "ALTER " + p_target_type + " " + p_target_fqn + " SET TAG " + fq_tag + " = " + q + p_tag_value + q

    result["sql"] = sql
    try:
        session.sql(sql).collect()
        parts = p_target_fqn.split(".")
        db = parts[0] if len(parts) > 0 else ""
        sch = parts[1] if len(parts) > 1 else ""
        obj = parts[2] if len(parts) > 2 else p_target_fqn
        col_detail = " column " + p_column_name if p_column_name else ""
        log(session, audit_id, user, "APPLY_TAG", db, sch, obj, p_target_type, "Tag " + p_tag_name + "=" + p_tag_value + col_detail, sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "ERROR"
        result["message"] = str(e)[:500]
    return result

def log(session, aid, user, etype, db, sch, obj, otype, detail, sql, status, msg):
    q = chr(39)
    try:
        session.sql("INSERT INTO PRISM_HORIZON.AUDIT.GOV_AUDIT_LOG (AUDIT_ID, INVOKED_BY, EVENT_TYPE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, OBJECT_TYPE, ACTION_DETAIL, SQL_COMMAND, STATUS, MESSAGE) VALUES (" + str(aid) + ", " + q + user + q + ", " + q + etype + q + ", " + q + db + q + ", " + q + sch + q + ", " + q + obj + q + ", " + q + otype + q + ", " + q + detail.replace(q,q+q)[:500] + q + ", " + q + sql.replace(q,q+q)[:2000] + q + ", " + q + status + q + ", " + q + msg.replace(q,q+q)[:500] + q + ")").collect()
    except: pass
';

USE SCHEMA PRISM_HORIZON.POLICIES;
CREATE OR REPLACE PROCEDURE SP_GOV_CREATE_MASKING_POLICY(P_POLICY_NAME VARCHAR, P_DATA_TYPE VARCHAR, P_TEMPLATE_NAME VARCHAR, P_AUTHORIZED_ROLE VARCHAR, P_COMMENT VARCHAR DEFAULT '')
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json
def run(session, p_policy_name, p_data_type, p_template_name, p_authorized_role, p_comment):
    q = chr(39)
    result = {"status": "SUCCESS", "policy_name": "", "sql": ""}
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_HORIZON.AUDIT.SEQ_GOV_AUDIT.NEXTVAL").collect()[0][0]
    fq_policy = "PRISM_HORIZON.POLICIES." + p_policy_name

    tmpl = session.sql("SELECT POLICY_BODY_TEMPLATE FROM PRISM_HORIZON.POLICIES.MASKING_POLICY_TEMPLATES WHERE TEMPLATE_NAME = " + q + p_template_name + q + " AND DATA_TYPE = " + q + p_data_type + q + " AND IS_ACTIVE = TRUE LIMIT 1").collect()
    if not tmpl:
        result["status"] = "ERROR"
        result["message"] = "Template " + p_template_name + " for " + p_data_type + " not found"
        return result

    body = tmpl[0][0].replace("<AUTHORIZED_ROLE>", p_authorized_role)
    sql = "CREATE OR REPLACE MASKING POLICY " + fq_policy + " AS (val " + p_data_type + ") RETURNS " + p_data_type + " -> " + body
    if p_comment:
        sql += " COMMENT = " + q + p_comment.replace(q, q+q) + q

    result["policy_name"] = fq_policy
    result["sql"] = sql

    try:
        session.sql(sql).collect()
        session.sql("INSERT INTO PRISM_HORIZON.POLICIES.POLICY_REGISTRY (POLICY_DATABASE, POLICY_SCHEMA, POLICY_NAME, POLICY_TYPE, POLICY_BODY, TARGET_DATA_TYPE, POLICY_COMMENT, CREATED_BY) VALUES (" + q + "PRISM_HORIZON" + q + ", " + q + "POLICIES" + q + ", " + q + p_policy_name + q + ", " + q + "MASKING" + q + ", " + q + body.replace(q,q+q) + q + ", " + q + p_data_type + q + ", " + q + p_comment.replace(q,q+q) + q + ", " + q + user + q + ")").collect()
        log(session, audit_id, user, "CREATE_MASKING_POLICY", "PRISM_HORIZON", "POLICIES", p_policy_name, "MASKING_POLICY", "Template: " + p_template_name + ", Auth role: " + p_authorized_role, sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "ERROR"
        result["message"] = str(e)[:500]
        log(session, audit_id, user, "CREATE_MASKING_POLICY", "PRISM_HORIZON", "POLICIES", p_policy_name, "MASKING_POLICY", "Failed", sql, "ERROR", str(e)[:500])
    return result

def log(session, aid, user, etype, db, sch, obj, otype, detail, sql, status, msg):
    q = chr(39)
    try:
        session.sql("INSERT INTO PRISM_HORIZON.AUDIT.GOV_AUDIT_LOG (AUDIT_ID, INVOKED_BY, EVENT_TYPE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, OBJECT_TYPE, ACTION_DETAIL, SQL_COMMAND, STATUS, MESSAGE) VALUES (" + str(aid) + ", " + q + user + q + ", " + q + etype + q + ", " + q + db + q + ", " + q + sch + q + ", " + q + obj + q + ", " + q + otype + q + ", " + q + detail.replace(q,q+q)[:500] + q + ", " + q + sql.replace(q,q+q)[:2000] + q + ", " + q + status + q + ", " + q + msg.replace(q,q+q)[:500] + q + ")").collect()
    except: pass
';

USE SCHEMA PRISM_HORIZON.POLICIES;
CREATE OR REPLACE PROCEDURE SP_GOV_APPLY_MASKING_POLICY(P_TABLE_FQN VARCHAR, P_COLUMN_NAME VARCHAR, P_POLICY_NAME VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS OWNER
AS 'import json
def run(session, p_table_fqn, p_column_name, p_policy_name):
    q = chr(39)
    result = {"status": "SUCCESS"}
    user = session.sql("SELECT CURRENT_USER()").collect()[0][0]
    audit_id = session.sql("SELECT PRISM_HORIZON.AUDIT.SEQ_GOV_AUDIT.NEXTVAL").collect()[0][0]
    fq_policy = "PRISM_HORIZON.POLICIES." + p_policy_name

    sql = "ALTER TABLE " + p_table_fqn + " MODIFY COLUMN " + p_column_name + " SET MASKING POLICY " + fq_policy
    result["sql"] = sql

    try:
        session.sql(sql).collect()
        parts = p_table_fqn.split(".")
        db = parts[0] if len(parts) > 0 else ""
        sch = parts[1] if len(parts) > 1 else ""
        obj = parts[2] if len(parts) > 2 else p_table_fqn
        log(session, audit_id, user, "APPLY_MASKING_POLICY", db, sch, obj, "TABLE", "Policy " + p_policy_name + " on column " + p_column_name, sql, "SUCCESS", "")
    except Exception as e:
        result["status"] = "ERROR"
        result["message"] = str(e)[:500]
        log(session, audit_id, user, "APPLY_MASKING_POLICY", "", "", p_table_fqn, "TABLE", "Failed", sql, "ERROR", str(e)[:500])
    return result

def log(session, aid, user, etype, db, sch, obj, otype, detail, sql, status, msg):
    q = chr(39)
    try:
        session.sql("INSERT INTO PRISM_HORIZON.AUDIT.GOV_AUDIT_LOG (AUDIT_ID, INVOKED_BY, EVENT_TYPE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, OBJECT_TYPE, ACTION_DETAIL, SQL_COMMAND, STATUS, MESSAGE) VALUES (" + str(aid) + ", " + q + user + q + ", " + q + etype + q + ", " + q + db + q + ", " + q + sch + q + ", " + q + obj + q + ", " + q + otype + q + ", " + q + detail.replace(q,q+q)[:500] + q + ", " + q + sql.replace(q,q+q)[:2000] + q + ", " + q + status + q + ", " + q + msg.replace(q,q+q)[:500] + q + ")").collect()
    except: pass
';

GRANT CREATE TAG ON SCHEMA PRISM_HORIZON.TAGS TO ROLE PRISM_GOV_ROLE;
GRANT CREATE MASKING POLICY ON SCHEMA PRISM_HORIZON.POLICIES TO ROLE PRISM_GOV_ROLE;

SELECT 'Step 7 complete.' AS STATUS;

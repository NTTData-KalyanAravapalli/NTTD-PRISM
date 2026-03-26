# --- Configuration ---
import streamlit as st
from snowflake.snowpark.context import get_active_session
import pandas as pd
import graphviz
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

ABOUT = "About PRISM"

# Configuration - loaded dynamically from PRISM_SETTINGS table
def load_config_from_db():
    """Load CONFIG from PRISM_SETTINGS table. Falls back to defaults if not available."""
    defaults = {
        "SECURITY_DB": "SECURITY_UNDER_DEVELOPMENT",
        "SECURITY_SCHEMA": "ACCESS_CONTROL",
        "OPERATIONS_DB": "OPERATIONS_UNDER_DEVELOPMENT",
        "OPERATIONS_SCHEMA": "LOGS",
        "HORIZON_DB": "HORIZON",
        "WAREHOUSE": "COMPUTE_WH",
        "APP_ROLE": "PRISM_APP_ROLE",
        "GOV_ROLE": "PRISM_GOV_ROLE",
        "VERSION": "2.0.0",
    }
    try:
        rows = session.sql("SELECT SETTING_KEY, SETTING_VALUE FROM PRISM_SETTINGS").collect()
        for r in rows:
            defaults[r[0]] = r[1]
    except:
        pass
    return defaults

PRISM_CFG = load_config_from_db()

CONFIG = {
    "APP": {
        "TITLE": "Portal for Role Integration, Security & Management",
        "LOGO_URL": "NTT-Data-Logo.png"
    },
    "DATABASE": {
        "NAME": PRISM_CFG.get("SECURITY_DB", "SECURITY_UNDER_DEVELOPMENT"),
        "SCHEMA": PRISM_CFG.get("SECURITY_SCHEMA", "ACCESS_CONTROL")
    },
    "AUDIT_DATABASE": {
        "NAME": PRISM_CFG.get("OPERATIONS_DB", "OPERATIONS_UNDER_DEVELOPMENT"),
        "SCHEMA": PRISM_CFG.get("OPERATIONS_SCHEMA", "LOGS")
    },
    "TABLES": {
        "ENVIRONMENTS": "ENVIRONMENTS",
        "ROLE_METADATA": "FUNCTIONAL_TECHNICAL_ROLE_METADATA",
        "AUDIT_LOG": "AUDIT_LOG",
        "AUDIT_LOG_SEQUENCE": "SEQ_AUDIT_LOG",
        "ROLE_HIERARCHY_LOG": "ROLE_HIERARCHY_LOG",
        "ROLE_HIERARCHY_LOG_SEQUENCE": "SEQ_ROLE_HIERARCHY_LOG",
        "ACCESS_PROFILES": "ACCESS_PROFILES",
        "ACCESS_PROFILE_PRIVILEGES": "ACCESS_PROFILE_PRIVILEGES",
        "SNOWFLAKE_PRIVILEGE_CATALOG": "SNOWFLAKE_PRIVILEGE_CATALOG",
        "WAREHOUSE_METADATA": "WAREHOUSE_METADATA",
        "ENVIRONMENT_ROLE_METADATA": "ENVIRONMENT_ROLE_METADATA"
    },
    "HORIZON": {
        "DATABASE": PRISM_CFG.get("HORIZON_DB", "HORIZON"),
        "TAGS_SCHEMA": "TAGS",
        "POLICIES_SCHEMA": "POLICIES",
        "AUDIT_SCHEMA": "AUDIT",
        "TAG_REGISTRY": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".TAGS.TAG_REGISTRY",
        "POLICY_REGISTRY": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".POLICIES.POLICY_REGISTRY",
        "MASKING_TEMPLATES": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".POLICIES.MASKING_POLICY_TEMPLATES",
        "GOV_AUDIT_LOG": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".AUDIT.GOV_AUDIT_LOG",
        "SP_CREATE_TAG": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".TAGS.SP_GOV_CREATE_TAG",
        "SP_APPLY_TAG": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".TAGS.SP_GOV_APPLY_TAG",
        "SP_CREATE_MASKING": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".POLICIES.SP_GOV_CREATE_MASKING_POLICY",
        "SP_APPLY_MASKING": PRISM_CFG.get("HORIZON_DB", "HORIZON") + ".POLICIES.SP_GOV_APPLY_MASKING_POLICY"
    },
    "STORED_PROCEDURES": {
        "DATABASE_CONTROLLER": "SP_DATABASE_CONTROLLER",
        "MANAGE_FUNCTIONAL_TECHNICAL_ROLES": "SP_MANAGE_FUNCTIONAL_TECHNICAL_ROLES_CONTROLLER"
    }
}
}


def get_fully_qualified_name(object_name, include_db=True, include_audit_db=False):
    """
    Generate fully qualified name for database objects.
    Args:
        object_name: The name of the table/sequence/procedure
        include_db: Whether to include database name in the path
    Returns:
        Fully qualified name (e.g., "DATABASE.SCHEMA.OBJECT" or "SCHEMA.OBJECT")
    """

    if include_db:
        return f"{CONFIG['DATABASE']['NAME']}.{CONFIG['DATABASE']['SCHEMA']}.{object_name}"
   
#    if include_db:
#        return f"{CONFIG['SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_APPLY_METADATA_PRIVILEGES_TO_ROLEDATABASE']['NAME']}.{CONFIG['DATABASE']['SCHEMA']}.{object_name}"
    if include_audit_db:
        return f"{CONFIG['AUDIT_DATABASE']['NAME']}.{CONFIG['AUDIT_DATABASE']['SCHEMA']}.{object_name}"        
    return f"{CONFIG['DATABASE']['SCHEMA']}.{object_name}"

# --- Constants ---
APP_TITLE = CONFIG["APP"]["TITLE"]
SNOWFLAKE_LOGO_URL = CONFIG["APP"]["LOGO_URL"]

# Snowflake Object Names - Using the helper function
ENVIRONMENTS_TABLE = get_fully_qualified_name(CONFIG["TABLES"]["ENVIRONMENTS"])
ROLE_METADATA_TABLE = get_fully_qualified_name(CONFIG["TABLES"]["ROLE_METADATA"])
AUDIT_LOG_TABLE = get_fully_qualified_name(CONFIG["TABLES"]["AUDIT_LOG"],False,True)
AUDIT_LOG_SEQUENCE = get_fully_qualified_name(CONFIG["TABLES"]["AUDIT_LOG_SEQUENCE"],False, True)
ROLE_HIERARCHY_LOG_TABLE = get_fully_qualified_name(CONFIG["TABLES"]["ROLE_HIERARCHY_LOG"],False, True)
ROLE_HIERARCHY_LOG_SEQUENCE = get_fully_qualified_name(CONFIG["TABLES"]["ROLE_HIERARCHY_LOG_SEQUENCE"],False, True)

# Actions
CREATE_DATABASE = "Create a Database"
CLONE_DATABASE = "Clone a Database"
DELETE_DATABASE = "Delete a Database"
CREATE_WAREHOUSE = "Create a Warehouse"
CREATE_ROLE = "Create a Role"
CREATE_ENVIRONMENT_ROLES = "Create Environment Roles"  
SHOW_ROLE_HIERARCHY = "Show Role Hierarchy"
SHOW_DATABASE_ROLE_HIERARCHY = "Show Database Role Hierarchy"
DISPLAY_RBAC_ARCHITECTURE = "Display RBAC Architecture"
MANAGE_METADATA = "Manage Metadata"
AUDIT_LOGS = "Audit Logs"
ASSIGN_ROLES = "Assign Roles"
ASSIGN_DATABASE_ROLES = "Assign Database Roles"
REVOKE_ROLES = "Revoke Roles"  
COST_ANALYSIS = "Cost Analysis"
PRIVILEGE_DRIFT = "Privilege Drift"
ACCESS_PROFILES_VIEW = "Access Profiles"
GOV_POLICY_AUDIT = "Policy Audit"
GOV_TAG_MANAGER = "Tag Manager"
GOV_MASKING_POLICIES = "Masking Policies"
GOV_AUDIT_LOG = "Governance Audit"
AI_COMMAND = "AI Command"

ACTIONS_LIST = [
    ABOUT,
    CREATE_DATABASE,
    CLONE_DATABASE,
    DELETE_DATABASE,
    CREATE_WAREHOUSE,
    CREATE_ROLE,
    ASSIGN_ROLES,
    ASSIGN_DATABASE_ROLES,
    REVOKE_ROLES, 
    CREATE_ENVIRONMENT_ROLES,
    SHOW_ROLE_HIERARCHY,
    SHOW_DATABASE_ROLE_HIERARCHY,
    DISPLAY_RBAC_ARCHITECTURE,
    MANAGE_METADATA,
    COST_ANALYSIS,
    PRIVILEGE_DRIFT,
    ACCESS_PROFILES_VIEW,
    AUDIT_LOGS, 
]

# Role Types
FUNCTIONAL_ROLE = "Functional"
TECHNICAL_ROLE = "Technical"

# --- Snowpark Session ---
try:
    session = get_active_session()
    if session is None:
        st.error("Failed to get active Snowpark session. Ensure you are running this in a Snowflake-connected environment.")
        st.stop()
except Exception as e:
    st.error(f"Error establishing Snowflake session: {e}")
    st.stop()

# [Previous helper functions remain the same]

def configure_chart(fig):
    """Configure Plotly chart for adaptive light/dark mode."""
    fig.update_layout(
        template="plotly",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(size=12),
        margin=dict(l=20, r=20, t=40, b=20),
    )
    return fig

def get_environments():
    """Fetches available environment names from the ENVIRONMENTS_TABLE."""
    try:
        env_df = session.table(ENVIRONMENTS_TABLE).select("ENVIRONMENT_NAME").distinct()
        return sorted([row["ENVIRONMENT_NAME"] for row in env_df.collect()])
    except Exception as e:
        st.error(f"Error fetching environments from '{ENVIRONMENTS_TABLE}': {e}")
        return []

@st.cache_data(ttl=600)
def get_function_names(role_type_filter: str):
    """Fetches function names based on role type from ROLE_METADATA_TABLE."""
    try:
        role_df = session.table(ROLE_METADATA_TABLE).filter(f"ROLE_TYPE = '{role_type_filter}'").select("FUNCTION_NAME").distinct()
        return sorted([row["FUNCTION_NAME"] for row in role_df.collect()])
    except Exception as e:
        st.error(f"Error fetching function names for type '{role_type_filter}' from '{ROLE_METADATA_TABLE}': {e}")
        return []

@st.cache_data(ttl=300)
def get_databases():
    """Fetches all database names in the current account."""
    try:
        dbs = session.sql("SHOW DATABASES").collect()
        return sorted([db["name"] for db in dbs if db["name"]])
    except Exception as e:
        st.error(f"Error fetching databases: {e}")
        return []

@st.cache_data(ttl=300)
def get_current_snowflake_user() -> str:
    """Gets the current Snowflake user (viewer, not app owner)."""
    try:
        return st.user.user_name
    except Exception:
        try:
            return session.sql("SELECT CURRENT_USER()").collect()[0][0]
        except Exception:
            return "UNKNOWN_USER"

def get_current_snowflake_role() -> str:
    """Safely get the current role from the session."""
    try:
        return session.sql("SELECT CURRENT_ROLE()").collect()[0][0]
    except Exception:
        return "UNKNOWN_ROLE"

def log_audit_event(
    event_type: str,
    object_name: str,
    sql_command: str,
    status: str,
    message: str = "",
    invoked_by_role: str = None,
    invoked_by_user: str = None,
) -> int:
    """Logs an audit event to the AUDIT_LOG_TABLE and returns the event_id."""
    if invoked_by_role is None:
        invoked_by_role = get_current_snowflake_role()
    if invoked_by_user is None:
        invoked_by_user = get_current_snowflake_user()

    event_id = None
    insert_sql = ""
    try:
        event_id_result = session.sql(f"SELECT {AUDIT_LOG_SEQUENCE}.NEXTVAL AS ID").collect()
        if not event_id_result:
            st.warning(f"Audit logging failed for '{event_type}': Could not retrieve next event ID from sequence.")
            return None
        event_id = event_id_result[0]["ID"]

        insert_sql = f"""
            INSERT INTO {AUDIT_LOG_TABLE} (
                EVENT_ID, EVENT_TIME, INVOKED_BY, INVOKED_BY_ROLE, EVENT_TYPE,
                OBJECT_NAME, SQL_COMMAND, STATUS, MESSAGE
            ) VALUES (
                {event_id}, CURRENT_TIMESTAMP(), '{invoked_by_user}', '{invoked_by_role}',
                '{event_type}', '{object_name}', $${sql_command}$$, '{status}', $${message}$$
            )
        """
        session.sql(insert_sql).collect()
        return event_id
    except Exception as e:
        return event_id

def log_role_hierarchy_event(
    audit_event_id: int,
    invoked_by: str,
    environment_name: str,
    created_role_name: str,
    created_role_type: str,
    mapped_database_role: str,
    parent_account_role: str,
    sql_command_create_role: str,
    sql_command_grant_db_role: str,
    sql_command_grant_ownership: str,
    status: str,
    message: str = "",
):
    """Logs an event to the ROLE_HIERARCHY_LOG table."""
    insert_sql = ""
    try:
        log_id_result = session.sql(f"SELECT {ROLE_HIERARCHY_LOG_SEQUENCE}.NEXTVAL AS ID").collect()
        if not log_id_result:
            st.warning(f"Role hierarchy logging failed for '{created_role_name}': Could not retrieve LOG_ID from sequence.")
            return
        log_id = log_id_result[0]["ID"]

        insert_sql = f"""
            INSERT INTO {ROLE_HIERARCHY_LOG_TABLE} (
                LOG_ID, EVENT_TIME, AUDIT_EVENT_ID, INVOKED_BY, ENVIRONMENT_NAME,
                CREATED_ROLE_NAME, CREATED_ROLE_TYPE, MAPPED_DATABASE_ROLE,
                PARENT_ACCOUNT_ROLE, SQL_COMMAND_CREATE_ROLE, SQL_COMMAND_GRANT_DB_ROLE,
                SQL_COMMAND_GRANT_OWNERSHIP, STATUS, MESSAGE
            ) VALUES (
                {log_id}, CURRENT_TIMESTAMP(), {audit_event_id if audit_event_id else "NULL"},
                '{invoked_by}', '{environment_name}', '{created_role_name}',
                '{created_role_type}', '{mapped_database_role}', '{parent_account_role}',
                $${sql_command_create_role}$$, $${sql_command_grant_db_role}$$,
                $${sql_command_grant_ownership}$$, '{status}', $${message}$$
            )
        """
        session.sql(insert_sql).collect()
    except Exception as e:
        return audit_event_id

# --- UI Functions for Actions ---
def ui_create_database():
    """UI for creating a new database and optionally schemas."""
    st.header("Create a New Database or Schemas")
    
    # Get access role suffixes from metadata
    access_role_suffixes = get_access_role_suffixes()
    if not access_role_suffixes:
        st.error("Could not fetch access role suffixes from metadata. Please ensure ACCESS_PROFILES table is properly configured.")
        return
    
    # Create radio button for operation type selection
    operation_type = st.radio(
        "Select Operation Type",
        ["Create Database Only", "Create Database with Schemas", "Create Schemas for Existing Database"],
        key="db_operation_type",
        horizontal=True,
        help="Choose whether to create just a database, a database with schemas, or add schemas to an existing database."
    )
    
    # Get list of existing databases for the "Create Schemas for Existing Database" option
    existing_databases = []
    if operation_type == "Create Schemas for Existing Database":
        existing_databases = get_databases()
    
    # Add detailed information about the database creation process
    st.info(f"""
    ### What this action will do:
    
    1. **Database Creation**:
       - Creates a new database with name format: `<ENV>_<DATABASE_NAME>`
       - Example: For environment 'DEV' and database 'MARKETING', creates `DEV_MARKETING`
    
    2. **Database Roles**:
       - Creates database roles with the following suffixes:
         {chr(10).join([f"         - `<DATABASE>.{suffix}`" for suffix in access_role_suffixes])}
    
    3. **Schema Creation** (if selected):
       - Creates schemas within the database
       - For each schema, creates schema-level roles with the following pattern:
         {chr(10).join([f"         - `<DATABASE>.<SCHEMA_NAME>_{suffix}`" for suffix in access_role_suffixes])}
       - Schema roles inherit permissions from corresponding database roles
       - Example: For schema 'SALES' in database 'DEV_MARKETING', creates roles like:
         - `<DATABASE>.<SCHEMA>_<ACCESS_PROFILE>` (as defined in ACCESS_PROFILES)
    
    4. **Ownership Structure**:
       - Ownership is configured via ENVIRONMENT_ROLE_METADATA table
       - Database roles owned by the role with OWNS_DB_ROLES=TRUE
       - Databases and schemas owned by the role with OWNS_DATABASES=TRUE
    
    5. **Access Control**:
       - Implements standard RBAC (Role-Based Access Control)
       - Establishes proper privilege hierarchy
       - Ensures secure access management
    """)

    with st.form("create_db_form"):
        # Environment selection with enhanced help text
        env = st.selectbox(
            "Target Environment",
            get_environments(),
            key="cd_env",
            help="Select the environment prefix for the database. This will be automatically added to the database name."
        )

        # Database selection or input based on operation type
        if operation_type == "Create Schemas for Existing Database":
            # For existing database, show a dropdown
            if env and existing_databases:
                # Filter databases based on the selected environment
                env_databases = [db for db in existing_databases if db.startswith(f"{env}_")]
                if not env_databases:
                    env_databases = existing_databases  # Fallback if no databases match the environment
                
                db_name_input = st.selectbox(
                    "Select Existing Database",
                    options=env_databases,
                    key="cd_existing_db",
                    help="Select the database where you want to create new schemas."
                )
                
                # Extract the base database name without environment prefix
                if db_name_input and db_name_input.startswith(f"{env}_"):
                    db_name = db_name_input[len(env)+1:]
                else:
                    db_name = db_name_input
            else:
                st.warning("No databases available or environment not selected.")
                db_name = ""
        else:
            # For new database, show a text input
            db_name_input = st.text_input(
                "Enter New Database Name",
                key="cd_db_name",
                help="Enter the base database name without environment prefix. It will be automatically converted to uppercase."
            )
            db_name = db_name_input.strip().upper() if db_name_input else ""

        # Schema input field (shown only for schema operations)
        schemas_csv = ""
        if operation_type in ["Create Database with Schemas", "Create Schemas for Existing Database"]:
            schemas_csv = st.text_input(
                "Enter Schema Names (comma-separated)",
                key="cd_schemas",
                help="Enter schema names separated by commas. Example: SALES,MARKETING,FINANCE"
            ).strip().upper()

        # Show preview based on operation type
        if env and db_name:
            preview_name = f"{env}_{db_name}"
            
            if operation_type == "Create Database Only":
                st.markdown(f"""
                #### Preview:
                - **Final Database Name:** `{preview_name}`
                - **Database Roles to be Created:**
                  {chr(10).join([f"              - `{preview_name}.{suffix}`" for suffix in access_role_suffixes])}
                """)
            elif operation_type in ["Create Database with Schemas", "Create Schemas for Existing Database"]:
                if schemas_csv:
                    schema_names = [schema.strip() for schema in schemas_csv.split(",") if schema.strip()]
                    st.markdown(f"""
                    #### Preview:
                    - **Database:** `{preview_name}`
                    - **Schemas to be Created:** {", ".join(schema_names)}
                    - **Schema Roles to be Created (for each schema):**
                      {chr(10).join([f"              - `{preview_name}.<SCHEMA_NAME>_{suffix}`" for suffix in access_role_suffixes])}
                    """)
                    
                    # Show example for the first schema if available
                    if schema_names:
                        example_schema = schema_names[0]
                        st.markdown(f"""
                        #### Example for Schema '{example_schema}':
                        - Schema Roles:
                          {chr(10).join([f"              - `{preview_name}.{example_schema}_{suffix}`" for suffix in access_role_suffixes])}
                        """)
                else:
                    st.warning("Please enter at least one schema name.")

        # Add confirmation checkbox
        confirm = st.checkbox(
            "I confirm that I want to proceed with this operation",
            key="confirm_db_creation"
        )

        submitted = st.form_submit_button("Submit")

        if submitted:
            if not confirm:
                st.warning("Please confirm the operation by checking the confirmation box.")
                return

            if not env:
                st.warning("Please select an environment.")
                return
                
            if not db_name:
                st.warning("Please provide a database name.")
                return
                
            if operation_type in ["Create Database with Schemas", "Create Schemas for Existing Database"] and not schemas_csv:
                st.warning("Please provide at least one schema name.")
                return

            # Prepare stored procedure call based on operation type
            sp_name = get_fully_qualified_name(CONFIG["STORED_PROCEDURES"]["DATABASE_CONTROLLER"])
            
            if operation_type == "Create Database Only":
                sql_command = f"CALL {sp_name}('{env}', '{db_name}')"
                operation_desc = f"Creating database {env}_{db_name} and setting up roles..."
            elif operation_type == "Create Database with Schemas":
                sql_command = f"CALL {sp_name}('{env}', '{db_name}', '', '', '', '', '', '{schemas_csv}')"
                operation_desc = f"Creating database {env}_{db_name} with schemas {schemas_csv} and setting up roles..."
            else:  # Create Schemas for Existing Database
                # For existing database, we pass the database name but don't create a new one
                # The stored procedure will detect that the database exists and only create schemas
                sql_command = f"CALL {sp_name}('{env}', '{db_name}', '', '', '', '', '', '{schemas_csv}')"
                operation_desc = f"Creating schemas {schemas_csv} in existing database {env}_{db_name} and setting up roles..."
            
            try:
                with st.spinner(operation_desc):
                    result = session.sql(sql_command).collect()
                    
                # Prepare success message based on operation type
                if operation_type == "Create Database Only":
                    success_message = f"""
                    ✅ Database created successfully!
                    
                    **Created Resources:**
                    - Database: `{env}_{db_name}`
                    - Database Roles:
                      {chr(10).join([f"                      - `{env}_{db_name}.{suffix}`" for suffix in access_role_suffixes])}
                    
                    **Ownership Assigned:**
                    - Database and Schemas → per ENVIRONMENT_ROLE_METADATA
                    - Database Roles → per ENVIRONMENT_ROLE_METADATA
                    - Objects → per ENVIRONMENT_ROLE_METADATA
                    """
                else:
                    # For schema operations
                    schema_names = [schema.strip() for schema in schemas_csv.split(",") if schema.strip()]
                    
                    if operation_type == "Create Database with Schemas":
                        success_message = f"""
                        ✅ Database and schemas created successfully!
                        
                        **Created Resources:**
                        - Database: `{env}_{db_name}`
                        - Database Roles:
                          {chr(10).join([f"                      - `{env}_{db_name}.{suffix}`" for suffix in access_role_suffixes])}
                        - Schemas: {", ".join(schema_names)}
                        - Schema Roles (for each schema):
                          {chr(10).join([f"                      - `{env}_{db_name}.<SCHEMA_NAME>_{suffix}`" for suffix in access_role_suffixes])}
                        
                        **Ownership Assigned:**
                        - Database and Schemas → per ENVIRONMENT_ROLE_METADATA
                        - Database and Schema Roles → per ENVIRONMENT_ROLE_METADATA
                        - Objects → per ENVIRONMENT_ROLE_METADATA
                        """
                    else:  # Create Schemas for Existing Database
                        success_message = f"""
                        ✅ Schemas created successfully in existing database!
                        
                        **Created Resources:**
                        - Database: `{env}_{db_name}` (existing)
                        - Schemas: {", ".join(schema_names)}
                        - Schema Roles (for each schema):
                          {chr(10).join([f"                      - `{env}_{db_name}.<SCHEMA_NAME>_{suffix}`" for suffix in access_role_suffixes])}
                        
                        **Ownership Assigned:**
                        - Schemas → per ENVIRONMENT_ROLE_METADATA
                        - Schema Roles → per ENVIRONMENT_ROLE_METADATA
                        - Objects → per ENVIRONMENT_ROLE_METADATA
                        """
                
                st.success(success_message)
                
                # Log the event
                log_audit_event(
                    "CREATE_DATABASE_SCHEMAS",
                    f"{env}_{db_name}" + (f" with schemas: {schemas_csv}" if schemas_csv else ""),
                    sql_command,
                    "SUCCESS",
                    f"Operation: {operation_type}. Result: Success."
                )
            except Exception as e:
                st.error(f"""
                Failed to complete operation
                
                Error: {str(e)}
                
                Please ensure:
                - You have the necessary permissions
                - The environment roles are properly set up
                - For schema creation, the database exists
                - Schema names are valid
                """)
                log_audit_event(
                    "CREATE_DATABASE_SCHEMAS",
                    f"{env}_{db_name}" + (f" with schemas: {schemas_csv}" if schemas_csv else ""),
                    sql_command,
                    "ERROR",
                    str(e)
                )

def ui_clone_database():
    """UI for cloning an existing database with all Snowflake cloning options."""
    st.header("Clone an Existing Database")

    st.info("""
    ### Advanced Database Cloning

    **Features:**
    - Zero-copy clone (current state) or point-in-time clone via Time Travel
    - Automatic capture and reattachment of account role to database role mappings
    - Full RBAC setup on the cloned database (privileges, hierarchy, future grants)
    - Ownership transfer per ENVIRONMENT_ROLE_METADATA configuration
    - Support for IGNORE TABLES WITH INSUFFICIENT DATA RETENTION and IGNORE HYBRID TABLES
    """)

    environments = get_environments()
    all_databases = get_databases()

    env = st.selectbox("Target Environment", environments, key="cld_env")
    new_db_name_input = st.text_input("New Database Name (without env prefix)", key="cld_new_db_name").strip().upper()
    source_db = st.selectbox("Source Database to Clone", all_databases, key="cld_source_db")

    st.markdown("---")
    st.subheader("Cloning Options")
    clone_mode = st.radio("Clone Mode", ["Current State", "Point-in-Time (Timestamp)", "Point-in-Time (Offset)", "Before Statement"], key="cld_mode", horizontal=True)

    ts_value = None
    offset_value = None
    stmt_id = None

    if clone_mode == "Point-in-Time (Timestamp)":
        ts_col1, ts_col2 = st.columns(2)
        with ts_col1:
            ts_date = st.date_input("Date", key="cld_ts_date")
        with ts_col2:
            ts_time = st.time_input("Time", key="cld_ts_time")
        if ts_date and ts_time:
            ts_value = str(ts_date) + " " + str(ts_time)
    elif clone_mode == "Point-in-Time (Offset)":
        offset_value = st.number_input("Seconds ago", min_value=1, max_value=7776000, value=3600, key="cld_offset")
    elif clone_mode == "Before Statement":
        stmt_id = st.text_input("Statement ID (Query ID)", key="cld_stmt_id").strip()

    st.markdown("---")
    st.subheader("Advanced Options")
    col_o1, col_o2, col_o3 = st.columns(3)
    with col_o1:
        ignore_retention = st.checkbox("Ignore insufficient retention", key="cld_ign_ret")
    with col_o2:
        ignore_hybrid = st.checkbox("Ignore hybrid tables", key="cld_ign_hyb")
    with col_o3:
        include_stages = st.checkbox("Include internal stages", key="cld_inc_stg")

    st.markdown("---")
    st.subheader("Role and RBAC Configuration")
    col_r1, col_r2 = st.columns(2)
    with col_r1:
        setup_rbac = st.checkbox("Set up RBAC on cloned database", value=True, key="cld_rbac")
    with col_r2:
        reattach_roles = st.checkbox("Capture and reattach role mappings", value=True, key="cld_reattach")

    if env and new_db_name_input and source_db:
        target_db = f"{env}_{new_db_name_input}"
        with st.expander("Clone Preview", expanded=True):
            preview_data = {"Source": source_db, "Target": target_db, "Mode": clone_mode, "RBAC": setup_rbac, "Reattach Roles": reattach_roles}
            for k, v in preview_data.items():
                st.write(f"**{k}:** {v}")

    confirm = st.checkbox("I confirm I want to clone this database", key="confirm_clone")

    if st.button("Clone Database", type="primary", disabled=not confirm):
        if not all([env, new_db_name_input, source_db]):
            st.warning("Please fill all required fields.")
            return
        target_db = f"{env}_{new_db_name_input}"
        if target_db == source_db:
            st.error("Target cannot match source database.")
            return
        mode_map = {"Current State": "CURRENT", "Point-in-Time (Timestamp)": "TIMESTAMP", "Point-in-Time (Offset)": "OFFSET", "Before Statement": "STATEMENT"}
        sp_name = get_fully_qualified_name("SP_CLONE_DATABASE", include_db=True)
        try:
            with st.spinner(f"Cloning {source_db} to {target_db}... This may take several minutes."):
                result = session.call(sp_name, source_db, target_db, env, mode_map[clone_mode], ts_value if ts_value else "", int(offset_value) if offset_value else 0, stmt_id if stmt_id else "", ignore_retention, ignore_hybrid, include_stages, setup_rbac, reattach_roles)
            import json
            result_data = json.loads(result) if isinstance(result, str) else result
            if result_data.get("status") == "SUCCESS":
                st.success(f"Database cloned successfully: `{target_db}`")
                col_m1, col_m2 = st.columns(2)
                with col_m1:
                    st.metric("Role Mappings Captured", result_data.get("role_mappings_captured", 0))
                with col_m2:
                    st.metric("Role Mappings Restored", result_data.get("role_mappings_restored", 0))
                for step in result_data.get("steps", []):
                    icon = "pass" if step["status"] == "SUCCESS" else "fail"
                    st.write(f"**{step['step']}**: {step['status']} - {step.get('detail', '')}")
                if result_data.get("warnings"):
                    with st.expander("Warnings"):
                        for w in result_data["warnings"]:
                            st.warning(w)
            else:
                st.error("Clone failed. Check steps below.")
                for step in result_data.get("steps", []):
                    st.write(f"**{step['step']}**: {step['status']} - {step.get('detail', '')}")
            log_audit_event("CLONE_DATABASE", target_db, f"Source: {source_db}", result_data.get("status", "UNKNOWN"), str(result_data)[:500])
            st.cache_data.clear()
        except Exception as e:
            st.error("Clone operation failed. Please check permissions and that the target database does not already exist.")
            log_audit_event("CLONE_DATABASE", target_db, f"Source: {source_db}", "ERROR", str(e))
def ui_delete_database():
    """UI for deleting a database."""
    st.header("Delete a Database")
    st.warning("This action is IRREVERSIBLE. The database and all its objects, roles, and data will be permanently deleted.")
    environments = get_environments()
    all_databases = get_databases()

    with st.form("delete_db_form"):
        env = st.selectbox("Target Environment", environments, key="dd_env", help="Select the environment of the database to delete.")
       
        # Filter databases based on the selected environment (assuming a naming convention like ENV_DB_NAME or ENV in DB name)
        if env and all_databases:
            available_dbs_in_env = [db for db in all_databases if db.startswith(f"{env}_") or env in db]
            if not available_dbs_in_env: # If no matches by prefix/inclusion, show all as a fallback
                 available_dbs_in_env = all_databases
        else: # If no env selected or no databases, show all or empty
            available_dbs_in_env = all_databases if all_databases else []

        db_to_delete = st.selectbox(
            "Select Database to Delete",
            available_dbs_in_env,
            key="dd_db_to_delete",
            help="Ensure this is the correct database. Deletion is often irreversible."
        )
        confirm_delete = st.checkbox(f"I confirm I want to permanently delete the database: **{db_to_delete}**", key="dd_confirm")
        submitted = st.form_submit_button("Delete Database", type="primary")

        if submitted:
            if not confirm_delete:
                st.warning("Please confirm the deletion by checking the box.")
                return

            if env and db_to_delete:
                sql_command = f"DROP DATABASE IF EXISTS {db_to_delete}" # Use IF EXISTS for safety
                try:
                    st.info(f"Attempting to delete database: {db_to_delete}...")
                    session.sql(sql_command).collect()
                    st.success(f"Database '{db_to_delete}' successfully deleted from environment '{env}'.")
                    log_audit_event("DELETE_DATABASE", db_to_delete, sql_command, "SUCCESS", f"Database deleted from env {env}.")
                    st.cache_data.clear() # Clear cache as database list changed
                except Exception as e:
                    st.error(f"Failed to delete database '{db_to_delete}': {e}")
                    log_audit_event("DELETE_DATABASE", db_to_delete, sql_command, "ERROR", str(e))
            else:
                st.warning("Please select an environment and a database to delete.")

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_warehouse_metadata():
    """Fetch warehouse configuration metadata."""
    try:
        query = f"""
        SELECT *
        FROM {get_fully_qualified_name(CONFIG["TABLES"]["WAREHOUSE_METADATA"])}
        WHERE IS_ACTIVE = TRUE
        ORDER BY WAREHOUSE_CLASS, WAREHOUSE_TYPE, WAREHOUSE_SIZE
        """
        return session.sql(query).to_pandas()
    except Exception as e:
        st.error(f"Error fetching warehouse metadata: {e}")
        return pd.DataFrame()

def ui_create_warehouse():
    """UI for creating a warehouse with all Snowflake options, metadata-driven."""
    st.header("Create a New Warehouse")

    warehouse_metadata = get_warehouse_metadata()
    if warehouse_metadata.empty:
        st.error("No warehouse metadata found.")
        return

    environments = get_environments()
    env = st.selectbox("Target Environment", environments, key="cw_env")

    wh_classes = sorted(warehouse_metadata["WAREHOUSE_CLASS"].unique())
    wh_class = st.radio("Warehouse Class", wh_classes, key="cw_class", horizontal=True, help="STANDARD for general use, SNOWPARK-OPTIMIZED for ML/AI/Python workloads")

    filtered = warehouse_metadata[warehouse_metadata["WAREHOUSE_CLASS"] == wh_class]
    wh_types = sorted(filtered["WAREHOUSE_TYPE"].unique())
    wh_type = st.selectbox("Purpose/Function", wh_types, key="cw_type")

    filtered2 = filtered[filtered["WAREHOUSE_TYPE"] == wh_type]
    sizes = sorted(filtered2["WAREHOUSE_SIZE"].tolist())
    wh_size = st.selectbox("Warehouse Size", sizes, key="cw_size")

    custom_name = ""
    config = None
    if wh_type and wh_size:
        match = filtered2[filtered2["WAREHOUSE_SIZE"] == wh_size]
        if not match.empty:
            config = match.iloc[0]
            if config["IS_CUSTOM"]:
                custom_name = st.text_input("Custom Function Name", key="cw_custom").strip().upper()

    if config is not None:
        st.markdown("---")
        st.subheader("Warehouse Configuration")
        col1, col2 = st.columns(2)
        with col1:
            auto_suspend = st.number_input("Auto Suspend (seconds)", min_value=0, value=int(config["DEFAULT_AUTO_SUSPEND_SECS"]), key="cw_suspend", help="0 = never suspend")
            auto_resume = st.checkbox("Auto Resume", value=bool(config["DEFAULT_AUTO_RESUME"]), key="cw_resume")
            initially_suspended = st.checkbox("Initially Suspended", value=bool(config["DEFAULT_INITIALLY_SUSPENDED"]), key="cw_init_susp")
        with col2:
            max_concurrency = st.number_input("Max Concurrency Level", min_value=1, max_value=64, value=int(config["DEFAULT_MAX_CONCURRENCY_LEVEL"]), key="cw_concurrency")
            stmt_timeout = st.number_input("Statement Timeout (seconds)", min_value=0, value=int(config["DEFAULT_STATEMENT_TIMEOUT_SECS"]), key="cw_stmt_to", help="0 = no timeout")
            queued_timeout = st.number_input("Queued Statement Timeout (seconds)", min_value=0, value=int(config["DEFAULT_STMT_QUEUED_TIMEOUT_SECS"]), key="cw_q_to", help="0 = no timeout")

        st.markdown("---")
        st.subheader("Multi-Cluster & Query Acceleration")
        col3, col4 = st.columns(2)
        with col3:
            min_clusters = st.number_input("Min Cluster Count", min_value=1, max_value=10, value=int(config["DEFAULT_MIN_CLUSTER_COUNT"]), key="cw_min_cl")
            max_clusters = st.number_input("Max Cluster Count", min_value=1, max_value=10, value=int(config["DEFAULT_MAX_CLUSTER_COUNT"]), key="cw_max_cl")
            scaling_policy = st.selectbox("Scaling Policy", ["STANDARD", "ECONOMY"], index=0 if config["DEFAULT_SCALING_POLICY"] == "STANDARD" else 1, key="cw_scaling")
        with col4:
            enable_qa = st.checkbox("Enable Query Acceleration", value=bool(config["DEFAULT_ENABLE_QUERY_ACCELERATION"]), key="cw_qa")
            qa_scale = 8
            if enable_qa:
                qa_scale = st.number_input("Query Acceleration Max Scale Factor", min_value=0, max_value=100, value=int(config["DEFAULT_QUERY_ACCEL_MAX_SCALE"]), key="cw_qa_scale")
            resource_monitor = st.text_input("Resource Monitor (optional)", value=config["DEFAULT_RESOURCE_MONITOR"] if config["DEFAULT_RESOURCE_MONITOR"] else "", key="cw_res_mon")

        comment_wh = st.text_input("Comment", value=config["DEFAULT_COMMENT"] if config["DEFAULT_COMMENT"] else "", key="cw_comment")

        st.markdown("---")
        st.subheader("Role Assignment")
        all_roles = get_all_roles()
        selected_roles = st.multiselect("Grant Warehouse Access To", options=all_roles if all_roles else [], key="cw_roles")

        func_part = custom_name if custom_name else wh_type
        wh_name = f"{env}_{func_part}_{wh_size}_WH".upper() if env and func_part and wh_size else ""

        if wh_name:
            with st.expander("Warehouse Preview", expanded=True):
                preview = {"Name": wh_name, "Class": wh_class, "Size": wh_size, "Auto Suspend": str(auto_suspend) + "s", "Clusters": str(min_clusters) + "-" + str(max_clusters), "Query Accel": enable_qa}
                for k, v in preview.items():
                    st.write(f"**{k}:** {v}")

        confirm = st.checkbox("I confirm I want to create this warehouse", key="cw_confirm")

        if st.button("Create Warehouse", type="primary", disabled=not confirm):
            if not wh_name:
                st.warning("Please complete all required fields.")
                return
            sp_name = get_fully_qualified_name("SP_CREATE_WAREHOUSE", include_db=True)
            try:
                with st.spinner(f"Creating warehouse {wh_name}..."):
                    result = session.call(sp_name, env, wh_type, wh_size, wh_class, custom_name if custom_name else "", auto_suspend, auto_resume, initially_suspended, min_clusters, max_clusters, scaling_policy, enable_qa, qa_scale, stmt_timeout, queued_timeout, max_concurrency, resource_monitor if resource_monitor else "", comment_wh if comment_wh else "", selected_roles if selected_roles else [])
                import json
                result_data = json.loads(result) if isinstance(result, str) else result
                if result_data.get("status") == "SUCCESS":
                    st.success(f"Warehouse created: `{result_data.get('warehouse_name', wh_name)}`")
                    if result_data.get("grants"):
                        st.subheader("Role Grants")
                        for g in result_data["grants"]:
                            st.write(f"**{g['role']}**: {g['status']}")
                else:
                    st.error("Warehouse creation failed.")
                    for w in result_data.get("warnings", []):
                        st.warning(w)
                log_audit_event("CREATE_WAREHOUSE", wh_name, "SP_CREATE_WAREHOUSE", result_data.get("status", "UNKNOWN"), str(result_data)[:500])
                st.cache_data.clear()
            except Exception as e:
                st.error("Operation failed. Please check your inputs and permissions.")
                log_audit_event("CREATE_WAREHOUSE", wh_name, "Error", "ERROR", str(e))
def ui_create_role():
    """UI for creating a new role, granting database access, and setting ownership."""
    st.header("Create New Role")
    environments = get_environments()
    all_databases = get_databases()
    
    # Define a global key for the access level selection that will be used throughout the function
    access_level_key = "cr_access_level"

    # Get role type suffixes from metadata
    role_type_suffixes = get_role_type_suffixes()
    if not role_type_suffixes:
        st.error("Could not fetch role type suffixes from metadata. Please ensure FUNCTIONAL_TECHNICAL_ROLE_METADATA table is properly configured.")
        return

    # --- Define widgets that control form structure OUTSIDE the form ---
    env = st.selectbox(
        "Target Environment for Role", 
        environments, 
        key="cr_env_outer",  # Ensure unique key if similar widget exists elsewhere
        help="Environment prefix for the role name and its owner."
    )
    role_type = st.selectbox(
        "Select Role Type", 
        [FUNCTIONAL_ROLE, TECHNICAL_ROLE], 
        key="cr_role_type_outer", 
        help="Select if this is a Functional or Technical role."
    )

    # Fetch function names based on role type selected outside the form
    func_options = get_function_names(role_type) if role_type else []

    custom_prefix = st.text_input(
        "Optional: Enter Custom Prefix (e.g., MARKETING, FINANCE)",
        key="cr_custom_prefix_outer",
        help="If provided, this will be added as a prefix to the selected Function/Area (e.g., MARKETING_ANALYTICS)"
    ).strip().upper().replace(" ", "_")

    func_name_input = st.selectbox(
        f"Choose {role_type} Function/Area for Role Name",
        func_options,
        key="cr_func_name_outer",
        help="Select the base function/area. Will be combined with prefix if provided."
    )
    
    # For display purposes only - determined by selections outside the form
    display_func_name = f"{custom_prefix}_{func_name_input}" if custom_prefix and func_name_input else func_name_input
    suffix = role_type_suffixes[0] if role_type == FUNCTIONAL_ROLE else role_type_suffixes[1] if len(role_type_suffixes) > 1 else "FR" if role_type == FUNCTIONAL_ROLE else "TR"
    # Fix: Don't add an extra underscore when appending the suffix since the suffix already includes an underscore
    display_role_name = f"{env}_{display_func_name}{suffix}".upper() if env and display_func_name else ""
   
    if display_role_name:
        st.caption(f"Generated Role Name Preview: `{display_role_name}`")
    else:
        st.caption("Role name will be generated based on selections (Environment, Function/Area).")

    # Access Type Selection - Placed OUTSIDE the form
    access_type = st.radio(
        "Select Access Type for the New Role",
        ("Database Level Access", "Grant to Existing Role", "Create Role - No Access"),
        key="cr_access_type_outer", # Unique key
        horizontal=True,
        help="Choose how this new role will be configured and what grants it will have initially."
    )
    # You can remove the DEBUG st.write for access_type now or keep it for testing

    # Move database and schema selection outside the form for better responsiveness
    selected_db_in_form = None
    selected_schema_in_form = None
    access_scope = "Database Level"
    
    if access_type == "Database Level Access":
        st.markdown("#### Database Access Configuration")
        if env and all_databases:
            relevant_databases = [db for db in all_databases if db.startswith(f"{env}_") or env in db or "COMMON" in db.upper()]
            if not relevant_databases and all_databases:
                relevant_databases = all_databases
        else:
            relevant_databases = all_databases if all_databases else []

        # Initialize session state for database selection if needed
        if 'cr_selected_db' not in st.session_state and relevant_databases:
            st.session_state.cr_selected_db = relevant_databases[0]
            
        # Database selection outside the form
        selected_db_in_form = st.selectbox(
            "Select Database for Privilege Grant",
            relevant_databases,
            key="cr_selected_db",
            help="The database to which this new role will be granted access via a database role."
        )
        
        # Access scope selection outside the form
        access_scope = st.radio(
            "Select Access Scope",
            ["Database Level", "Schema Level"],
            key="cr_access_scope",
            horizontal=True,
            help="Choose whether to grant access at database level or schema level"
        )
        
        # Schema selection if schema level access is selected (outside the form)
        if access_scope == "Schema Level" and selected_db_in_form:
            try:
                schemas = get_database_schemas(selected_db_in_form)
                
                if not schemas:
                    schemas = ["PUBLIC"]
                    st.warning(f"No schemas found in database '{selected_db_in_form}'. Using 'PUBLIC' as default.")
                
                # Initialize session state for schema selection
                if 'cr_selected_schema' not in st.session_state or st.session_state.cr_selected_schema not in schemas:
                    st.session_state.cr_selected_schema = schemas[0]
                
                selected_schema_in_form = st.selectbox(
                    "Select Schema",
                    options=schemas,
                    key="cr_selected_schema",
                    help="Choose the schema to grant access to"
                )
                
                # Show additional info about schema roles
                if selected_schema_in_form:
                    st.info(f"Schema-level role format: `{selected_db_in_form}.{selected_schema_in_form}_<ROLE_SUFFIX>`")
            except Exception as e:
                st.error(f"Error loading schemas: {e}")
                schemas = ["PUBLIC"]
                selected_schema_in_form = "PUBLIC"
                st.info("Using 'PUBLIC' as the default schema")
    
    # Set up access level selection BEFORE the form
    if access_type == "Database Level Access":
        # Get access role suffixes from metadata
        access_role_suffixes = get_access_role_suffixes()
        if not access_role_suffixes:
            st.error("Failed to fetch access role suffixes from metadata. Please ensure the ACCESS_PROFILES table is properly configured.")
            return

        # Create dynamic access level map based on metadata
        access_level_map = {
            f"Access Level {suffix}": suffix
            for suffix in access_role_suffixes
        }
        
        # Display appropriate label based on access scope
        if access_scope == "Schema Level":
            access_level_label = "Select Access Level to Grant on Schema"
            access_level_help = f"This maps to a pre-defined schema role (e.g., {selected_db_in_form}.{selected_schema_in_form}_<SUFFIX>)."
        else:
            access_level_label = "Select Access Level to Grant on Database"
            access_level_help = f"This maps to a pre-defined database role (e.g., {selected_db_in_form}.<SUFFIX>)."
        
        # Initialize session state for access level if needed
        if access_level_key not in st.session_state:
            st.session_state[access_level_key] = list(access_level_map.keys())[0]
        
        # Initialize the update flag if not already set
        if 'preview_needs_update' not in st.session_state:
            st.session_state.preview_needs_update = True
            
        # Define a callback function to update when access level changes
        def on_access_level_change():
            # This will trigger when the access level changes
            st.session_state.preview_needs_update = True
            # For older Streamlit versions, use st.rerun() or simply rely on the session state change
            
        # Access level selection outside the form
        access_level_desc = st.selectbox(
            access_level_label,
            options=list(access_level_map.keys()),
            key=access_level_key,
            help=access_level_help,
            on_change=on_access_level_change
        )
    
    # --- Start of the form ---
    with st.form("create_role_form_inner"):
        # Variables to store form inputs
        selected_existing_role_for_grant_in_form = None
        
        if access_type == "Database Level Access":
            # Display the selected values inside the form (read-only)
            info_text = f"**Selected Database:** {selected_db_in_form}\n**Access Scope:** {access_scope}"
            
            if access_scope == "Schema Level" and selected_schema_in_form:
                info_text += f"\n**Selected Schema:** {selected_schema_in_form}"
                
                # Get current access level from session state or the selected value
                current_access_level = st.session_state.get(access_level_key, "")
                info_text += f"\n**Access Level:** {current_access_level}"
                
                st.info(info_text)

        elif access_type == "Grant to Existing Role":
            st.markdown("#### Grant to Existing Role Configuration")
            all_fr_tr_roles_df = get_functional_technical_roles() # This is fine to call here
            if not all_fr_tr_roles_df.empty:
                fr_tr_roles_list = all_fr_tr_roles_df['ROLE_NAME'].tolist()
                if display_role_name and display_role_name in fr_tr_roles_list: # display_role_name from outside
                    fr_tr_roles_list.remove(display_role_name)
                
                if fr_tr_roles_list: 
                    selected_existing_role_for_grant_in_form = st.selectbox(
                        "Select Existing Role to Grant This New Role To",
                        fr_tr_roles_list,
                        key="cr_existing_role_in_form",
                        help="The new role (once created) will be granted TO this selected existing role."
                    )
                else:
                    st.warning(f"No suitable existing Functional (_FR) or Technical (_TR) roles found to grant to (excluding '{display_role_name}' if it already exists).")
            else:
                st.warning("No existing Functional (_FR) or Technical (_TR) roles found in the system.")
        
        # Submit button inside the form
        submitted = st.form_submit_button("Submit Role Request")
    
    # Move preview section outside the form and after all selections for real-time updates
    preview_container = st.container()
    
    # For older Streamlit versions, we can't force a rerun programmatically
    # Just reset the flag for future use
    if st.session_state.get('preview_needs_update', False):
        st.session_state.preview_needs_update = False
        
    with preview_container:
        # Get current access level for display purposes
        current_access_level = st.session_state.get(access_level_key, "")
        # Remove the key parameter from the expander as it's not supported in this Streamlit version
        with st.expander("View Role Configuration Details", expanded=True):
            st.markdown("### Role Configuration Preview")
            details = {
                "Environment": env,
                "Role Type": role_type,
                "Custom Prefix": custom_prefix,
                "Base Function/Area": func_name_input,
                "Final Function Name": display_func_name,
                "Generated Role Name": display_role_name,
                "Selected Access Type": access_type
            }
            
            if access_type == "Database Level Access":
                details["Target Database (Full Name)"] = selected_db_in_form
                db_name_no_prefix_preview = None
                if selected_db_in_form:
                    db_parts_preview = selected_db_in_form.split('_', 1)
                    if len(db_parts_preview) > 1 and db_parts_preview[0].upper() == env.upper():
                        db_name_no_prefix_preview = db_parts_preview[1]
                    else:
                        db_name_no_prefix_preview = selected_db_in_form
                details["Target Database (Without Prefix)"] = db_name_no_prefix_preview if selected_db_in_form else "N/A"
                
                # Get the current selected access level directly from the session state
                # This ensures we always have the most up-to-date value
                current_access_level = st.session_state.get(access_level_key, "")
                
                # If somehow the access level isn't in session state, use the first option
                if not current_access_level and 'access_level_map' in locals():
                    current_access_level = list(access_level_map.keys())[0]
                    
                # Add to details dictionary
                details["Access Level Description"] = current_access_level
                
                # Get the role suffix based on the current access level
                access_role_suffix_preview = None
                if 'access_level_map' in locals() and current_access_level:
                    access_role_suffix_preview = access_level_map.get(current_access_level)
                
                # Add the role suffix to details for clarity
                details["Role Suffix"] = access_role_suffix_preview if access_role_suffix_preview else "N/A"
                
                # Add access scope and schema details
                details["Access Scope"] = access_scope
                
                if access_scope == "Schema Level" and selected_schema_in_form:
                    details["Selected Schema"] = selected_schema_in_form
                    if access_role_suffix_preview:
                        details["Implied Schema Role"] = f"{selected_db_in_form}.{selected_schema_in_form}_{access_role_suffix_preview}"
                elif access_role_suffix_preview:
                    details["Implied Database Role"] = f"{selected_db_in_form}.{access_role_suffix_preview}"
            elif access_type == "Grant to Existing Role":
                details["Grant New Role TO Existing Role"] = selected_existing_role_for_grant_in_form if selected_existing_role_for_grant_in_form else "N/A"
            
            for key, value in details.items():
                st.write(f"**{key}:** {value}")

    # Process form submission
    if 'submitted' in locals() and submitted:
        # Critical: Use the values from widgets outside the form for logic that depends on them
        # and values from inside the form (e.g., selected_db_in_form) for their specific parts.
        
        if not all([env, func_name_input, role_type]): # Values from outside
            st.warning("Please ensure Environment, Role Type, and Function/Area are selected to generate a role name.")
            return
        
        if not display_role_name: # Value from outside
            st.warning("Could not generate role name. Please check all selections.")
            return

        final_sql_command_for_log = ""
        success_messages = []
        log_message_details = ""

        try:
            if access_type == "Database Level Access": # access_type from outside
                # Now use the _in_form versions for these values
                db_name_no_prefix_submit = None
                if selected_db_in_form:
                    db_parts_submit = selected_db_in_form.split('_', 1)
                    db_name_no_prefix_submit = db_parts_submit[1] if len(db_parts_submit) > 1 and db_parts_submit[0].upper() == env.upper() else selected_db_in_form
                
                # Always use the most current access level from session state
                current_access_level = st.session_state.get(access_level_key, "")
                if not current_access_level and 'access_level_map' in locals():
                    current_access_level = list(access_level_map.keys())[0]
                access_role_suffix_submit = access_level_map.get(current_access_level)

                if not all([selected_db_in_form, access_role_suffix_submit, db_name_no_prefix_submit]):
                    st.warning("For 'Database Level Access', please select a database and access level.")
                    return
                
                # Check if schema level access is selected and validate schema
                is_schema_level = access_scope == "Schema Level"
                if is_schema_level and not selected_schema_in_form:
                    st.error("For 'Schema Level Access', please select a valid schema.")
                    st.info("If no schemas are available in the dropdown, you may need to create schemas in the database first or check your permissions.")
                    return
                
                # Create role with appropriate database or schema role
                if is_schema_level:
                    # For schema level access, we'll create the role and grant the schema role directly
                    # First create the role
                    sql_command_create_role = f"CREATE ROLE IF NOT EXISTS {display_role_name};"
                    session.sql(sql_command_create_role).collect()
                    success_messages.append(f"Successfully created role '{display_role_name}'.")
                    
                    # Then grant the schema role to the new role
                    schema_role = f"{selected_db_in_form}.{selected_schema_in_form}_{access_role_suffix_submit}"
                    sql_command_grant_schema_role = f"GRANT DATABASE ROLE {schema_role} TO ROLE {display_role_name};"
                    try:
                        session.sql(sql_command_grant_schema_role).collect()
                        success_messages.append(f"Successfully granted schema role '{schema_role}' TO role '{display_role_name}'.")
                    except Exception as e:
                        st.error(f"Error granting schema role: {str(e)}")
                        st.info("This might happen if the schema role doesn't exist. Make sure the schema was created with proper roles.")
                        return
                        
                    final_sql_command_for_log = f"{sql_command_create_role}\n{sql_command_grant_schema_role}"
                    log_message_details = f"Role '{display_role_name}' created with schema-level access to '{schema_role}'."
                else:
                    # For database level access, use the stored procedure as before
                    sp_name = get_fully_qualified_name(CONFIG["STORED_PROCEDURES"]["MANAGE_FUNCTIONAL_TECHNICAL_ROLES"])
                    # Use func_name_input, role_type, custom_prefix from OUTSIDE the form here
                    sql_command_sp = f"""
                    CALL {sp_name}(
                        '{env}',                     
                        '{func_name_input}',         
                        '{role_type}',               
                        '{db_name_no_prefix_submit}', 
                        '{access_role_suffix_submit}',
                        '{custom_prefix}'            
                    )
                    """
                    final_sql_command_for_log = sql_command_sp
                    session.sql(sql_command_sp).collect()
                    
                    success_messages.append(f"Successfully processed request for role '{display_role_name}' with '{current_access_level}' on database '{selected_db_in_form}'.")
                    log_message_details = f"Role '{display_role_name}' configured with {access_role_suffix_submit} access to DB '{selected_db_in_form}' (logical name: {db_name_no_prefix_submit}) via SP."
                
                # Grant the new role to <ENV>_USERADMIN for visibility (for both database and schema level)
                account_role_owner = get_env_role_for_ownership('OWNS_ACCOUNT_ROLES').replace('<ENV>', env)
                sql_command_grant_to_useradmin = f"GRANT ROLE {display_role_name} TO ROLE {account_role_owner};"
                try:
                    session.sql(sql_command_grant_to_useradmin).collect()
                    success_messages.append(f"Successfully granted role '{display_role_name}' TO '{account_role_owner}' for visibility.")
                    final_sql_command_for_log = f"{final_sql_command_for_log}\n{sql_command_grant_to_useradmin}"
                    log_message_details += f" Granted to '{account_role_owner}'." + (f" (Custom Prefix: {custom_prefix})" if custom_prefix else "")
                except Exception as e:
                    st.warning(f"Role created but could not grant to {account_role_owner}: {str(e)}")

            elif access_type == "Grant to Existing Role": # access_type from outside
                if not selected_existing_role_for_grant_in_form: # _in_form version
                    st.warning("For 'Grant to Existing Role', please select an existing role to grant the new role to within the form.")
                    return

                # display_role_name is from outside
                sql_command_create_role = f"CREATE ROLE IF NOT EXISTS {display_role_name};"
                session.sql(sql_command_create_role).collect()
                success_messages.append(f"Successfully created role '{display_role_name}'.")
                
                sql_command_grant_to_existing = f"GRANT ROLE {display_role_name} TO ROLE {selected_existing_role_for_grant_in_form};"
                session.sql(sql_command_grant_to_existing).collect()
                success_messages.append(f"Successfully granted role '{display_role_name}' TO role '{selected_existing_role_for_grant_in_form}'.")
                
                # Grant the new role to <ENV>_USERADMIN for visibility
                account_role_owner = get_env_role_for_ownership('OWNS_ACCOUNT_ROLES').replace('<ENV>', env)
                sql_command_grant_to_useradmin = f"GRANT ROLE {display_role_name} TO ROLE {account_role_owner};"
                try:
                    session.sql(sql_command_grant_to_useradmin).collect()
                    success_messages.append(f"Successfully granted role '{display_role_name}' TO '{account_role_owner}' for visibility.")
                except Exception as e:
                    st.warning(f"Role created but could not grant to {account_role_owner}: {str(e)}")
                
                final_sql_command_for_log = f"{sql_command_create_role}\n{sql_command_grant_to_existing}\n{sql_command_grant_to_useradmin}"
                log_message_details = f"Role '{display_role_name}' created and then granted TO role '{selected_existing_role_for_grant_in_form}' and '{account_role_owner}'." + \
                                      (f" (Custom Prefix: {custom_prefix})" if custom_prefix else "") # custom_prefix from outside

            elif access_type == "Create Role - No Access": # access_type from outside
                # display_role_name is from outside
                sql_command_create_role = f"CREATE ROLE IF NOT EXISTS {display_role_name};"
                session.sql(sql_command_create_role).collect()
                success_messages.append(f"Successfully created role '{display_role_name}' with no initial access grants.")
                
                # Grant the new role to <ENV>_USERADMIN for visibility
                account_role_owner = get_env_role_for_ownership('OWNS_ACCOUNT_ROLES').replace('<ENV>', env)
                sql_command_grant_to_useradmin = f"GRANT ROLE {display_role_name} TO ROLE {account_role_owner};"
                try:
                    session.sql(sql_command_grant_to_useradmin).collect()
                    success_messages.append(f"Successfully granted role '{display_role_name}' TO '{account_role_owner}' for visibility.")
                except Exception as e:
                    st.warning(f"Role created but could not grant to {account_role_owner}: {str(e)}")
                
                final_sql_command_for_log = f"{sql_command_create_role}\n{sql_command_grant_to_useradmin}"
                log_message_details = f"Role '{display_role_name}' created with no specific access grants and granted to '{account_role_owner}'." + \
                                     (f" (Custom Prefix: {custom_prefix})" if custom_prefix else "") # custom_prefix from outside

            st.success("\n".join(success_messages))
            log_audit_event(
                "CREATE_ROLE_ACTION", 
                display_role_name, # From outside
                final_sql_command_for_log,
                "SUCCESS",
                f"Access Type: {access_type}. Details: {log_message_details}" # access_type from outside
            )
            st.cache_data.clear() 
            
        except Exception as e:
            error_message = str(e)
            st.error(f"Error during role operation: {error_message}")
            log_audit_event(
                "CREATE_ROLE_ACTION_ERROR",
                display_role_name, # From outside
                final_sql_command_for_log if final_sql_command_for_log else "Failed before SQL execution",
                "ERROR",
                f"Access Type: {access_type}. Error: {error_message}" + (f" (Custom Prefix: {custom_prefix})" if custom_prefix else "") # access_type, custom_prefix from outside
            )

# --- Role Hierarchy Visualization Functions ---
@st.cache_data(ttl=900) # Cache for 15 mins due to potential latency of ACCOUNT_USAGE
@st.cache_data(ttl=900) # Cache for 15 mins due to potential latency of ACCOUNT_USAGE
def get_all_role_grants_df():
    """
    Fetches all active role-to-role grants from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES.
    Returns a Pandas DataFrame with 'PARENT_ROLE' and 'CHILD_ROLE' columns.
    PARENT_ROLE -> CHILD_ROLE indicates that PARENT_ROLE inherits permissions from CHILD_ROLE.
    """
    try:
        # GRANTEE_NAME is the role that receives the grant (the parent in hierarchy)
        # NAME is the role that is granted (the child in hierarchy)
        query = """
            SELECT
                GRANTEE_NAME AS PARENT_ROLE,
                NAME AS CHILD_ROLE
            FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
            WHERE
                PRIVILEGE = 'USAGE'           -- This indicates a role grant
                AND GRANTED_ON = 'ROLE'       -- The object being granted is a role
                AND GRANTED_TO = 'ROLE'       -- The grantee is also a role
                AND DELETED_ON IS NULL        -- Only consider active grants
        """
        grants_snowpark_df = session.sql(query)
        return grants_snowpark_df.to_pandas() if grants_snowpark_df and grants_snowpark_df.count() > 0 else pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE'])
    except Exception as e:
        st.error(f"Error fetching full role hierarchy from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES: {e}")
        st.info("Please ensure the application role has access (e.g., via `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <app_role>;`). Note that ACCOUNT_USAGE views can have data latency.")
        return pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE'])

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_all_roles():
    """Fetches all role names in the current account."""
    try:
        roles_df = session.sql("""
            SELECT DISTINCT NAME 
            FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES 
            WHERE DELETED_ON IS NULL 
            ORDER BY NAME
        """).collect()
        # Fix: Use uppercase 'NAME' to match the column name from Snowflake
        return sorted([role["NAME"] for role in roles_df if role["NAME"]])
    except Exception as e:
        st.error(f"Error fetching roles: {e}")
        return []

def extract_sub_hierarchy(full_grants_df: pd.DataFrame, selected_role_name: str, depth: int = 3):
    """
    Extracts a sub-hierarchy (ancestors and descendants) around selected_role_name
    from the full grants DataFrame up to a specified depth.
    Returns a DataFrame of edges and a set of all nodes in the sub-hierarchy.
    """
    if full_grants_df.empty:
        return pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE']), {selected_role_name}
   
    # Check if selected role exists in the grant data at all
    all_roles_in_grants = set(full_grants_df['PARENT_ROLE']).union(set(full_grants_df['CHILD_ROLE']))
    if selected_role_name not in all_roles_in_grants:
        return pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE']), {selected_role_name}

    sub_hierarchy_edges = set()
    nodes_in_subgraph = {selected_role_name}

    # Get Ancestors (roles that grant to selected_role, and their parents, etc. - BFS upwards)
    q = [(selected_role_name, 0)]  # (role, current_depth)
    visited_ancestors = {selected_role_name}
    head = 0
    while head < len(q):
        curr_role, d = q[head]; head += 1
        if d >= depth: continue
       
        # Find roles that grant to curr_role (i.e., curr_role is their child)
        parents_of_curr_df = full_grants_df[full_grants_df['CHILD_ROLE'] == curr_role]
        for _, row in parents_of_curr_df.iterrows():
            ancestor_role = row['PARENT_ROLE']
            sub_hierarchy_edges.add((ancestor_role, curr_role))
            nodes_in_subgraph.add(ancestor_role)
            if ancestor_role not in visited_ancestors:
                visited_ancestors.add(ancestor_role)
                q.append((ancestor_role, d + 1))

    # Get Descendants (roles that selected_role grants to, and their children, etc. - BFS downwards)
    q = [(selected_role_name, 0)]
    visited_descendants = {selected_role_name}
    head = 0
    while head < len(q):
        curr_role, d = q[head]; head += 1
        if d >= depth: continue

        # Find roles that curr_role grants to (i.e., curr_role is their parent)
        children_of_curr_df = full_grants_df[full_grants_df['PARENT_ROLE'] == curr_role]
        for _, row in children_of_curr_df.iterrows():
            descendant_role = row['CHILD_ROLE']
            sub_hierarchy_edges.add((curr_role, descendant_role))
            nodes_in_subgraph.add(descendant_role)
            if descendant_role not in visited_descendants:
                visited_descendants.add(descendant_role)
                q.append((descendant_role, d + 1))
   
    if not sub_hierarchy_edges:
        return pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE']), nodes_in_subgraph

    sub_df_from_edges = pd.DataFrame(list(sub_hierarchy_edges), columns=['PARENT_ROLE', 'CHILD_ROLE'])
    return sub_df_from_edges, nodes_in_subgraph

def generate_graphviz_dot(grants_df: pd.DataFrame, title: str = "Role Hierarchy", selected_role_name: str = None, highlighted_nodes: set = None):
    """Generates a Graphviz DOT string from the grants DataFrame."""
   
    # Determine if we should use dark mode colors
    # We'll set colors that work well in both light and dark mode
    # with better contrast for dark mode
    dot_lines = [
        'digraph RoleHierarchy {',
        '  rankdir="TB";',
        '  overlap="false";',
        '  splines="true";',
        '  nodesep="0.5";',
        '  ranksep="0.75";',
        '  labelloc="t";',
        '  bgcolor="#1E1E1E";',  # Solid background color for visibility
        f'  label="{title}";',
        '  fontsize=20;',
        '  fontcolor="#FFFFFF";',  # White text for dark mode
        '  node [shape=box, style="rounded,filled", fillcolor="#3498DB", fontname="Arial", fontsize=10, fontcolor="#FFFFFF", color="#555555", height=0.3, width=1.5];',
        '  edge [fontname="Arial", fontsize=9, arrowsize=0.7, color="#AAAAAA"];'
    ]
   
    # Determine all unique nodes involved
    all_nodes_in_edges = set(grants_df['PARENT_ROLE']).union(set(grants_df['CHILD_ROLE']))
   
    # Ensure all nodes to be shown are defined
    nodes_to_define = all_nodes_in_edges
    if highlighted_nodes:
        nodes_to_define = highlighted_nodes
    elif selected_role_name and not grants_df.empty:
        nodes_to_define.add(selected_role_name)
    elif selected_role_name and grants_df.empty:
        nodes_to_define = {selected_role_name}

    if not nodes_to_define and grants_df.empty:
        dot_lines.append('  info_node [label="No role hierarchy data to display or role is isolated.", shape=plaintext, fontsize=12];')

    # Define nodes with specific styling
    for node in sorted(list(nodes_to_define)):
        node_label = node.replace("_", "\\n")
        if node == selected_role_name:
            # Selected role gets a bright gold color with dark text for high contrast
            dot_lines.append(f'  "{node}" [label="{node_label}", fillcolor="#F1C40F", shape=ellipse, style="filled,bold", fontcolor="#000000", penwidth=2.0];')
        elif highlighted_nodes and node in highlighted_nodes:
            # Highlighted nodes get a bright teal color for better visibility in dark mode
            dot_lines.append(f'  "{node}" [label="{node_label}", fillcolor="#1ABC9C", fontcolor="#FFFFFF", style="filled", penwidth=1.5];')
        else:
            # Default nodes use the base styling defined above but with more contrast
            dot_lines.append(f'  "{node}" [label="{node_label}", fillcolor="#3498DB"];')

    # Define edges
    for _, row in grants_df.iterrows():
        parent = row['PARENT_ROLE']
        child = row['CHILD_ROLE']
        if parent in nodes_to_define and child in nodes_to_define:
            dot_lines.append(f'  "{parent}" -> "{child}";')
   
    dot_lines.append('}')
    return "\n".join(dot_lines)

def ui_show_role_hierarchy():
    """UI for showing role hierarchy DAGs."""
    st.header("Show Role Hierarchy")
    st.info("Role hierarchy data is sourced from `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES`. This view can have a data latency (typically up to 2 hours). Newly created roles or grant changes might not appear immediately.")

    view_type = st.radio(
        "Select Hierarchy View Type:",
        ("View Full Account Hierarchy", "View Specific Role Hierarchy"),
        key="role_hierarchy_view_type",
        horizontal=True
    )

    full_grants_df = get_all_role_grants_df()

    if view_type == "View Full Account Hierarchy":
        st.subheader("Full Account Role Hierarchy DAG")
        if full_grants_df.empty:
            st.warning("No role grant data found in `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES` or an error occurred during fetching.")
        else:
            with st.spinner("Generating full hierarchy graph... This may take a moment for large accounts."):
                graph_title = f"Full Account Role Hierarchy"
                all_display_roles = sorted(list(set(full_grants_df['PARENT_ROLE']).union(set(full_grants_df['CHILD_ROLE']))))
                role_to_highlight_full = st.selectbox("Optionally highlight a role in the full graph:", ["None"] + all_display_roles, key="highlight_role_full")
               
                dot_string = generate_graphviz_dot(
                    full_grants_df, 
                    title=graph_title, 
                    selected_role_name=(role_to_highlight_full if role_to_highlight_full != "None" else None)
                )
                try:
                    st.graphviz_chart(dot_string, use_container_width=True)
                except Exception as e:
                    st.error(f"Could not render graph. Graphviz might have issues with very large graphs or specific characters. Error: {e}")
                    st.text_area("Graphviz DOT Source (for debugging)", dot_string, height=300)

            with st.expander("View Raw Grant Data (Full Hierarchy)"):
                st.dataframe(full_grants_df, hide_index=True)

    elif view_type == "View Specific Role Hierarchy":
        st.subheader("Specific Role Hierarchy DAG")
        all_system_roles = get_all_roles()
        if not all_system_roles:
            st.warning("No roles found in the system or error fetching roles. Cannot select a specific role.")
            return

        col_select, col_depth = st.columns([3,1])
        with col_select:
            default_role_index = all_system_roles.index("PUBLIC") if "PUBLIC" in all_system_roles else 0
            selected_role = st.selectbox(
                "Select a Role to View its Hierarchy:",
                options=all_system_roles,
                index=default_role_index,
                key="selected_role_for_hierarchy"
            )
        with col_depth:
            depth = st.number_input("Traversal Depth (levels up/down):", min_value=1, max_value=10, value=2, key="role_hierarchy_depth")

        if selected_role:
            if full_grants_df.empty and selected_role not in get_all_role_grants_df():
                st.warning(f"Role grant data (`ACCOUNT_USAGE.GRANTS_TO_ROLES`) is unavailable or role '{selected_role}' has no grants. Cannot extract specific hierarchy accurately. Please check permissions or data latency.")
                return

            with st.spinner(f"Generating hierarchy for role '{selected_role}' with depth {depth}..."):
                sub_hierarchy_df, nodes_in_subgraph = extract_sub_hierarchy(full_grants_df, selected_role, depth)
                graph_title = f"Hierarchy for Role: {selected_role} (Depth: {depth})"

                if sub_hierarchy_df.empty and selected_role in nodes_in_subgraph:
                    st.info(f"Role '{selected_role}' is isolated or has no grant relationships within the specified depth based on `ACCOUNT_USAGE` data.")
                    dot_string = generate_graphviz_dot(
                        pd.DataFrame(columns=['PARENT_ROLE', 'CHILD_ROLE']), 
                        title=graph_title, 
                        selected_role_name=selected_role, 
                        highlighted_nodes={selected_role}
                    )
                elif not nodes_in_subgraph:
                    st.warning(f"Could not find role '{selected_role}' in the grant data.")
                    return
                else:
                    dot_string = generate_graphviz_dot(
                        sub_hierarchy_df, 
                        title=graph_title, 
                        selected_role_name=selected_role, 
                        highlighted_nodes=nodes_in_subgraph
                    )
               
                try:
                    st.graphviz_chart(dot_string, use_container_width=True)
                except Exception as e:
                    st.error(f"Could not render graph. Error: {e}")
                    st.text_area("Graphviz DOT Source (for debugging)", dot_string, height=300)

                with st.expander(f"View Raw Grant Data for '{selected_role}' Sub-Hierarchy (Depth: {depth})"):
                    if sub_hierarchy_df.empty:
                        st.write(f"No direct grant relationships found for '{selected_role}' in the sub-graph within this depth.")
                    else:
                        st.dataframe(sub_hierarchy_df, hide_index=True)
                    st.write("Nodes considered in this sub-graph:", sorted(list(nodes_in_subgraph)))


def ui_display_rbac_architecture():
    """UI for displaying RBAC architecture diagram."""
    st.header("RBAC Architecture")
    st.image("TMHCC RBAC Design.png", use_container_width=True)
    st.download_button(
        label="Download RBAC Architecture Diagram",
        data=open("TMHCC RBAC Design.png", "rb").read(),
        file_name="TMHCC RBAC Design.png",
        mime="image/png"
    )

def ui_manage_metadata():
    """UI for managing metadata tables with inline editing and composite key handling."""
    st.header("Manage Metadata")
   
    metadata_tables_query = """
    SELECT table_name
    FROM SECURITY_UNDER_DEVELOPMENT.information_schema.tables
    WHERE table_schema = 'ACCESS_CONTROL'
    AND table_name LIKE '%METADATA'
    """
    metadata_tables = session.sql(metadata_tables_query).collect()
    table_names = [row['TABLE_NAME'] for row in metadata_tables]
   
    selected_table = st.selectbox("Select Metadata Table", table_names)
   
    if selected_table:
        # Fetch current data
        table_data = session.table(f"SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.{selected_table}").collect()
        df = pd.DataFrame(table_data)
        
        if df.empty:
            st.warning(f"No data found in {selected_table}")
            return

        # Define key columns
        key_columns = ['ACCESS_CODE', 'ROLE_SUFFIX', 'OBJECT_TYPE']
        
        st.subheader("Current Data")
        
        # Create two columns
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Convert DataFrame to editable format
            edited_df = st.data_editor(
                df,
                num_rows="dynamic",
                key=f"editor_{selected_table}",
                use_container_width=True,
                hide_index=True,
                column_config={
                    # Make key columns more visible and required
                    "ACCESS_CODE": st.column_config.TextColumn(
                        "ACCESS_CODE",
                        help="Part of composite key",
                        required=True,
                        width="medium"
                    ),
                    "ROLE_SUFFIX": st.column_config.TextColumn(
                        "ROLE_SUFFIX",
                        help="Part of composite key",
                        required=True,
                        width="medium"
                    ),
                    "OBJECT_TYPE": st.column_config.TextColumn(
                        "OBJECT_TYPE",
                        help="Part of composite key",
                        required=True,
                        width="medium"
                    )
                }
            )
        
        with col2:
            # Add controls for the edited data
            if st.button("Save Changes", key="save_changes"):
                try:
                    # Function to create composite key
                    def get_composite_key(row):
                        return tuple(str(row[col]).upper() for col in key_columns)

                    # Create sets of composite keys for comparison
                    original_keys = {get_composite_key(row) for _, row in df.iterrows()}
                    edited_keys = {get_composite_key(row) for _, row in edited_df.iterrows()}

                    # Check for duplicate keys in edited data
                    edited_key_counts = edited_df.groupby([col.upper() for col in key_columns]).size()
                    if (edited_key_counts > 1).any():
                        st.error("Duplicate composite keys found. Each combination of ACCESS_CODE, ROLE_SUFFIX, and OBJECT_TYPE must be unique.")
                        return

                    # Process updates and inserts
                    for index, row in edited_df.iterrows():
                        current_key = get_composite_key(row)
                        
                        # Create WHERE clause for composite key
                        where_clause = " AND ".join([
                            f"{col} = '{str(row[col]).upper()}'"
                            for col in key_columns
                        ])

                        # Check if this is a new record
                        if current_key not in original_keys:
                            # This is a new record
                            columns = ", ".join(row.index)
                            values = ", ".join([f"'{str(v).upper() if col in key_columns else str(v)}'" 
                                             for col, v in row.items()])
                            sql_command = f"""
                                INSERT INTO ACCESS_CONTROL.{selected_table} 
                                ({columns}) VALUES ({values})
                            """
                            
                            session.sql(sql_command).collect()
                            log_audit_event(
                                "ADD_METADATA", 
                                selected_table, 
                                sql_command, 
                                "SUCCESS", 
                                f"Added new record with key: {current_key}"
                            )
                        else:
                            # Find original row for comparison
                            original_row = df[
                                df[key_columns].apply(
                                    lambda x: tuple(str(v).upper() for v in x) == current_key, 
                                    axis=1
                                )
                            ].iloc[0]

                            # Check if row was modified
                            if not row.equals(original_row):
                                # Create update statement for modified columns
                                updates = []
                                for col in df.columns:
                                    if str(row[col]) != str(original_row[col]):
                                        updates.append(f"{col} = '{str(row[col])}'")
                                
                                if updates:
                                    set_clause = ", ".join(updates)
                                    sql_command = f"""
                                        UPDATE ACCESS_CONTROL.{selected_table} 
                                        SET {set_clause} 
                                        WHERE {where_clause}
                                    """
                                    
                                    session.sql(sql_command).collect()
                                    log_audit_event(
                                        "UPDATE_METADATA", 
                                        selected_table, 
                                        sql_command, 
                                        "SUCCESS", 
                                        f"Updated record with key: {current_key}"
                                    )

                    # Handle deletions
                    deleted_keys = original_keys - edited_keys
                    for deleted_key in deleted_keys:
                        where_clause = " AND ".join([
                            f"{col} = '{val}'"
                            for col, val in zip(key_columns, deleted_key)
                        ])
                        
                        sql_command = f"""
                            DELETE FROM ACCESS_CONTROL.{selected_table} 
                            WHERE {where_clause}
                        """
                        session.sql(sql_command).collect()
                        log_audit_event(
                            "DELETE_METADATA", 
                            selected_table, 
                            sql_command, 
                            "SUCCESS", 
                            f"Deleted record with key: {deleted_key}"
                        )

                    st.success("Changes saved successfully!")
                    # Refresh the page to show updated data
                    st.rerun()
                    
                except Exception as e:
                    st.error(f"Error saving changes: {e}")
                    log_audit_event(
                        "UPDATE_METADATA", 
                        selected_table, 
                        "BATCH_UPDATE", 
                        "ERROR", 
                        str(e)
                    )
            
            # Add a refresh button
            if st.button("Refresh Data", key="refresh_data"):
                st.rerun()
            
            # Add help text
            st.markdown("""
            ### How to use:
            1. Double-click any cell to edit
            2. Add new rows using the + button
            3. Delete rows using the X button
            4. Click 'Save Changes' when done
            5. Use 'Refresh Data' to reload
            
            ### Note:
            - ACCESS_CODE, ROLE_SUFFIX, and OBJECT_TYPE together form a unique key
            - These fields are required and case-insensitive
            - Duplicate combinations are not allowed
            """)
            
            # Add metadata about the table
            st.markdown("### Table Info")
            st.markdown(f"""
            - **Total Records:** {len(df)}
            - **Columns:** {len(df.columns)}
            - **Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """)

def ui_create_environment_roles():
    """UI for creating environment roles and establishing role mappings."""
    st.header("Create Environment Roles")
   
    st.info("""
    This action creates environment-specific account roles as defined in the ENVIRONMENT_ROLE_METADATA table. Roles and parent mappings are fully metadata-driven.
    Review ENVIRONMENT_ROLE_METADATA in Manage Metadata for the current configuration.
    """)

    with st.form("create_env_roles_form"):
        environments = get_environments()
       
        if not environments:
            st.error("No environments found in the ENVIRONMENTS table.")
            return
           
        selected_env = st.selectbox(
            "Select Environment",
            environments,
            help="Select the environment to create roles for"
        )
       
        confirm = st.checkbox(
            f"I confirm I want to create and map roles for environment: {selected_env}",
            help="This will create three new roles and map them to system roles"
        )
       
        submitted = st.form_submit_button("Create Environment Roles")
       
        if submitted:
            if not confirm:
                st.warning("Please confirm the action by checking the confirmation box.")
                return
               
            try:
                sp_name = get_fully_qualified_name(CONFIG["STORED_PROCEDURES"]["DATABASE_CONTROLLER"])
                sql_command = f"CALL {sp_name}('{selected_env}')"
                session.sql(sql_command).collect()
               
                log_audit_event(
                    "CREATE_ENVIRONMENT_ROLES",
                    f"{selected_env}_ROLES",
                    sql_command,
                    "SUCCESS",
                    f"Created and mapped environment roles for {selected_env}"
                )
               
                st.success(f"""
                Successfully created and mapped the following roles for environment '{selected_env}':
                Roles created per ENVIRONMENT_ROLE_METADATA configuration.

                """)
               
                st.cache_data.clear()
               
            except Exception as e:
                st.error(f"Failed to create environment roles: {e}")
                log_audit_event(
                    "CREATE_ENVIRONMENT_ROLES",
                    f"{selected_env}_ROLES",
                    sql_command,
                    "ERROR",
                    str(e)
                )
def ui_audit_logs():
    """Enhanced UI for displaying audit logs with interactive and aesthetic charts."""
    st.header("Audit Logs Dashboard")
    
    # Dark mode styling for metrics and containers
    st.markdown("""
        <style>
        /* PRISM Adaptive Theme - works with both light and dark mode */
        
        /* Remove forced backgrounds - let Streamlit native theme work */
        [data-testid="stSidebar"] {
            padding: 1rem;
        }
        
        /* Sidebar section structure */
        .sidebar-section {
            margin-bottom: 1.5rem;
        }
        .sidebar-section-title {
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            opacity: 0.6;
            margin-bottom: 0.5rem;
            padding-bottom: 0.4rem;
            border-bottom: 1px solid rgba(128,128,128,0.2);
        }
        
        /* Info cards - adaptive */
        .sidebar-info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin: 0.35rem 0;
            padding: 0.5rem 0.7rem;
            background: rgba(128,128,128,0.08);
            border-radius: 6px;
            border: 1px solid rgba(128,128,128,0.12);
        }
        .sidebar-info-label {
            font-size: 0.8rem;
            opacity: 0.6;
        }
        .sidebar-info-value {
            font-weight: 600;
            font-size: 0.85rem;
        }
        
        /* Logo card - works on both modes */
        .logo-card {
            background: rgba(255,255,255,0.92);
            border-radius: 8px;
            padding: 12px 16px;
            margin-bottom: 1rem;
            text-align: center;
            border: 1px solid rgba(128,128,128,0.1);
        }
        @media (prefers-color-scheme: dark) {
            .logo-card {
                background: rgba(255,255,255,0.95);
            }
        }
        
        /* PRISM title in sidebar */
        .prism-title {
            font-size: 1.4rem;
            font-weight: 700;
            letter-spacing: 0.15em;
            margin: 0.5rem 0 0.2rem 0;
        }
        .prism-subtitle {
            font-size: 0.65rem;
            opacity: 0.5;
            letter-spacing: 0.03em;
            margin-bottom: 1rem;
        }
        
        /* Clean button styling */
        [data-testid="stSidebar"] .stButton button {
            background: rgba(128,128,128,0.06);
            border: 1px solid rgba(128,128,128,0.15);
            border-radius: 6px;
            padding: 0.4rem 0.8rem;
            font-size: 0.85rem;
            transition: all 0.15s ease;
            text-align: left;
        }
        [data-testid="stSidebar"] .stButton button:hover {
            background: rgba(128,128,128,0.12);
            border-color: rgba(128,128,128,0.25);
        }
        
        /* Version footer */
        .version-footer {
            font-size: 0.7rem;
            opacity: 0.4;
            text-align: center;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid rgba(128,128,128,0.15);
        }
        </style>
    """, unsafe_allow_html=True)

    # Date range selector
    st.markdown("### 📅 Select Date Range")
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=datetime.now() - timedelta(days=30),
            help="Select start date for audit log analysis"
        )
    with col2:
        end_date = st.date_input(
            "End Date",
            value=datetime.now(),
            help="Select end date for audit log analysis"
        )

    # Convert dates to timestamps for Snowflake query
    start_ts = datetime.combine(start_date, datetime.min.time())
    end_ts = datetime.combine(end_date, datetime.max.time())

    # Fetch audit log data
    query = f"""
    SELECT 
        EVENT_ID,
        EVENT_TIME,
        INVOKED_BY,
        EVENT_TYPE,
        OBJECT_NAME,
        SQL_COMMAND,
        STATUS,
        MESSAGE
    FROM {AUDIT_LOG_TABLE}
    WHERE EVENT_TIME BETWEEN '{start_ts}' AND '{end_ts}'
    ORDER BY EVENT_TIME DESC
    """

    try:
        df = session.sql(query).to_pandas()
        
        if df.empty:
            st.warning("No audit logs found for the selected date range.")
            return

        # Function to simplify event types
        def simplify_event_type(event_type):
            parts = event_type.split('_')
            return '_'.join(parts[:2]) if len(parts) > 1 else event_type

        # Create simplified event type column
        df['SIMPLIFIED_EVENT'] = df['EVENT_TYPE'].apply(simplify_event_type)

        # Create tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Overview", 
            "📈 Event Analysis", 
            "👥 User Activity", 
            "📝 Detailed Logs"
        ])

        with tab1:
            st.subheader("📊 Audit Overview")
            
            # Metrics display
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_events = len(df)
                st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-value">{total_events:,}</div>
                        <div class="metric-label">Total Events</div>
                    </div>
                """, unsafe_allow_html=True)

            with col2:
                success_rate = (df['STATUS'] == 'SUCCESS').mean() * 100
                st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-value">{success_rate:.1f}%</div>
                        <div class="metric-label">Success Rate</div>
                    </div>
                """, unsafe_allow_html=True)

            with col3:
                unique_users = df['INVOKED_BY'].nunique()
                st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-value">{unique_users}</div>
                        <div class="metric-label">Unique Users</div>
                    </div>
                """, unsafe_allow_html=True)

            with col4:
                unique_events = df['SIMPLIFIED_EVENT'].nunique()
                st.markdown(f"""
                    <div class="metric-container">
                        <div class="metric-value">{unique_events}</div>
                        <div class="metric-label">Event Types</div>
                    </div>
                """, unsafe_allow_html=True)

            # Event Timeline
            st.markdown("### 📈 Event Timeline")
            df['DATE'] = pd.to_datetime(df['EVENT_TIME']).dt.date
            daily_events = df.groupby(['DATE', 'STATUS']).size().unstack(fill_value=0)
            
            fig = go.Figure()
            
            if 'SUCCESS' in daily_events.columns:
                fig.add_trace(go.Scatter(
                    x=daily_events.index,
                    y=daily_events['SUCCESS'],
                    name='Success',
                    line=dict(width=2, color='#2ECC71'),
                    fill='tozeroy',
                    fillcolor='rgba(46, 204, 113, 0.1)'
                ))
            
            if 'ERROR' in daily_events.columns:
                fig.add_trace(go.Scatter(
                    x=daily_events.index,
                    y=daily_events['ERROR'],
                    name='Error',
                    line=dict(width=2, color='#E74C3C'),
                    fill='tozeroy',
                    fillcolor='rgba(231, 76, 60, 0.1)'
                ))

            # Apply light mode styling for consistency
            fig = configure_chart(fig)
            
            # Additional layout customizations specific to this chart
            fig.update_layout(
                title="Daily Event Distribution",
                hovermode='x unified',
                showlegend=True,
                legend=dict(
                    yanchor="top",
                    y=0.99,
                    xanchor="right",
                    x=0.99,
                    bgcolor="rgba(30,30,30,0.7)"
                )
            )
            
            st.plotly_chart(fig, use_container_width=True)

        with tab2:
            st.subheader("📊 Event Analysis")
            
            # Calculate event statistics
            event_stats = df.groupby('SIMPLIFIED_EVENT').agg({
                'EVENT_ID': 'count',
                'STATUS': lambda x: (x == 'SUCCESS').mean() * 100
            }).round(2)
            
            event_stats.columns = ['Total Events', 'Success Rate (%)']
            event_stats = event_stats.sort_values('Total Events', ascending=False)

            # Create main event analysis chart
            fig = go.Figure()

            # Add total events bar
            fig.add_trace(go.Bar(
                x=event_stats.index,
                y=event_stats['Total Events'],
                name='Total Events',
                marker_color='#2E86C1',
                opacity=0.8,
                hovertemplate="<b>%{x}</b><br>" +
                            "Total Events: %{y:,.0f}<br>" +
                            "<extra></extra>"
            ))

            # Add success rate line
            fig.add_trace(go.Scatter(
                x=event_stats.index,
                y=event_stats['Success Rate (%)'],
                name='Success Rate',
                yaxis='y2',
                line=dict(color='#2ECC71', width=3),
                mode='lines+markers',
                marker=dict(size=8),
                hovertemplate="<b>%{x}</b><br>" +
                            "Success Rate: %{y:.1f}%<br>" +
                            "<extra></extra>"
            ))

            # Apply light mode styling for consistency
            fig = configure_chart(fig)
            
            # Additional layout customizations specific to this chart
            fig.update_layout(
                title="Event Analysis by Type",
                barmode='group',
                xaxis=dict(
                    title="Event Type",
                    tickangle=45,
                    tickfont=dict(size=10)
                ),
                yaxis=dict(
                    title="Total Events",
                    showgrid=True,
                    side='left',
                    tickformat=","
                ),
                yaxis2=dict(
                    title="Success Rate (%)",
                    showgrid=False,
                    side='right',
                    overlaying='y',
                    range=[0, 100]
                ),
                showlegend=True,
                legend=dict(
                    yanchor="top",
                    y=1.1,
                    xanchor="center",
                    x=0.5,
                    orientation="h"
                ),
                margin=dict(t=100)
            )

            st.plotly_chart(fig, use_container_width=True)

            # Add summary metrics in an expander
            with st.expander("📑 View Detailed Statistics", expanded=False):
                st.dataframe(
                    event_stats.style.background_gradient(
                        subset=['Success Rate (%)'],
                        cmap='RdYlGn',
                        vmin=0,
                        vmax=100
                    ),
                    use_container_width=True
                )

        with tab3:
            st.subheader("👥 User Activity Analysis")
            
            # User Activity Heatmap
            user_daily_activity = df.pivot_table(
                index='INVOKED_BY',
                columns='DATE',
                values='EVENT_ID',
                aggfunc='count',
                fill_value=0
            )

            fig = go.Figure(data=go.Heatmap(
                z=user_daily_activity.values,
                x=user_daily_activity.columns,
                y=user_daily_activity.index,
                colorscale=[
                    [0, "#1E1E1E"],  # Dark background for zero values
                    [0.1, "#133C55"], # Dark blue for low values
                    [0.3, "#0E6655"], # Teal for medium-low values
                    [0.5, "#117A65"], # Green for medium values
                    [0.7, "#1ABC9C"], # Light teal for medium-high values
                    [0.9, "#00CED1"], # Cyan for high values
                    [1.0, "#00FFFF"]  # Bright cyan for max values
                ],
                hoverongaps=False,
                hovertemplate='User: %{y}<br>Date: %{x}<br>Events: %{z}<extra></extra>'
            ))

            # Apply light mode styling for consistency
            fig = configure_chart(fig)
            
            # Additional layout customizations specific to this chart
            fig.update_layout(
                title="User Activity Heatmap",
                xaxis=dict(title="Date"),
                yaxis=dict(title="User"),
                height=400 + (len(user_daily_activity) * 20)
            )
            
            st.plotly_chart(fig, use_container_width=True)

            # Top Users Chart
            user_event_counts = df['INVOKED_BY'].value_counts().head(10)
            
            fig = go.Figure(data=[
                go.Bar(
                    x=user_event_counts.values,
                    y=user_event_counts.index,
                    orientation='h',
                    marker=dict(
                        color=px.colors.sequential.Viridis,
                        opacity=0.8
                    )
                )
            ])

            # Apply light mode styling for consistency
            fig = configure_chart(fig)
            
            # Additional layout customizations
            fig.update_layout(
                title="Top 10 Most Active Users",
                xaxis=dict(title="Number of Events"),
                yaxis=dict(title="User"),
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)

        with tab4:
            st.subheader("📝 Detailed Audit Logs")
            
            # Filters
            col1, col2, col3 = st.columns(3)
            with col1:
                status_filter = st.multiselect(
                    "Filter by Status",
                    options=sorted(df['STATUS'].unique()),
                    default=sorted(df['STATUS'].unique())
                )
            with col2:
                event_filter = st.multiselect(
                    "Filter by Event Type",
                    options=sorted(df['SIMPLIFIED_EVENT'].unique()),
                    default=sorted(df['SIMPLIFIED_EVENT'].unique())
                )
            with col3:
                user_filter = st.multiselect(
                    "Filter by User",
                    options=sorted(df['INVOKED_BY'].unique()),
                    default=sorted(df['INVOKED_BY'].unique())
                )

            # Apply filters
            filtered_df = df[
                df['STATUS'].isin(status_filter) &
                df['SIMPLIFIED_EVENT'].isin(event_filter) &
                df['INVOKED_BY'].isin(user_filter)
            ]

            # Display filtered count
            st.markdown(f"""
                <div style='
                    background: transparent;
                    padding: 10px;
                    border-radius: 5px;
                    margin: 10px 0;
                    text-align: center;
                    border: 1px solid #e0e0e0;
                '>
                    <span style='font-size: 16px;'>
                        Showing <strong style='color: #1976D2;'>{len(filtered_df):,}</strong> of 
                        <strong style='color: #1976D2;'>{len(df):,}</strong> total events
                    </span>
                </div>
            """, unsafe_allow_html=True)

            # Display detailed logs
            st.dataframe(
                filtered_df[[
                    'EVENT_TIME',
                    'INVOKED_BY',
                    'SIMPLIFIED_EVENT',
                    'OBJECT_NAME',
                    'STATUS',
                    'MESSAGE'
                ]].sort_values('EVENT_TIME', ascending=False),
                hide_index=True,
                use_container_width=True
            )

    except Exception as e:
        st.error(f"Error fetching audit logs: {e}")
        st.exception(e)

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_database_role_hierarchy(selected_db):
    """Fetch role hierarchy for a specific database using recursive query."""
    query = f"""
    WITH RECURSIVE role_hierarchy AS (
        -- Base Query: Start with DATABASE_ROLE hierarchy
        SELECT 
            NAME AS PARENT, 
            GRANTEE_NAME AS CHILD,
            NAME AS ROOT, -- Keep track of the starting role
            1 AS LEVEL
        FROM snowflake.account_usage.grants_to_roles 
        WHERE table_catalog = '{selected_db}' 
            AND granted_on = 'DATABASE_ROLE' 
            AND granted_to = 'ROLE' 
            AND grant_option = 0
        
        UNION ALL
        
        -- Recursive Query: Fetch roles from CHILD of first query
        SELECT 
            g.GRANTEE_NAME AS PARENT, 
            g.NAME AS CHILD,
            r.ROOT, -- Maintain the same starting role
            r.LEVEL + 1 AS LEVEL -- Track depth for clarity
        FROM snowflake.account_usage.grants_to_roles g
        INNER JOIN role_hierarchy r 
            ON g.GRANTEE_NAME = r.CHILD -- Using CHILD from the previous step
        WHERE g.granted_on = 'ROLE' 
            AND g.grant_option = 0
    )

    SELECT * FROM role_hierarchy
    ORDER BY ROOT, LEVEL;
    """
    return session.sql(query).to_pandas()

@st.cache_data(ttl=300)  # Cache for 5 minutes
def ui_assign_database_roles():
    """UI for assigning database roles to functional/technical roles."""
    st.header("Assign Database Roles")
    
    # Get access role suffixes from metadata
    access_role_suffixes = get_access_role_suffixes()
    if not access_role_suffixes:
        st.error("Could not fetch access role suffixes from metadata. Please ensure ACCESS_PROFILES table is properly configured.")
        return
    
    st.info("""
    This action allows you to:
    1. Select a Functional or Technical role
    2. Grant appropriate database or schema-level role access
    3. Manage database and schema-level permissions
    
    Note: Only databases matching the role's environment will be shown.
    """)

    # Get all FR/TR roles
    roles_df = get_functional_technical_roles()
    
    if roles_df.empty:
        st.warning("No functional or technical roles found in the system.")
        return
    
    # Initialize session state for selections if not already set
    if 'db_role_selected_role' not in st.session_state:
        st.session_state.db_role_selected_role = roles_df['ROLE_NAME'].tolist()[0] if roles_df['ROLE_NAME'].tolist() else None
    
    # Role selection outside the form for interactive updates
    selected_role = st.selectbox(
        "Select Role to Grant Access",
        options=roles_df['ROLE_NAME'].tolist(),
        key="db_role_selected_role",
        help="Choose the role that will receive database or schema access"
    )
    
    # Extract environment from role name and filter databases
    role_env = None
    relevant_databases = []
    selected_db = None
    access_level_desc = None
    access_role_suffix = None
    
    if selected_role:
        role_env = get_environment_from_role(selected_role)
        all_databases = get_databases()
        
        # Filter databases based on environment
        relevant_databases = [
            db for db in all_databases 
            if db.startswith(f"{role_env}_") or 
               "COMMON" in db.upper()  # Include COMMON databases
        ]
        
        if not relevant_databases:
            st.warning(f"No databases found for environment: {role_env}. Please select a different role.")
        else:
            # Initialize session state for database selection if needed
            if 'db_role_selected_db' not in st.session_state or st.session_state.db_role_selected_db not in relevant_databases:
                st.session_state.db_role_selected_db = relevant_databases[0]
            
            # Database selection
            selected_db = st.selectbox(
                "Select Database",
                options=relevant_databases,
                key="db_role_selected_db",
                help=f"Choose a database from environment {role_env}"
            )
            
            # Access scope selection (database or schema level)
            access_scope = st.radio(
                "Select Access Scope",
                ["Database Level", "Schema Level"],
                key="db_role_access_scope",
                horizontal=True,
                help="Choose whether to grant access at database level or schema level"
            )
            
            # Schema selection if schema level access is selected
            selected_schema = None
            if access_scope == "Schema Level" and selected_db:
                schemas = get_database_schemas(selected_db)
                
                if not schemas:
                    st.warning(f"No schemas found in database '{selected_db}' or unable to fetch schemas.")
                else:
                    # Initialize session state for schema selection
                    if 'db_role_selected_schema' not in st.session_state or st.session_state.db_role_selected_schema not in schemas:
                        st.session_state.db_role_selected_schema = schemas[0] if schemas else None
                    
                    selected_schema = st.selectbox(
                        "Select Schema",
                        options=schemas,
                        key="db_role_selected_schema",
                        help="Choose the schema to grant access to"
                    )
            
            # Access level selection
            access_level_map = {
                f"Access Level {suffix}": suffix for suffix in access_role_suffixes
            }
            
            # Initialize session state for access level if needed
            if 'db_role_access_level' not in st.session_state:
                st.session_state.db_role_access_level = list(access_level_map.keys())[0]
            
            access_level_desc = st.selectbox(
                "Select Access Level",
                options=list(access_level_map.keys()),
                key="db_role_access_level",
                help="Choose the level of access to grant"
            )
            
            access_role_suffix = access_level_map[access_level_desc]
    
    # Preview section - outside the form for real-time updates
    if selected_role and selected_db:
        with st.expander("View Grant Details", expanded=True):
            st.markdown("### Grant Configuration Preview")
            
            # Determine the role to grant based on access scope
            if 'access_scope' in locals() and access_scope == "Schema Level" and 'selected_schema' in locals() and selected_schema:
                role_to_grant = f"{selected_db}.{selected_schema}_{access_role_suffix}"
                scope_text = f"Schema: {selected_schema}"
            else:
                role_to_grant = f"{selected_db}.{access_role_suffix}"
                scope_text = "Database Level"
            
            details = {
                "Role to Grant To": selected_role,
                "Role Environment": role_env,
                "Target Database": selected_db,
                "Access Scope": scope_text,
                "Role to Grant": role_to_grant,
                "Access Level": access_level_desc
            }
            for key, value in details.items():
                st.write(f"**{key}:** {value}")
    
    # Now create the form for submission
    with st.form("assign_db_roles_form"):
        # Hidden fields to store the current selections
        st.text_input("Hidden Role", value=selected_role if selected_role else "", label_visibility="collapsed", disabled=True)
        st.text_input("Hidden Database", value=selected_db if selected_db else "", label_visibility="collapsed", disabled=True)
        
        # Determine the role to grant for the form
        role_to_grant = ""
        if 'selected_db' in locals() and selected_db:
            if 'access_scope' in locals() and access_scope == "Schema Level" and 'selected_schema' in locals() and selected_schema:
                role_to_grant = f"{selected_db}.{selected_schema}_{access_role_suffix}"
            else:
                role_to_grant = f"{selected_db}.{access_role_suffix}"
        
        st.text_input("Hidden Role to Grant", value=role_to_grant, label_visibility="collapsed", disabled=True)
        
        # Confirmation
        confirm = st.checkbox(
            "I confirm I want to grant the selected role",
            key="db_role_confirm",
            help="Please confirm you want to proceed with the grant"
        )
        
        submitted = st.form_submit_button("Grant Role Access")
        
        if submitted:
            if not selected_role or not role_to_grant:
                st.error("Please select all required options before submitting.")
                return
                
            if not confirm:
                st.warning("Please confirm the action by checking the confirmation box.")
                return
            
            # Construct and execute the GRANT command
            grant_command = f"GRANT DATABASE ROLE {role_to_grant} TO ROLE {selected_role}"
            
            try:
                session.sql(grant_command).collect()
                
                # Log the successful grant
                log_audit_event(
                    "GRANT_DATABASE_ROLE",
                    role_to_grant,
                    grant_command,
                    "SUCCESS",
                    f"Granted {role_to_grant} to {selected_role}"
                )
                
                # Grant USAGE on the database to the role
                try:
                    grant_usage_command = f"GRANT USAGE ON DATABASE {selected_db} TO ROLE {selected_role}"
                    session.sql(grant_usage_command).collect()
                    
                    # Log the successful USAGE grant
                    log_audit_event(
                        "GRANT_DATABASE_USAGE",
                        selected_db,
                        grant_usage_command,
                        "SUCCESS",
                        f"Granted USAGE on database {selected_db} to role {selected_role}"
                    )
                except Exception as e:
                    usage_error_message = str(e)
                    st.warning(f"Successfully granted database role, but failed to grant database USAGE: {usage_error_message}")
                    log_audit_event(
                        "GRANT_DATABASE_USAGE",
                        selected_db,
                        grant_usage_command,
                        "ERROR",
                        usage_error_message
                    )
                
                # Determine success message based on access scope
                if 'access_scope' in locals() and access_scope == "Schema Level" and 'selected_schema' in locals() and selected_schema:
                    success_message = f"""
                    ✅ Successfully granted schema role:
                    - Schema Role: {role_to_grant}
                    - Granted To: {selected_role}
                    - Access Level: {access_level_desc}
                    - Schema: {selected_schema}
                    """
                else:
                    success_message = f"""
                    ✅ Successfully granted database role:
                    - Database Role: {role_to_grant}
                    - Granted To: {selected_role}
                    - Access Level: {access_level_desc}
                    """
                
                st.success(success_message)
                
                # Show current grants in an expander
                with st.expander("View Current Role Grants"):
                    try:
                        current_grants_query = f"""
                        SELECT 
                            GRANTEE_NAME,
                            NAME,
                            GRANTED_ON,
                            CREATED_ON
                        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
                        WHERE GRANTEE_NAME = '{selected_role}'
                        AND NAME LIKE '{selected_db}.%'
                        AND DELETED_ON IS NULL
                        ORDER BY CREATED_ON DESC
                        """
                        current_grants = session.sql(current_grants_query).to_pandas()
                        if not current_grants.empty:
                            st.dataframe(current_grants, hide_index=True)
                        else:
                            st.info("No current grants found.")
                    except Exception as e:
                        st.warning(f"Could not fetch current grants: {e}")
                
            except Exception as e:
                error_message = str(e)
                st.error(f"Error granting role: {error_message}")
                log_audit_event(
                    "GRANT_DATABASE_ROLE",
                    role_to_grant,
                    grant_command,
                    "ERROR",
                    error_message
                )


@st.cache_data(ttl=300)  # Cache for 5 minutes
@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_database_role_grants(selected_db):
    """Fetch direct grants on the database level."""
    try:
        query = """
        SELECT DISTINCT
            PRIVILEGE,
            GRANTED_ON,
            GRANTEE_NAME as ROLE_NAME
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE 
            TABLE_CATALOG = '{db}'
            AND GRANTED_ON = 'DATABASE'
            AND DELETED_ON IS NULL
        ORDER BY ROLE_NAME, PRIVILEGE;
        """.format(db=selected_db.upper())
        
        return session.sql(query).to_pandas()
    except Exception as e:
        st.error(f"Error fetching database grants: {e}")
        return pd.DataFrame(columns=['PRIVILEGE', 'GRANTED_ON', 'ROLE_NAME'])

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_functional_technical_roles():
    """Fetch all roles with _FR or _TR suffix."""
    try:
        query = """
        SELECT DISTINCT name as ROLE_NAME
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE (name LIKE '%_FR' OR name LIKE '%_TR')
        AND DELETED_ON IS NULL
        ORDER BY name
        """
        return session.sql(query).to_pandas()
    except Exception as e:
        st.error(f"Error fetching roles: {e}")
        return pd.DataFrame(columns=['ROLE_NAME'])

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_current_role_grants(role_name):
    """Fetch current grants for a specific role."""
    try:
        query = f"""
        SELECT 
            NAME as GRANTED_ROLE,
            GRANTEE_NAME as GRANTED_TO_ROLE,
            CREATED_ON as GRANT_DATE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTEE_NAME = '{role_name}'
            AND PRIVILEGE = 'USAGE'
            AND GRANTED_ON = 'ROLE'
            AND DELETED_ON IS NULL
        ORDER BY CREATED_ON DESC
        """
        return session.sql(query).to_pandas()
    except Exception as e:
        st.error(f"Error fetching role grants: {e}")
        return pd.DataFrame(columns=['GRANTED_ROLE', 'GRANTED_TO_ROLE', 'GRANT_DATE'])

def generate_database_role_graph(hierarchy_df, db_grants_df, selected_db):
    """Generate a Graphviz graph for database role hierarchy with additional grant information."""
    dot = graphviz.Digraph(comment=f'Role Hierarchy for Database: {selected_db}')
    dot.attr(rankdir='TB', 
            splines='ortho',
            nodesep='0.5',
            ranksep='0.7')
    
    # Global node attributes
    dot.attr('node', 
            shape='box',
            style='rounded,filled',
            fontname='Arial',
            fontsize='10',
            height='0.3',
            margin='0.2')
    
    # Add database node at the top
    dot.node(selected_db,
            selected_db,
            shape='cylinder',
            fillcolor='#90EE90',
            style='filled')
    
    # Track added nodes to prevent duplicates
    added_nodes = set()
    
    # Add nodes for roles with direct database grants
    for _, row in db_grants_df.iterrows():
        role_name = row['ROLE_NAME']
        if role_name not in added_nodes:
            dot.node(role_name,
                    f"{role_name}\n({row['PRIVILEGE']})",
                    fillcolor='#ADD8E6',
                    style='filled')
            added_nodes.add(role_name)
            # Add edge from database to role
            dot.edge(selected_db, role_name, style='dashed')
    
    # Add role hierarchy nodes and edges
    for _, row in hierarchy_df.iterrows():
        parent = row['PARENT_ROLE']
        child = row['CHILD_ROLE']
        
        # Add parent node if not already added
        if parent not in added_nodes:
            dot.node(parent, parent, fillcolor='#E6F0FF', style='filled')
            added_nodes.add(parent)
        
        # Add child node if not already added
        if child not in added_nodes:
            dot.node(child, child, fillcolor='#E6F0FF', style='filled')
            added_nodes.add(child)
        
        # Add hierarchy edge
        dot.edge(parent, child)
    
    return dot

def ui_view_database_grants(selected_db):
    """UI component for viewing database grants and role hierarchy."""
    st.subheader(f"Database Role Hierarchy: {selected_db}")
    
    # Add information about data latency
    st.info("""
    This view shows the complete role hierarchy for the selected database, including:
    1. Database roles and their relationships
    2. Role hierarchy with levels
    3. Root roles and their child roles
    
    Note: Data is sourced from ACCOUNT_USAGE views which may have up to 2 hours latency.
    """)
    
    # Fetch data
    with st.spinner("Fetching database role hierarchy..."):
        hierarchy_df = get_database_role_hierarchy(selected_db)
    
    # Show visualization if we have data
    if not hierarchy_df.empty:
        try:
            with st.spinner("Generating role hierarchy visualization..."):
                # Create a graph using graphviz
                dot = graphviz.Digraph(comment='Database Role Hierarchy')
                dot.attr(rankdir='TB')
                
                # Add nodes and edges
                for _, row in hierarchy_df.iterrows():
                    # Add parent node
                    dot.node(row['PARENT'], row['PARENT'])
                    # Add child node
                    dot.node(row['CHILD'], row['CHILD'])
                    # Add edge
                    dot.edge(row['PARENT'], row['CHILD'])
                
                st.graphviz_chart(dot)
                
                # Show detailed information in expander
                with st.expander("View Role Hierarchy Details"):
                    st.dataframe(hierarchy_df, hide_index=True)
        except Exception as e:
            st.error(f"Error generating visualization: {e}")
            st.text_area("Graphviz DOT Source (for debugging)", dot.source, height=300)
    else:
        st.warning(f"No role hierarchy found for database '{selected_db}'")

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_database_role_grants_for_role(role_name):
    """Fetch database role grants for a specific role."""
    try:
        query = f"""
        SELECT 
            NAME as GRANTED_ROLE,
            GRANTEE_NAME as GRANTED_TO_ROLE,
            TABLE_CATALOG as DATABASE_NAME,
            CREATED_ON as GRANT_DATE,
            'DATABASE_ROLE' as ROLE_TYPE
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        WHERE GRANTEE_NAME = '{role_name}'
            AND PRIVILEGE = 'USAGE'
            AND GRANTED_ON = 'DATABASE_ROLE'
            AND DELETED_ON IS NULL
        ORDER BY CREATED_ON DESC
        """
        return session.sql(query).to_pandas()
    except Exception as e:
        st.error(f"Error fetching database role grants: {e}")
        return pd.DataFrame(columns=['GRANTED_ROLE', 'GRANTED_TO_ROLE', 'DATABASE_NAME', 'GRANT_DATE', 'ROLE_TYPE'])

def ui_revoke_roles():
    """UI for revoking role grants."""
    st.header("Revoke Role Grants")
    
    # Information message
    st.info("""
    This action allows you to:
    1. View existing role grants (both regular roles and database roles)
    2. Revoke role grants from other roles
    
    Use this when you need to remove access by revoking a role from another role.
    """)
    
    # Get all roles with _FR or _TR suffix using cached function
    try:
        roles_df = get_functional_technical_roles()
        if roles_df.empty:
            st.warning("No functional or technical roles found in the account.")
            return
            
        roles_list = roles_df['ROLE_NAME'].tolist()
        
        # Initialize session state for selections if not already set
        if 'revoke_target_role' not in st.session_state and roles_list:
            st.session_state.revoke_target_role = roles_list[0]
            
        # Create two columns for the main interface
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Select Role to Modify")
            target_role = st.selectbox(
                "Select role to remove grants from",
                options=roles_list,
                key="revoke_target_role",
                help="Select the role from which you want to revoke grants"
            )
            
            # Show current grants for the selected role
            if target_role:
                st.markdown("#### Current Role Grants")
                
                # Get regular role grants
                current_role_grants_df = get_current_role_grants(target_role)
                
                # Get database role grants
                current_db_role_grants_df = get_database_role_grants_for_role(target_role)
                
                # Initialize session state for selected grants
                if 'selected_grants' not in st.session_state:
                    st.session_state.selected_grants = []
                    
                if 'selected_db_grants' not in st.session_state:
                    st.session_state.selected_db_grants = []
                
                # Display regular role grants if available
                if not current_role_grants_df.empty:
                    st.markdown("**Existing Regular Role Grants:**")
                    
                    # Format the dataframe for display
                    display_df = current_role_grants_df.copy()
                    display_df['GRANT_DATE'] = pd.to_datetime(display_df['GRANT_DATE']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Display the grants with a select column
                    selected_grants = []
                    for idx, row in display_df.iterrows():
                        granted_role = row['GRANTED_ROLE']
                        grant_date = row['GRANT_DATE']
                        if st.checkbox(
                            f"Revoke Role: {granted_role} (Granted on: {grant_date})",
                            key=f"revoke_role_{target_role}_{granted_role}",
                            help=f"Select to revoke {granted_role} from {target_role}"
                        ):
                            selected_grants.append((granted_role, "ROLE"))
                    
                    # Store the selected grants in session state
                    st.session_state.selected_grants = selected_grants
                else:
                    st.info("No existing regular role grants found for this role.")
                
                # Display database role grants if available
                if not current_db_role_grants_df.empty:
                    st.markdown("**Existing Database Role Grants:**")
                    
                    # Format the dataframe for display
                    display_db_df = current_db_role_grants_df.copy()
                    display_db_df['GRANT_DATE'] = pd.to_datetime(display_db_df['GRANT_DATE']).dt.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Display the grants with a select column
                    selected_db_grants = []
                    for idx, row in display_db_df.iterrows():
                        granted_db_role = row['GRANTED_ROLE']
                        database_name = row['DATABASE_NAME']
                        grant_date = row['GRANT_DATE']
                        if st.checkbox(
                            f"Revoke DB Role: {granted_db_role} (Database: {database_name}, Granted on: {grant_date})",
                            key=f"revoke_db_role_{target_role}_{granted_db_role}_{database_name}",
                            help=f"Select to revoke database role {granted_db_role} from {target_role}"
                        ):
                            selected_db_grants.append((granted_db_role, "DATABASE_ROLE", database_name))
                    
                    # Store the selected database grants in session state
                    st.session_state.selected_db_grants = selected_db_grants
                else:
                    st.info("No existing database role grants found for this role.")
                
                # If no grants at all
                if current_role_grants_df.empty and current_db_role_grants_df.empty:
                    st.warning("No role grants of any type found for this role.")
        
        with col2:
            st.markdown("### Review and Confirm")
            
            # Check if any grants are selected
            has_selections = (len(st.session_state.get('selected_grants', [])) > 0 or 
                             len(st.session_state.get('selected_db_grants', [])) > 0)
            
            if target_role and has_selections:
                st.markdown("#### Selected Grants to Revoke:")
                
                # Display regular role grants to revoke
                for role, role_type in st.session_state.get('selected_grants', []):
                    st.write(f"- Role: {role} from {target_role}")
                
                # Display database role grants to revoke
                for db_role, role_type, db_name in st.session_state.get('selected_db_grants', []):
                    st.write(f"- Database Role: {db_role} (from database {db_name}) from {target_role}")
                
                # Add confirmation for revocation
                confirm = st.checkbox(
                    "I confirm I want to revoke the selected role grants",
                    key="confirm_revoke",
                    help="Please confirm you want to proceed with the revocation"
                )
                
                if st.button("Revoke Selected Grants", disabled=not confirm):
                    with st.spinner("Revoking selected grants..."):
                        success_count = 0
                        error_count = 0
                        
                        # Process regular role revocations
                        for role_to_revoke, role_type in st.session_state.get('selected_grants', []):
                            revoke_command = f"REVOKE ROLE {role_to_revoke} FROM ROLE {target_role}"
                            try:
                                session.sql(revoke_command).collect()
                                success_count += 1
                                
                                # Log the successful revocation
                                log_audit_event(
                                    "REVOKE_ROLE",
                                    f"{role_to_revoke} FROM {target_role}",
                                    revoke_command,
                                    "SUCCESS",
                                    f"Revoked role {role_to_revoke} from {target_role}"
                                )
                                
                            except Exception as e:
                                error_count += 1
                                st.error(f"Error revoking role {role_to_revoke}: {e}")
                                log_audit_event(
                                    "REVOKE_ROLE",
                                    f"{role_to_revoke} FROM {target_role}",
                                    revoke_command,
                                    "ERROR",
                                    str(e)
                                )
                        
                        # Process database role revocations
                        for db_role_to_revoke, role_type, db_name in st.session_state.get('selected_db_grants', []):
                            # Use the database name from the selected grant
                            revoke_db_command = f"REVOKE DATABASE ROLE {db_name}.{db_role_to_revoke.split('.')[-1]} FROM ROLE {target_role}"
                            try:
                                session.sql(revoke_db_command).collect()
                                success_count += 1
                                
                                # Log the successful revocation
                                log_audit_event(
                                    "REVOKE_DATABASE_ROLE",
                                    f"{db_name}.{db_role_to_revoke.split('.')[-1]} FROM {target_role}",
                                    revoke_db_command,
                                    "SUCCESS",
                                    f"Revoked database role {db_name}.{db_role_to_revoke.split('.')[-1]} from {target_role}"
                                )
                                
                            except Exception as e:
                                error_count += 1
                                st.error(f"Error revoking database role {db_name}.{db_role_to_revoke.split('.')[-1]}: {e}")
                                log_audit_event(
                                    "REVOKE_DATABASE_ROLE",
                                    f"{db_name}.{db_role_to_revoke.split('.')[-1]} FROM {target_role}",
                                    revoke_db_command,
                                    "ERROR",
                                    str(e)
                                )
                        
                        # Show summary
                        if success_count > 0:
                            st.success(f"Successfully revoked {success_count} grant(s)")
                        if error_count > 0:
                            st.error(f"Failed to revoke {error_count} grant(s)")
                        
                        # Clear the cache and session state to refresh the grants view
                        st.cache_data.clear()
                        st.session_state.selected_grants = []
                        st.session_state.selected_db_grants = []
                        
                        # Show updated grants
                        st.markdown("### Updated Grants")
                        
                        # Check regular roles
                        updated_role_grants_df = get_current_role_grants(target_role)
                        if not updated_role_grants_df.empty:
                            st.subheader("Regular Role Grants")
                            st.dataframe(updated_role_grants_df, hide_index=True)
                        
                        # Check database roles
                        updated_db_role_grants_df = get_database_role_grants_for_role(target_role)
                        if not updated_db_role_grants_df.empty:
                            st.subheader("Database Role Grants")
                            st.dataframe(updated_db_role_grants_df, hide_index=True)
                            
                        # If no grants at all after revocation
                        if updated_role_grants_df.empty and updated_db_role_grants_df.empty:
                            st.info("No remaining grants found for this role.")
                        
                        # Force a rerun to refresh the UI
                        st.rerun()
                            
            else:
                st.info("Select role grant(s) to revoke from the left panel.")
                
    except Exception as e:
        st.error(f"Error in revoke roles interface: {e}")
        st.exception(e)

def ui_cost_analysis():
    """UI for analyzing Snowflake costs with detailed visualizations."""
    st.header("Cost Analysis Dashboard")
    
    # Add description
    st.info("""
    This dashboard provides detailed insights into your Snowflake costs across different dimensions:
    - Warehouse Usage and Costs
    - Storage Costs
    - Query Performance and Cost Impact
    - Cost Trends and Forecasting
    """)

    # Date range selector
    st.markdown("### 📅 Select Date Range")
    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input(
            "Start Date",
            value=datetime.now() - timedelta(days=30),
            help="Select start date for cost analysis"
        )
    with col2:
        end_date = st.date_input(
            "End Date",
            value=datetime.now(),
            help="Select end date for cost analysis"
        )

    # Convert dates to timestamps for Snowflake query
    start_ts = datetime.combine(start_date, datetime.min.time())
    end_ts = datetime.combine(end_date, datetime.max.time())

    try:
        # Create tabs for different cost analyses
        tab1, tab2, tab3, tab4 = st.tabs([
            "💰 Warehouse Costs",
            "💾 Storage Costs",
            "⚡ Query Costs",
            "📈 Cost Trends"
        ])

        with tab1:
            st.subheader("Warehouse Usage and Costs")
            
            # Fixed warehouse usage query
            warehouse_query = f"""
            SELECT 
                WAREHOUSE_NAME,
                DATE_TRUNC('day', START_TIME) as USAGE_DATE,
                SUM(CREDITS_USED) as CREDITS_USED,
                COUNT(*) as USAGE_COUNT,
                AVG(CREDITS_USED_COMPUTE) as AVG_COMPUTE_CREDITS,
                AVG(CREDITS_USED_CLOUD_SERVICES) as AVG_CLOUD_CREDITS
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME BETWEEN '{start_ts}' AND '{end_ts}'
            GROUP BY 1, 2
            ORDER BY 2, 1
            """
            
            wh_df = session.sql(warehouse_query).to_pandas()
            
            if not wh_df.empty:
                # Total credits used metric
                total_credits = wh_df['CREDITS_USED'].sum()
                st.metric("Total Credits Used", f"{total_credits:,.2f}")

                # Warehouse usage over time
                fig = go.Figure()
                for warehouse in wh_df['WAREHOUSE_NAME'].unique():
                    wh_data = wh_df[wh_df['WAREHOUSE_NAME'] == warehouse]
                    fig.add_trace(go.Scatter(
                        x=wh_data['USAGE_DATE'],
                        y=wh_data['CREDITS_USED'],
                        name=warehouse,
                        mode='lines+markers',
                        hovertemplate="<b>%{x}</b><br>" +
                                    "Credits: %{y:.2f}<br>" +
                                    "<extra></extra>"
                    ))

                # Apply appropriate styling based on mode
                # For simplicity in this demo, we'll use light mode styling
                # In a production app, this would check the user's preference
                fig = configure_chart(fig)
                
                # Additional layout customizations
                fig.update_layout(
                    title="Daily Warehouse Credit Usage",
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)

                # Warehouse comparison bar chart
                wh_summary = wh_df.groupby('WAREHOUSE_NAME').agg({
                    'CREDITS_USED': 'sum',
                    'USAGE_COUNT': 'sum',
                    'AVG_COMPUTE_CREDITS': 'mean',
                    'AVG_CLOUD_CREDITS': 'mean'
                }).reset_index()

                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=wh_summary['WAREHOUSE_NAME'],
                    y=wh_summary['CREDITS_USED'],
                    name='Credits Used',
                    text=wh_summary['CREDITS_USED'].round(2),
                    textposition='auto',
                ))

                # Apply light mode styling for consistency
                fig = configure_chart(fig)
                
                # Additional layout customizations
                fig.update_layout(
                    title="Total Credits Used by Warehouse",
                    xaxis=dict(title="Warehouse"),
                    yaxis=dict(title="Total Credits")
                )
                st.plotly_chart(fig, use_container_width=True)

        with tab2:
            st.subheader("Storage Costs and Trends")
            
            # Fetch storage usage data
            storage_query = f"""
            SELECT 
                DATE_TRUNC('day', USAGE_DATE) as USAGE_DATE,
                STORAGE_BYTES/POWER(1024, 4) as STORAGE_TB,
                STAGE_BYTES/POWER(1024, 4) as STAGE_TB,
                FAILSAFE_BYTES/POWER(1024, 4) as FAILSAFE_TB
            FROM SNOWFLAKE.ACCOUNT_USAGE.STORAGE_USAGE
            WHERE USAGE_DATE BETWEEN '{start_ts}' AND '{end_ts}'
            ORDER BY USAGE_DATE
            """
            
            storage_df = session.sql(storage_query).to_pandas()
            
            if not storage_df.empty:
                # Storage metrics
                latest_storage = storage_df.iloc[-1]
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Database Storage (TB)", f"{latest_storage['STORAGE_TB']:.2f}")
                with col2:
                    st.metric("Stage Storage (TB)", f"{latest_storage['STAGE_TB']:.2f}")
                with col3:
                    st.metric("Failsafe Storage (TB)", f"{latest_storage['FAILSAFE_TB']:.2f}")

                # Storage trend chart
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=storage_df['USAGE_DATE'],
                    y=storage_df['STORAGE_TB'],
                    name='Database Storage',
                    mode='lines',
                    line=dict(width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=storage_df['USAGE_DATE'],
                    y=storage_df['STAGE_TB'],
                    name='Stage Storage',
                    mode='lines',
                    line=dict(width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=storage_df['USAGE_DATE'],
                    y=storage_df['FAILSAFE_TB'],
                    name='Failsafe Storage',
                    mode='lines',
                    line=dict(width=2)
                ))

                # Apply light mode styling for consistency
                fig = configure_chart(fig)
                
                # Additional layout customizations
                fig.update_layout(
                    title="Storage Usage Trends",
                    xaxis=dict(title="Date"),
                    yaxis=dict(title="Storage (TB)"),
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)

        with tab3:
            st.subheader("Query Cost Analysis")
            
            # Updated query execution data query
            query_query = f"""
            SELECT 
                WAREHOUSE_NAME,
                ROUND(AVG(TOTAL_ELAPSED_TIME/1000), 2) as AVG_EXECUTION_TIME_SEC,
                ROUND(AVG(BYTES_SCANNED/POWER(1024, 2)), 2) as AVG_MB_SCANNED,
                COUNT(*) as QUERY_COUNT,
                ROUND(AVG(CREDITS_USED_CLOUD_SERVICES), 4) as AVG_CLOUD_SERVICES_CREDITS
            FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
            WHERE START_TIME BETWEEN '{start_ts}' AND '{end_ts}'
            AND WAREHOUSE_NAME IS NOT NULL
            GROUP BY WAREHOUSE_NAME
            ORDER BY AVG_EXECUTION_TIME_SEC DESC
            """
            
            query_df = session.sql(query_query).to_pandas()
            
            if not query_df.empty:
                # Query performance metrics
                col1, col2 = st.columns(2)
                
                with col1:
                    fig = go.Figure()
                    fig.add_trace(go.Bar(
                        x=query_df['WAREHOUSE_NAME'],
                        y=query_df['AVG_EXECUTION_TIME_SEC'],
                        text=query_df['AVG_EXECUTION_TIME_SEC'].round(2),
                        textposition='auto',
                    ))
                    # Apply light mode styling for consistency
                    fig = configure_chart(fig)
                    
                    # Additional layout customizations
                    fig.update_layout(
                        title="Average Query Execution Time by Warehouse",
                        xaxis=dict(title="Warehouse"),
                        yaxis=dict(title="Seconds")
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    fig = go.Figure()
                    fig.add_trace(go.Bar(
                        x=query_df['WAREHOUSE_NAME'],
                        y=query_df['AVG_MB_SCANNED'],
                        text=query_df['AVG_MB_SCANNED'].round(2),
                        textposition='auto',
                    ))
                    # Apply light mode styling for consistency
                    fig = configure_chart(fig)
                    
                    # Additional layout customizations
                    fig.update_layout(
                        title="Average Data Scanned by Warehouse",
                        xaxis=dict(title="Warehouse"),
                        yaxis=dict(title="MB Scanned")
                    )
                    st.plotly_chart(fig, use_container_width=True)

        with tab4:
            st.subheader("Cost Trends and Forecasting")
            
            # Fetch daily cost data
            cost_query = f"""
            SELECT 
                DATE_TRUNC('day', START_TIME) as USAGE_DATE,
                SUM(CREDITS_USED) as TOTAL_CREDITS,
                SUM(CREDITS_USED_COMPUTE) as COMPUTE_CREDITS,
                SUM(CREDITS_USED_CLOUD_SERVICES) as CLOUD_SERVICES_CREDITS
            FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
            WHERE START_TIME BETWEEN '{start_ts}' AND '{end_ts}'
            GROUP BY 1
            ORDER BY 1
            """
            
            cost_df = session.sql(cost_query).to_pandas()
            
            if not cost_df.empty:
                # Calculate moving averages
                cost_df['7_DAY_MA'] = cost_df['TOTAL_CREDITS'].rolling(window=7).mean()
                cost_df['30_DAY_MA'] = cost_df['TOTAL_CREDITS'].rolling(window=30).mean()

                # Cost trend chart
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=cost_df['USAGE_DATE'],
                    y=cost_df['TOTAL_CREDITS'],
                    name='Daily Credits',
                    mode='lines',
                    line=dict(width=1)
                ))
                fig.add_trace(go.Scatter(
                    x=cost_df['USAGE_DATE'],
                    y=cost_df['7_DAY_MA'],
                    name='7-Day Moving Avg',
                    mode='lines',
                    line=dict(width=2)
                ))
                fig.add_trace(go.Scatter(
                    x=cost_df['USAGE_DATE'],
                    y=cost_df['30_DAY_MA'],
                    name='30-Day Moving Avg',
                    mode='lines',
                    line=dict(width=2)
                ))

                # Apply light mode styling for consistency
                fig = configure_chart(fig)
                
                # Additional layout customizations
                fig.update_layout(
                    title="Credit Usage Trends with Moving Averages",
                    xaxis=dict(title="Date"),
                    yaxis=dict(title="Credits Used"),
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)

                # Credit distribution pie chart
                total_compute = cost_df['COMPUTE_CREDITS'].sum()
                total_cloud = cost_df['CLOUD_SERVICES_CREDITS'].sum()
                
                fig = go.Figure(data=[go.Pie(
                    labels=['Compute Credits', 'Cloud Services Credits'],
                    values=[total_compute, total_cloud],
                    hole=.3
                )])
                
                # Apply light mode styling for consistency
                fig = configure_chart(fig)
                
                # Additional layout customizations
                fig.update_layout(
                    title="Credit Usage Distribution"
                )
                st.plotly_chart(fig, use_container_width=True)

    except Exception as e:
        st.error(f"Error fetching cost analysis data: {e}")
        st.info("""
        To use this feature, ensure:
        1. You have access to ACCOUNT_USAGE views
        2. Your role has appropriate permissions
        3. There is cost data available in the selected date range
        """)
def ui_about():
    """About PRISM."""
    st.header("PRISM")
    st.caption("Portal for Role Integration, Security & Management")

    st.markdown("""
    PRISM is a metadata-driven RBAC provisioning and governance framework for Snowflake.
    It automates database, schema, role, and warehouse lifecycle management across
    multiple environments from a single control plane.
    """)

    st.markdown("---")

    tab1, tab2, tab3, tab4 = st.tabs(["Architecture", "Metadata Tables", "Capabilities", "Version"])

    with tab1:
        st.subheader("How It Works")
        st.markdown("""
        PRISM follows a **3-layer metadata architecture**:

        **Layer 1: Snowflake Privilege Catalog** (auto-synced)
        - Source of truth from `EXPLAIN_GRANTABLE_PRIVILEGES()`
        - Weekly auto-sync via scheduled task
        - Detects new Snowflake features automatically

        **Layer 2: Access Profiles**
        - 8 profiles: OWN, DBA, FULL, RW, RO, DO, GOV, SVC
        - Hierarchy defined in metadata, not code
        - Adding/removing profiles requires zero code changes

        **Layer 3: Profile Privileges**
        - Maps each profile to specific privileges per object type
        - One row per privilege (normalized)
        - Supports both DATABASE and SCHEMA grant targets
        """)

        st.subheader("Role Hierarchy")
        try:
            hierarchy_df = session.sql("SELECT * FROM " + get_fully_qualified_name("V_ROLE_HIERARCHY", include_db=True)).to_pandas()
            if not hierarchy_df.empty:
                import graphviz
                dot = graphviz.Digraph(graph_attr={"rankdir": "TB", "bgcolor": "transparent"})
                dot.attr("node", shape="box", style="rounded,filled", fillcolor="#E3EBF6", fontname="Helvetica")
                profiles_df = session.sql("SELECT ACCESS_CODE, ROLE_SUFFIX, IS_SYSTEM_ONLY FROM " + get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILES"], include_db=True) + " WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER").to_pandas()
                for _, r in profiles_df.iterrows():
                    color = "#fff3e0" if r["IS_SYSTEM_ONLY"] else "#e8f0fe"
                    dot.node(r["ACCESS_CODE"], r["ACCESS_CODE"] + "\n(" + r["ROLE_SUFFIX"] + ")", fillcolor=color, fontcolor="#1a1a1a")
                for _, r in hierarchy_df.iterrows():
                    dot.edge(r["PARENT_PROFILE"], r["CHILD_PROFILE"])
                st.graphviz_chart(dot)
        except Exception as e:
            st.info(f"Hierarchy visualization unavailable: {e}")

        st.subheader("Ownership Model")
        st.markdown("""
        | Object Type | Owned By | Driven By |
        |---|---|---|
        | Databases | `<ENV>_SYSADMIN` | ENVIRONMENT_ROLE_METADATA (OWNS_DATABASES) |
        | Schemas | `<ENV>_SYSADMIN` | ENVIRONMENT_ROLE_METADATA (OWNS_SCHEMAS) |
        | Objects (tables, views, etc.) | `<ENV>_USERADMIN` | FUTURE OWNERSHIP grants |
        | Database Roles | `<ENV>_USERADMIN` | ENVIRONMENT_ROLE_METADATA (OWNS_DB_ROLES) |
        | Account Roles (FR/TR) | `<ENV>_USERADMIN` | ENVIRONMENT_ROLE_METADATA (OWNS_ACCOUNT_ROLES) |
        """)

    with tab2:
        st.subheader("Metadata Tables")
        tables_info = {
            "SNOWFLAKE_PRIVILEGE_CATALOG": "Auto-synced from EXPLAIN_GRANTABLE_PRIVILEGES(). Source of truth for all grantable privileges.",
            "ACCESS_PROFILES": "8 access profiles (OWN, DBA, FULL, RW, RO, DO, GOV, SVC) with hierarchy and ownership flags.",
            "ACCESS_PROFILE_PRIVILEGES": "Maps each profile to specific privileges per object type. One privilege per row.",
            "ENVIRONMENT_ROLE_METADATA": "Per-environment account role definitions (SYSADMIN, USERADMIN, ADMIN) with ownership config.",
            "ENVIRONMENTS": "List of environments (DEV, SIT, UAT, PROD, LAB).",
            "FUNCTIONAL_TECHNICAL_ROLE_METADATA": "Functional (FR) and Technical (TR) role naming patterns.",
            "WAREHOUSE_METADATA": "Warehouse templates with all Snowflake options (class, multi-cluster, QAS, timeouts).",
        }
        for tbl, desc in tables_info.items():
            st.markdown(f"- **{tbl}** — {desc}")

        st.subheader("Views")
        views_info = {
            "V_PRIVILEGE_DRIFT": "New Snowflake privileges not yet assigned to any profile.",
            "V_PROFILE_PRIVILEGE_SUMMARY": "Complete matrix of what each profile can do.",
            "V_ROLE_HIERARCHY": "Role inheritance chain.",
            "V_OWNERSHIP_MIGRATION_PLAN": "SQL scripts for ownership migration.",
        }
        for v, desc in views_info.items():
            st.markdown(f"**{v}** - {desc}")

    with tab3:
        st.subheader("Capabilities")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("""
            **Database Lifecycle**
            - Create databases with full RBAC setup
            - Clone with Time Travel + role preservation
            - Schema-level role provisioning
            - Automated ownership transfers

            **Role Management**
            - Functional & Technical role creation
            - Database & schema role assignment
            - Role hierarchy visualization
            - Role revocation with audit trail
            """)
        with col2:
            st.markdown("""
            **Warehouse Management**
            - Standard & Snowpark-optimized classes
            - Multi-cluster with scaling policies
            - Query Acceleration Service
            - All options metadata-driven

            **Governance**
            - Privilege drift detection
            - Auto-sync with Snowflake catalog
            - 8 access profiles (OWN, DBA, FULL, RW, RO, DO, GOV, SVC)
            - Complete audit logging
            """)

        st.subheader("Design Principles")
        st.markdown("""
        | Principle | Implementation |
        |---|---|
        | **Zero hardcoding** | All configuration in metadata tables |
        | **Future-proof** | Auto-detects new Snowflake features via catalog sync |
        | **Parallelized** | Python SPs with ThreadPoolExecutor for GRANT operations |
        | **Auditable** | Every action logged to AUDIT_LOG with full SQL capture |
        | **Multi-environment** | DEV, SIT, UAT, PROD, LAB from ENVIRONMENTS table |
        | **Least privilege** | App runs as PRISM_APP_ROLE, SPs escalate via EXECUTE AS OWNER |
        """)

    with tab4:
        st.subheader("Version")
        version_data = {
            "Version": "2.0.0",
            "Release Date": "25-03-2026",
            "Framework": "Metadata-driven RBAC",
            "Platform": "Streamlit in Snowflake",
        }
        for k, v in version_data.items():
            st.text(f"{k}: {v}")

        st.subheader("Stored Procedures")
        try:
            sp_count = session.sql("SELECT COUNT(*) FROM SECURITY_UNDER_DEVELOPMENT.INFORMATION_SCHEMA.PROCEDURES WHERE PROCEDURE_SCHEMA = 'ACCESS_CONTROL' AND PROCEDURE_NAME LIKE 'SP_%'").collect()[0][0]
            tbl_count = session.sql("SELECT COUNT(*) FROM SECURITY_UNDER_DEVELOPMENT.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'ACCESS_CONTROL' AND TABLE_TYPE = 'BASE TABLE'").collect()[0][0]
            view_count = session.sql("SELECT COUNT(*) FROM SECURITY_UNDER_DEVELOPMENT.INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA = 'ACCESS_CONTROL'").collect()[0][0]
            priv_count = session.sql("SELECT COUNT(*) FROM " + get_fully_qualified_name(CONFIG["TABLES"]["SNOWFLAKE_PRIVILEGE_CATALOG"], include_db=True)).collect()[0][0]
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Stored Procedures", sp_count)
            col2.metric("Metadata Tables", tbl_count)
            col3.metric("Views", view_count)
            col4.metric("Cataloged Privileges", priv_count)
        except Exception as e:
            st.info(f"Could not load stats: {e}")

@st.cache_data(ttl=300)
def get_access_role_suffixes():
    """Fetch distinct role suffixes from ACCESS_PROFILES."""
    try:
        query = f"""
        SELECT ROLE_SUFFIX
        FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILES"])}
        WHERE IS_ACTIVE = TRUE
        ORDER BY HIERARCHY_ORDER
        """
        return session.sql(query).to_pandas()['ROLE_SUFFIX'].tolist()
    except Exception as e:
        st.error(f"Error fetching access role suffixes: {e}")
        return []

@st.cache_data(ttl=300)  # Cache for 5 minutes
def get_role_type_suffixes():
    """Fetch distinct role type suffixes from FUNCTIONAL_TECHNICAL_ROLE_METADATA."""
    try:
        query = f"""
        SELECT DISTINCT SUFFIX
        FROM {get_fully_qualified_name(CONFIG["TABLES"]["ROLE_METADATA"])}
        ORDER BY SUFFIX
        """
        return session.sql(query).to_pandas()['SUFFIX'].tolist()
    except Exception as e:
        st.error(f"Error fetching role type suffixes: {e}")
        return []

def ui_show_database_role_hierarchy():
    """UI for showing database role hierarchy."""
    st.header("Show Database Role Hierarchy")
    
    # Add information about data latency
    st.info("""
    This view shows the complete role hierarchy for the selected database, including:
    1. Database roles and their relationships
    2. Role hierarchy with levels
    3. Root roles and their child roles
    
    Note: Data is sourced from ACCOUNT_USAGE views which may have up to 2 hours latency.
    """)
    
    # Get list of databases
    databases = get_databases()
    
    if not databases:
        st.warning("No databases found in the account.")
        return
        
    # Database selector
    selected_db = st.selectbox(
        "Select Database to View Role Hierarchy",
        options=databases,
        help="Choose a database to view its role hierarchy"
    )
    
    if selected_db:
        # Fetch data
        with st.spinner("Fetching database role hierarchy..."):
            hierarchy_df = get_database_role_hierarchy(selected_db)
        
        # Show visualization if we have data
        if not hierarchy_df.empty:
            try:
                with st.spinner("Generating role hierarchy visualization..."):
                    # Create a graph using graphviz
                    dot = graphviz.Digraph(comment='Database Role Hierarchy')
                    dot.attr(rankdir='TB')
                    
                    # Add nodes and edges
                    for _, row in hierarchy_df.iterrows():
                        # Add parent node
                        dot.node(row['PARENT'], row['PARENT'])
                        # Add child node
                        dot.node(row['CHILD'], row['CHILD'])
                        # Add edge
                        dot.edge(row['PARENT'], row['CHILD'])
                    
                    st.graphviz_chart(dot)
                    
                    # Show detailed information in expander
                    with st.expander("View Role Hierarchy Details"):
                        st.dataframe(hierarchy_df, hide_index=True)
            except Exception as e:
                st.error(f"Error generating visualization: {e}")
                st.text_area("Graphviz DOT Source (for debugging)", dot.source, height=300)
        else:
            st.warning(f"No role hierarchy found for database '{selected_db}'")

def ui_assign_roles():
    """UI for assigning roles."""
    st.header("Assign Roles")
    
    # Information message
    st.info("""
    This interface allows you to assign roles to other roles.
    
    Note: Role assignments may take up to 2 hours to appear in the visualization due to ACCOUNT_USAGE view latency.
    """)
    
    try:
        # Get functional and technical roles
        roles_df = get_functional_technical_roles()
        if roles_df.empty:
            st.warning("No functional or technical roles found in the account.")
            return
            
        roles_list = roles_df['ROLE_NAME'].tolist()
        
        # Create two columns for role selection
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Grant To")
            target_role = st.selectbox(
                "Select role to grant to",
                options=roles_list,
                key="target_role",
                help="The role that will receive the grant"
            )
            
            # Show current grants for the selected target role
            if target_role:
                st.markdown("#### Current Grants for Selected Role")
                current_grants_df = get_current_role_grants(target_role)
                if not current_grants_df.empty:
                    st.dataframe(current_grants_df, hide_index=True)
                else:
                    st.info("No existing role grants found.")
            
        with col2:
            st.markdown("### Role to Grant")
            role_to_grant = st.selectbox(
                "Select role to be granted",
                options=roles_list,
                key="role_to_grant",
                help="The role that will be granted"
            )
        
        # Add a confirmation button
        if st.button("Grant Role", help="Click to execute the role grant"):
            if target_role == role_to_grant:
                st.error("Cannot grant a role to itself!")
            else:
                # Construct and execute the GRANT command
                grant_command = f"GRANT ROLE {role_to_grant} TO ROLE {target_role}"
                try:
                    session.sql(grant_command).collect()
                    
                    # Log the successful grant
                    log_audit_event(
                        "GRANT_ROLE",
                        f"{role_to_grant} TO {target_role}",
                        grant_command,
                        "SUCCESS",
                        f"Granted role {role_to_grant} to {target_role}"
                    )
                    
                    st.success(f"Successfully granted role '{role_to_grant}' to '{target_role}'")
                    
                    # Clear the cache for this role's grants
                    st.cache_data.clear()
                    
                    # Show the updated grants
                    st.markdown("### Updated Grants")
                    updated_grants_df = get_current_role_grants(target_role)
                    if not updated_grants_df.empty:
                        st.dataframe(updated_grants_df, hide_index=True)
                    else:
                        st.info("No grants found after update. Note: There might be a delay in the ACCOUNT_USAGE view update.")
                    
                except Exception as e:
                    st.error(f"Error granting role: {e}")
                    log_audit_event(
                        "GRANT_ROLE",
                        f"{role_to_grant} TO {target_role}",
                        grant_command,
                        "ERROR",
                        str(e)
                    )
                    
    except Exception as e:
        st.error(f"Error in role assignment interface: {e}")

@st.cache_data(ttl=300, show_spinner=False)  # Cache for 5 minutes
def get_database_schemas(database_name):
    """Fetches all schema names in the specified database."""
    if not database_name:
        return []
        
    try:
        # Try direct query first
        query = f"""
        SELECT SCHEMA_NAME 
        FROM {database_name}.INFORMATION_SCHEMA.SCHEMATA
        WHERE SCHEMA_NAME NOT IN ('INFORMATION_SCHEMA')
        ORDER BY SCHEMA_NAME
        """
        schemas_df = session.sql(query).collect()
        schemas = [schema["SCHEMA_NAME"] for schema in schemas_df if schema["SCHEMA_NAME"]]
        
        # If no schemas found, try a different approach with SHOW SCHEMAS
        if not schemas:
            try:
                show_query = f"SHOW SCHEMAS IN DATABASE {database_name}"
                show_schemas_df = session.sql(show_query).collect()
                schemas = [schema["name"] for schema in show_schemas_df 
                          if schema["name"] != "INFORMATION_SCHEMA"]
            except Exception:
                # Silently fail on the second attempt
                pass
                
        return schemas
    except Exception as e:
        # Don't show error in UI, just return empty list
        print(f"Error fetching schemas from database '{database_name}': {e}")
        return []

def get_environment_from_role(role_name):
    """Extract environment prefix from role name."""
    return role_name.split('_')[0] if role_name else None

def is_dark_mode():
    """Check if the user's browser is in dark mode.
    This is a best-effort detection that will default to False.
    """
    # In a real implementation, this would check the browser's color scheme
    # For now, we'll default to False (light mode) for consistency
    return False



@st.cache_data(ttl=300)
def is_governance_user():
    """Check if current user has PRISM_GOV_ROLE. Uses session_state to avoid repeat calls."""
    if "_gov_checked" in st.session_state:
        return st.session_state["_gov_checked"]
    try:
        user = get_current_snowflake_user()
        result = session.sql("SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS WHERE ROLE = 'PRISM_GOV_ROLE' AND GRANTEE_NAME = '" + user + "' AND DELETED_ON IS NULL").collect()
        has_direct = result and result[0][0] > 0
        if has_direct:
            st.session_state["_gov_checked"] = True
            return True
        result2 = session.call("SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_CHECK_GOV_ACCESS", user)
        val = bool(result2)
        st.session_state["_gov_checked"] = val
        return val
    except Exception:
        st.session_state["_gov_checked"] = False
        return False

def ui_gov_policy_audit():
    """Policy audit dashboard."""
    st.header("Policy Audit Dashboard")
    tab1, tab2, tab3 = st.tabs(["Masking Policies", "Row Access Policies", "Tag Assignments"])
    with tab1:
        try:
            df = session.sql("SELECT POLICY_NAME, POLICY_CATALOG AS DATABASE_NAME, POLICY_SCHEMA AS SCHEMA_NAME, POLICY_OWNER, CREATED, LAST_ALTERED FROM SNOWFLAKE.ACCOUNT_USAGE.MASKING_POLICIES WHERE DELETED IS NULL ORDER BY POLICY_NAME").to_pandas()
            st.metric("Total Masking Policies", len(df))
            st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error("An error occurred. Please contact your administrator if this persists.")
    with tab2:
        try:
            df = session.sql("SELECT POLICY_NAME, POLICY_CATALOG AS DATABASE_NAME, POLICY_SCHEMA AS SCHEMA_NAME, POLICY_OWNER, CREATED, LAST_ALTERED FROM SNOWFLAKE.ACCOUNT_USAGE.ROW_ACCESS_POLICIES WHERE DELETED IS NULL ORDER BY POLICY_NAME").to_pandas()
            st.metric("Total Row Access Policies", len(df))
            st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error("An error occurred. Please contact your administrator if this persists.")
    with tab3:
        try:
            df = session.sql("SELECT TAG_NAME, TAG_DATABASE, TAG_SCHEMA, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME, TAG_VALUE, DOMAIN FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES ORDER BY TAG_NAME LIMIT 500").to_pandas()
            st.metric("Tag Assignments", len(df))
            st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error("An error occurred. Please contact your administrator if this persists.")

def ui_gov_tag_manager():
    """Create and apply tags."""
    st.header("Tag Manager")
    tab1, tab2 = st.tabs(["Create Tag", "Apply Tag"])
    with tab1:
        tag_name = st.text_input("Tag Name", key="gt_name").strip().upper()
        tag_comment = st.text_input("Comment", key="gt_comment")
        if st.button("Create Tag", key="gt_create") and tag_name:
            try:
                result = session.call("HORIZON.TAGS.SP_GOV_CREATE_TAG", tag_name, tag_comment, [])
                import json
                r = json.loads(result) if isinstance(result, str) else result
                if r.get("status") == "SUCCESS":
                    st.success(f"Tag created: {r.get('tag_name', tag_name)}")
                else:
                    st.error(r.get("message", "Failed"))
            except Exception as e:
                st.error("An error occurred. Please contact your administrator if this persists.")
    with tab2:
        databases = get_databases()
        target_db = st.selectbox("Database", databases, key="gt_db")
        target_type = st.radio("Apply To", ["TABLE", "SCHEMA", "DATABASE"], key="gt_type", horizontal=True)
        target_schema = ""
        target_table = ""
        target_column = ""
        if target_type in ("TABLE", "SCHEMA") and target_db:
            schemas = get_database_schemas(target_db)
            target_schema = st.selectbox("Schema", schemas if schemas else [], key="gt_schema")
        if target_type == "TABLE" and target_db and target_schema:
            try:
                tables = session.sql(f"SELECT TABLE_NAME FROM {target_db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{target_schema}' AND TABLE_TYPE = 'BASE TABLE' ORDER BY 1").to_pandas()["TABLE_NAME"].tolist()
                target_table = st.selectbox("Table", tables, key="gt_table")
                cols = session.sql(f"SELECT COLUMN_NAME FROM {target_db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{target_schema}' AND TABLE_NAME = '{target_table}' ORDER BY 1").to_pandas()["COLUMN_NAME"].tolist()
                target_column = st.selectbox("Column (optional)", [""] + cols, key="gt_col")
            except: pass
        tag_registry = session.sql("SELECT TAG_NAME FROM HORIZON.TAGS.TAG_REGISTRY WHERE IS_ACTIVE = TRUE ORDER BY 1").to_pandas()["TAG_NAME"].tolist()
        selected_tag = st.selectbox("Tag", tag_registry if tag_registry else [], key="gt_tag")
        tag_val = st.text_input("Tag Value", key="gt_val")
        if st.button("Apply Tag", key="gt_apply") and selected_tag:
            if target_type == "DATABASE":
                fqn = target_db
            elif target_type == "SCHEMA":
                fqn = target_db + "." + target_schema
            else:
                fqn = target_db + "." + target_schema + "." + target_table
            try:
                result = session.call("HORIZON.TAGS.SP_GOV_APPLY_TAG", target_type, fqn, selected_tag, tag_val, target_column if target_column else "")
                import json
                r = json.loads(result) if isinstance(result, str) else result
                if r.get("status") == "SUCCESS":
                    st.success(f"Tag applied: {selected_tag}={tag_val} on {fqn}")
                else:
                    st.error(r.get("message", "Failed"))
            except Exception as e:
                st.error("An error occurred. Please contact your administrator if this persists.")

def ui_gov_masking_policies():
    """Create and apply masking policies."""
    st.header("Masking Policies")
    tab1, tab2, tab3 = st.tabs(["Create from Template", "Apply to Column", "Registry"])
    with tab1:
        templates = session.sql("SELECT TEMPLATE_NAME, DATA_TYPE, DESCRIPTION, MASKED_VALUE_EXAMPLE FROM HORIZON.POLICIES.MASKING_POLICY_TEMPLATES WHERE IS_ACTIVE = TRUE ORDER BY TEMPLATE_NAME, DATA_TYPE").to_pandas()
        st.dataframe(templates, use_container_width=True, hide_index=True)
        st.markdown("---")
        policy_name = st.text_input("Policy Name", key="gm_name").strip().upper()
        col1, col2 = st.columns(2)
        with col1:
            tmpl = st.selectbox("Template", templates["TEMPLATE_NAME"].unique().tolist() if not templates.empty else [], key="gm_tmpl")
        with col2:
            dtype_options = templates[templates["TEMPLATE_NAME"] == tmpl]["DATA_TYPE"].tolist() if tmpl and not templates.empty else []
            dtype = st.selectbox("Data Type", dtype_options, key="gm_dtype")
        auth_role = st.text_input("Authorized Role (sees unmasked data)", key="gm_role").strip().upper()
        comment = st.text_input("Comment", key="gm_comment")
        if st.button("Create Masking Policy", key="gm_create") and policy_name and tmpl and dtype and auth_role:
            try:
                result = session.call("HORIZON.POLICIES.SP_GOV_CREATE_MASKING_POLICY", policy_name, dtype, tmpl, auth_role, comment)
                import json
                r = json.loads(result) if isinstance(result, str) else result
                if r.get("status") == "SUCCESS":
                    st.success(f"Policy created: {r.get('policy_name', policy_name)}")
                else:
                    st.error(r.get("message", "Failed"))
            except Exception as e:
                st.error("An error occurred. Please contact your administrator if this persists.")
    with tab2:
        databases = get_databases()
        db = st.selectbox("Database", databases, key="gm_db")
        schemas = get_database_schemas(db) if db else []
        schema = st.selectbox("Schema", schemas if schemas else [], key="gm_schema")
        tables = []
        if db and schema:
            try:
                tables = session.sql(f"SELECT TABLE_NAME FROM {db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '{schema}' ORDER BY 1").to_pandas()["TABLE_NAME"].tolist()
            except: pass
        tbl = st.selectbox("Table", tables, key="gm_tbl")
        cols = []
        if db and schema and tbl:
            try:
                cols = session.sql(f"SELECT COLUMN_NAME FROM {db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{tbl}' ORDER BY 1").to_pandas()["COLUMN_NAME"].tolist()
            except: pass
        col = st.selectbox("Column", cols, key="gm_col")
        policies = session.sql("SELECT POLICY_NAME FROM HORIZON.POLICIES.POLICY_REGISTRY WHERE IS_ACTIVE = TRUE ORDER BY 1").to_pandas()["POLICY_NAME"].tolist()
        pol = st.selectbox("Masking Policy", policies if policies else [], key="gm_pol")
        if st.button("Apply Masking Policy", key="gm_apply") and db and schema and tbl and col and pol:
            try:
                fqn = db + "." + schema + "." + tbl
                result = session.call("HORIZON.POLICIES.SP_GOV_APPLY_MASKING_POLICY", fqn, col, pol)
                import json
                r = json.loads(result) if isinstance(result, str) else result
                if r.get("status") == "SUCCESS":
                    st.success(f"Masking policy {pol} applied to {fqn}.{col}")
                else:
                    st.error(r.get("message", "Failed"))
            except Exception as e:
                st.error("An error occurred. Please contact your administrator if this persists.")
    with tab3:
        try:
            registry = session.sql("SELECT * FROM HORIZON.POLICIES.POLICY_REGISTRY ORDER BY CREATED_AT DESC").to_pandas()
            st.dataframe(registry, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error("An error occurred. Please contact your administrator if this persists.")

def ui_gov_audit_log():
    """Governance audit log viewer."""
    st.header("Governance Audit Log")
    try:
        df = session.sql("SELECT EVENT_TIME, INVOKED_BY, EVENT_TYPE, OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, OBJECT_TYPE, ACTION_DETAIL, STATUS, MESSAGE FROM HORIZON.AUDIT.GOV_AUDIT_LOG ORDER BY EVENT_TIME DESC LIMIT 200").to_pandas()
        if df.empty:
            st.info("No governance audit events yet.")
        else:
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Events", len(df))
            col2.metric("Unique Users", df["INVOKED_BY"].nunique())
            col3.metric("Event Types", df["EVENT_TYPE"].nunique())
            event_filter = st.multiselect("Filter by Event Type", df["EVENT_TYPE"].unique().tolist(), key="ga_filter")
            if event_filter:
                df = df[df["EVENT_TYPE"].isin(event_filter)]
            st.dataframe(df, use_container_width=True, hide_index=True)
    except Exception as e:
        st.error("An error occurred. Please contact your administrator if this persists.")




def call_ai(mode, user_input, context=""):
    """Call the AI assistant SP with model fallback."""
    try:
        result = session.call("SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_AI_ASSISTANT", mode, user_input, context)
        import json
        return json.loads(result) if isinstance(result, str) else result
    except Exception as e:
        return {"status": "ERROR", "response": str(e)[:300], "ai_available": False}

def ui_ai_command():
    """Natural language command interface."""
    st.header("AI Command")
    st.caption("Describe what you want to do in plain English")
    with st.expander("Supported Commands"):
        st.markdown("""
        | Category | Example |
        |---|---|
        | **Database** | Create database MARKETING in DEV with schemas RAW, STAGE, PUBLISH |
        | **Clone** | Clone PROD_FINANCE to UAT as FINANCE_COPY |
        | **Warehouse** | Create a medium ETL warehouse in SIT |
        | **Roles** | Create a functional role DEVELOPER in DEV |
        | **Environment** | Set up environment roles for PROD |
        | **Tags** | Create a tag called PII_LEVEL |
        | **Masking** | Create a partial email mask authorized for DBA |
        | **Grants** | Grant DEV_ETL_WH to DEV_DEVELOPER_FR |
        """)

    with st.form("ai_command_form"):
        user_cmd = st.text_area("What would you like to do?", height=80, placeholder="e.g. Create a database called ANALYTICS in DEV with schemas BRONZE, SILVER, GOLD")
        col_parse, col_exec = st.columns(2)
        with col_parse:
            parse_btn = st.form_submit_button("Parse & Execute", type="primary", use_container_width=True)
        with col_exec:
            parse_only = st.form_submit_button("Parse Only", use_container_width=True)

    if (parse_btn or parse_only) and user_cmd:
        with st.spinner("AI is parsing your request..."):
            result = call_ai("COMMAND", user_cmd)
        if not result.get("ai_available", True):
            st.warning(result.get("response", "AI not available in this region."))
            return
        if result.get("status") != "SUCCESS":
            st.warning("Could not parse. Please rephrase.")
            return
        resp = result.get("response", "")
        try:
            import json, re
            cleaned = str(resp).strip().strip('"')
            cleaned = re.sub(r"```json?|```", "", cleaned).strip()
            cleaned = cleaned.replace(chr(92)+chr(110), chr(10))
            bs = cleaned.find("{")
            be = cleaned.rfind("}")
            if bs >= 0 and be > bs:
                cleaned = cleaned[bs:be+1]
            parsed = json.loads(cleaned)
            action = parsed.get("action", "")
            params = parsed.get("params", {})
            confirm_msg = parsed.get("confirmation_message", "")
        except:
            st.error("Could not parse AI response. Please try rephrasing.")
            st.code(str(resp)[:500])
            return

        st.markdown("---")
        st.subheader("Parsed Action")
        st.info(confirm_msg)
        c1, c2 = st.columns(2)
        c1.metric("Action", action)
        c2.caption(f"Model: {result.get('model_used', '')}")
        with st.expander("Parameters", expanded=True):
            st.json(params)

        if parse_only:
            st.info("Parsed successfully. Use Parse & Execute to run the action.")
            return

        st.markdown("---")
        with st.spinner("Executing..."):
            try:
                msg = execute_ai_action(action, params)
                st.success(msg)
                st.cache_data.clear()
            except Exception as e:
                st.error("Execution failed. Check parameters and try the manual form.")
                with st.expander("Details"):
                    st.code(str(e)[:500])

def execute_ai_action(action, params):
    """Execute a parsed AI action."""
    if action == "CREATE_DATABASE":
        schemas = params.get("schemas", [])
        schema_csv = ",".join(schemas) if isinstance(schemas, list) else str(schemas)
        sp = get_fully_qualified_name(CONFIG["STORED_PROCEDURES"]["DATABASE_CONTROLLER"])
        env = params.get("env","DEV")
        db = params.get("db_name","")
        session.sql(f"CALL {sp}('{env}','{db}','','','','','','{schema_csv}')").collect()
        return f"Database {env}_{db} created!"
    elif action == "CLONE_DATABASE":
        session.call("SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_CLONE_DATABASE", params.get("source_db",""), params.get("target_db",""), params.get("target_env",""), "CURRENT", "", 0, "", False, False, False, True, True)
        return f"Cloned to {params.get('target_db','')}!"
    elif action == "CREATE_WAREHOUSE":
        session.call("SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_CREATE_WAREHOUSE", params.get("env","DEV"), params.get("wh_type","GEN"), params.get("wh_size","SMALL"), params.get("wh_class","STANDARD"), "", 600, True, True, 1, 1, "STANDARD", False, 8, 172800, 0, 8, "", "", [])
        return "Warehouse created!"
    elif action == "CREATE_ROLE":
        sp = get_fully_qualified_name(CONFIG["STORED_PROCEDURES"]["DATABASE_CONTROLLER"])
        session.sql(f"CALL {sp}('{params.get('env','DEV')}','','','{params.get('function_name','')}','{params.get('role_type','Functional')}','{params.get('db_name','')}','{params.get('access_level','RO_AR')}','')").collect()
        return "Role created!"
    elif action == "SETUP_ENVIRONMENT":
        session.call("SECURITY_UNDER_DEVELOPMENT.ACCESS_CONTROL.SP_SETUP_ENVIRONMENT", params.get("env","DEV"))
        return f"Environment {params.get('env','')} set up!"
    elif action == "CREATE_TAG":
        session.call("HORIZON.TAGS.SP_GOV_CREATE_TAG", params.get("tag_name",""), params.get("comment",""), [])
        return f"Tag {params.get('tag_name','')} created!"
    elif action == "APPLY_TAG":
        session.call("HORIZON.TAGS.SP_GOV_APPLY_TAG", params.get("target_type","TABLE"), params.get("target_fqn",""), params.get("tag_name",""), params.get("tag_value",""), params.get("column_name",""))
        return "Tag applied!"
    elif action == "CREATE_MASKING_POLICY":
        session.call("HORIZON.POLICIES.SP_GOV_CREATE_MASKING_POLICY", params.get("policy_name",""), params.get("data_type","STRING"), params.get("template","FULL_MASK"), params.get("authorized_role",""), "")
        return "Masking policy created!"
    elif action == "APPLY_MASKING_POLICY":
        session.call("HORIZON.POLICIES.SP_GOV_APPLY_MASKING_POLICY", params.get("table_fqn",""), params.get("column_name",""), params.get("policy_name",""))
        return "Masking policy applied!"
    elif action == "ASSIGN_ROLE":
        session.sql(f"GRANT ROLE {params.get('role_to_grant','')} TO ROLE {params.get('target_role','')}").collect()
        return "Role granted!"
    elif action == "REVOKE_ROLE":
        session.sql(f"REVOKE ROLE {params.get('role_to_revoke','')} FROM ROLE {params.get('from_role','')}").collect()
        return "Role revoked!"
    elif action == "ASSIGN_DB_ROLE":
        session.sql(f"GRANT DATABASE ROLE {params.get('db_name','')}.{params.get('db_role_suffix','')} TO ROLE {params.get('target_role','')}").collect()
        return "Database role assigned!"
    elif action == "DELETE_DATABASE":
        db_del = params.get("env","") + "_" + params.get("db_name","") if params.get("env") else params.get("db_name","")
        session.sql(f"DROP DATABASE IF EXISTS {db_del}").collect()
        return f"Database {db_del} deleted!"
    elif action == "GRANT_WAREHOUSE":
        session.sql(f"GRANT USAGE ON WAREHOUSE {params.get('warehouse_name','')} TO ROLE {params.get('role','')}").collect()
        return "Warehouse access granted!"
    else:
        return f"Action {action} not yet supported via AI."
def main():
    # Set page configuration and styling
    st.markdown("""
        <style>
        /* PRISM Adaptive Theme */
        [data-testid="stSidebar"] { padding: 1rem; }
        .sidebar-section { margin-bottom: 1.5rem; }
        .sidebar-section-title {
            font-size: 0.75rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.08em; opacity: 0.6; margin-bottom: 0.5rem;
            padding-bottom: 0.4rem; border-bottom: 1px solid rgba(128,128,128,0.2);
        }
        .sidebar-info-item {
            display: flex; justify-content: space-between; align-items: center;
            margin: 0.35rem 0; padding: 0.5rem 0.7rem;
            background: rgba(128,128,128,0.08); border-radius: 6px;
            border: 1px solid rgba(128,128,128,0.12);
        }
        .sidebar-info-label { font-size: 0.8rem; opacity: 0.6; }
        .sidebar-info-value { font-weight: 600; font-size: 0.85rem; }
        .logo-card {
            background: rgba(255,255,255,0.92); border-radius: 8px;
            padding: 12px 16px; margin-bottom: 0.5rem; text-align: center;
            border: 1px solid rgba(128,128,128,0.1);
        }
        @media (prefers-color-scheme: dark) {
            .logo-card { background: rgba(255,255,255,0.95); }
        }
        .prism-title { font-size: 1.4rem; font-weight: 700; letter-spacing: 0.15em; margin: 0.5rem 0 0.2rem 0; }
        .prism-subtitle { font-size: 0.65rem; opacity: 0.5; letter-spacing: 0.03em; margin-bottom: 1rem; }
        [data-testid="stSidebar"] .stButton button {
            background: rgba(128,128,128,0.06); border: 1px solid rgba(128,128,128,0.15);
            border-radius: 6px; padding: 0.4rem 0.8rem; font-size: 0.85rem;
            transition: all 0.15s ease; text-align: left;
        }
        [data-testid="stSidebar"] .stButton button:hover {
            background: rgba(128,128,128,0.12); border-color: rgba(128,128,128,0.25);
        }
        .version-footer {
            font-size: 0.7rem; opacity: 0.4; text-align: center;
            margin-top: 2rem; padding-top: 1rem;
            border-top: 1px solid rgba(128,128,128,0.15);
        }
        </style>
    """, unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        # Logo and branding
        st.markdown('<div class="logo-card">', unsafe_allow_html=True)
        st.image(SNOWFLAKE_LOGO_URL, width=180)
        st.markdown('</div>', unsafe_allow_html=True)
        st.markdown('<div class="prism-title">PRISM</div>', unsafe_allow_html=True)
        st.markdown('<div class="prism-subtitle">Portal for Role Integration, Security & Management</div>', unsafe_allow_html=True)
        

        
        # Session Information
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-section-title">Current Session</div>', unsafe_allow_html=True)
        current_user = get_current_snowflake_user()
        app_role = get_current_snowflake_role()
        try:
            user_role_result = session.sql("SELECT DEFAULT_ROLE FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE NAME = ? AND DELETED_ON IS NULL LIMIT 1", params=[current_user]).collect()
            user_role = user_role_result[0][0] if user_role_result and user_role_result[0][0] else "Not set"
        except Exception:
            user_role = "N/A"
        
        st.markdown(f'''
            <div class="sidebar-info-item">
                <span class="sidebar-info-label">User:</span>
                <span class="sidebar-info-value">{current_user}</span>
            </div>
            <div class="sidebar-info-item">
                <span class="sidebar-info-label">Default Role:</span>
                <span class="sidebar-info-value">{user_role}</span>
            </div>
            <div class="sidebar-info-item">
                <span class="sidebar-info-label">App Role:</span>
                <span class="sidebar-info-value">{app_role}</span>
            </div>
        ''', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Actions section
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-section-title">Actions</div>', unsafe_allow_html=True)
        
        # Group actions by category
        action_groups = {
            "Database Management": [
                CREATE_DATABASE,
                CLONE_DATABASE,
                DELETE_DATABASE,
                CREATE_WAREHOUSE
            ],
            "Role Management": [
                CREATE_ROLE,
                ASSIGN_ROLES,
                ASSIGN_DATABASE_ROLES,
                REVOKE_ROLES,
                CREATE_ENVIRONMENT_ROLES
            ],
            "Visualization & Analysis": [
                SHOW_ROLE_HIERARCHY,
                SHOW_DATABASE_ROLE_HIERARCHY,
                DISPLAY_RBAC_ARCHITECTURE,
                COST_ANALYSIS
            ],
            "Administration": [
                MANAGE_METADATA,
                PRIVILEGE_DRIFT,
                ACCESS_PROFILES_VIEW,
                AUDIT_LOGS
            ],
            "Information": [
                ABOUT
            ]
        }

        # AI Powered (Beta) - Disabled
        # To enable, uncomment the lines below
        # action_groups["AI Powered (Beta)"] = [AI_COMMAND]

        if is_governance_user():
            action_groups["Governance"] = [
                GOV_POLICY_AUDIT,
                GOV_TAG_MANAGER,
                GOV_MASKING_POLICIES,
                GOV_AUDIT_LOG,
            ]

        # Initialize session state for selected action if not exists
        if 'selected_action' not in st.session_state:
            st.session_state.selected_action = None

        # Create radio buttons for each group
        for group_name, actions in action_groups.items():
            st.markdown(f'<div style="color: #666; font-size: 0.9rem; margin: 1rem 0 0.5rem 0; font-weight: 500;">{group_name}</div>', unsafe_allow_html=True)
            
            # Create a container for each group's actions
            with st.container():
                for action in actions:
                    # Create a custom radio-like button
                    if st.button(
                        action,
                        key=f"btn_{action}",
                        use_container_width=True,
                        type="secondary" if st.session_state.selected_action != action else "primary"
                    ):
                        st.session_state.selected_action = action
                        st.rerun()

        # Get the selected action from session state
        selected_action = st.session_state.selected_action
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Footer information
        st.markdown('<div class="sidebar-section">', unsafe_allow_html=True)
        
        st.markdown('<div class="version-footer">PRISM v2.0.0 | Kalyan Aravapalli</div>', unsafe_allow_html=True)

    # Main content area

   
    # Action Dispatcher
    if selected_action == CREATE_DATABASE:
        ui_create_database()
    elif selected_action == CLONE_DATABASE:
        ui_clone_database()
    elif selected_action == DELETE_DATABASE:
        ui_delete_database()
    elif selected_action == CREATE_WAREHOUSE:
        ui_create_warehouse()
    elif selected_action == CREATE_ROLE:
        ui_create_role()
    elif selected_action == ASSIGN_ROLES:
        ui_assign_roles()
    elif selected_action == ASSIGN_DATABASE_ROLES:
        ui_assign_database_roles()
    elif selected_action == REVOKE_ROLES:
        ui_revoke_roles()
    elif selected_action == CREATE_ENVIRONMENT_ROLES:
        ui_create_environment_roles()    
    elif selected_action == SHOW_ROLE_HIERARCHY:
        ui_show_role_hierarchy()
    elif selected_action == SHOW_DATABASE_ROLE_HIERARCHY:
        ui_show_database_role_hierarchy()
    elif selected_action == DISPLAY_RBAC_ARCHITECTURE:
        ui_display_rbac_architecture()
    elif selected_action == MANAGE_METADATA:
        ui_manage_metadata()
    elif selected_action == PRIVILEGE_DRIFT:
        ui_privilege_drift()
    elif selected_action == ACCESS_PROFILES_VIEW:
        ui_access_profiles()
    elif selected_action == COST_ANALYSIS:
        ui_cost_analysis()    
    elif selected_action == AUDIT_LOGS:
        ui_audit_logs()
    elif selected_action == ABOUT:
        ui_about()    
    elif selected_action == GOV_POLICY_AUDIT:
        ui_gov_policy_audit()
    elif selected_action == GOV_TAG_MANAGER:
        ui_gov_tag_manager()
    elif selected_action == GOV_MASKING_POLICIES:
        ui_gov_masking_policies()
    elif selected_action == GOV_AUDIT_LOG:
        ui_gov_audit_log()
    elif selected_action == AI_COMMAND:
        ui_ai_command()
    else:
        st.info("Select an action from the sidebar to get started.")


def ui_privilege_drift():
    """Display privilege drift analysis - new Snowflake features not yet assigned to any profile."""
    st.header("Privilege Drift Analysis")
    st.markdown("Shows Snowflake privileges that have **not been assigned** to any access profile. Review and assign as needed.")

    try:
        drift_query = f"""
        SELECT OBJECT_TYPE, PRIVILEGE, PARENT_SCOPE, SUPPORTS_ALL, SUPPORTS_FUTURE, LAST_SYNCED_AT
        FROM {get_fully_qualified_name('V_PRIVILEGE_DRIFT')}
        ORDER BY PARENT_SCOPE, OBJECT_TYPE, PRIVILEGE
        """
        drift_df = session.sql(drift_query).to_pandas()

        if drift_df.empty:
            st.success("No privilege drift detected! All Snowflake privileges are assigned to at least one access profile.")
        else:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Unassigned Privileges", len(drift_df))
            with col2:
                st.metric("Object Types Affected", drift_df['OBJECT_TYPE'].nunique())
            with col3:
                if len(drift_df) > 0:
                    st.metric("Last Catalog Sync", str(drift_df['LAST_SYNCED_AT'].iloc[0])[:10])

            scope_filter = st.selectbox("Filter by Scope", ["All", "SCHEMA", "DATABASE"], key="drift_scope")
            if scope_filter != "All":
                drift_df = drift_df[drift_df['PARENT_SCOPE'] == scope_filter]

            st.dataframe(drift_df, use_container_width=True, hide_index=True)

            st.markdown("---")
            st.subheader("Sync Catalog")
            if st.button("Re-sync Privilege Catalog Now", key="sync_catalog"):
                with st.spinner("Syncing from EXPLAIN_GRANTABLE_PRIVILEGES()..."):
                    result = session.sql("CALL SP_SYNC_PRIVILEGE_CATALOG()").collect()
                    st.success(result[0][0])
                    st.cache_data.clear()
                    st.rerun()
    except Exception as e:
        st.error(f"Error loading drift analysis: {e}")


def ui_access_profiles():
    """Display access profiles, their hierarchy, and privilege mappings."""
    st.header("Access Profiles")

    tab1, tab2, tab3 = st.tabs(["Profiles & Hierarchy", "Privilege Matrix", "Profile Details"])

    with tab1:
        st.subheader("Access Profiles")
        try:
            profiles_query = f"""
            SELECT ACCESS_CODE, ROLE_SUFFIX, DESCRIPTION, HIERARCHY_PARENT, HIERARCHY_ORDER,
                   GRANT_SCOPE, APPLIES_AT, IS_SYSTEM_ONLY, IS_ACTIVE
            FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILES"])}
            ORDER BY HIERARCHY_ORDER
            """
            profiles_df = session.sql(profiles_query).to_pandas()
            st.dataframe(profiles_df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Error loading profiles: {e}")

        st.subheader("Role Hierarchy")
        try:
            hierarchy_query = f"""
            SELECT PARENT_PROFILE, CHILD_PROFILE, ROLE_SUFFIX, DEPTH, INHERITANCE_CHAIN, DESCRIPTION
            FROM {get_fully_qualified_name('V_ROLE_HIERARCHY')}
            ORDER BY PARENT_PROFILE, DEPTH
            """
            hierarchy_df = session.sql(hierarchy_query).to_pandas()
            st.dataframe(hierarchy_df, use_container_width=True, hide_index=True)

            st.subheader("Visual Hierarchy")
            try:
                dot = graphviz.Digraph(comment='Role Hierarchy', graph_attr={'rankdir': 'TB', 'bgcolor': 'transparent'})
                dot.attr('node', shape='box', style='rounded,filled', fillcolor='#e8f0fe', fontname='Helvetica')
                dot.attr('edge', color='#4a86c8')

                for _, row in profiles_df.iterrows():
                    label = f"{row['ACCESS_CODE']}\n({row['ROLE_SUFFIX']})"
                    color = '#fff3e0' if row['IS_SYSTEM_ONLY'] else '#e8f0fe'
                    dot.node(row['ACCESS_CODE'], label, fillcolor=color, fontcolor="#1a1a1a")

                for _, row in hierarchy_df.iterrows():
                    dot.edge(row['PARENT_PROFILE'], row['CHILD_PROFILE'])

                st.graphviz_chart(dot)
            except Exception as e:
                st.warning(f"Could not render hierarchy graph: {e}")
        except Exception as e:
            st.error(f"Error loading hierarchy: {e}")

    with tab2:
        st.subheader("Privilege Count by Profile and Object Type")
        try:
            matrix_query = f"""
            SELECT ACCESS_CODE, GRANT_TARGET, OBJECT_TYPE, COUNT(*) AS PRIVILEGE_COUNT,
                   LISTAGG(PRIVILEGE, ', ') WITHIN GROUP (ORDER BY PRIVILEGE) AS PRIVILEGES
            FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILE_PRIVILEGES"])}
            WHERE IS_ACTIVE = TRUE
            GROUP BY ACCESS_CODE, GRANT_TARGET, OBJECT_TYPE
            ORDER BY ACCESS_CODE, GRANT_TARGET, OBJECT_TYPE
            """
            matrix_df = session.sql(matrix_query).to_pandas()

            target_filter = st.selectbox("Grant Target", ["All", "DATABASE", "SCHEMA"], key="matrix_target")
            if target_filter != "All":
                matrix_df = matrix_df[matrix_df['GRANT_TARGET'] == target_filter]

            profile_filter = st.multiselect("Filter Profiles", matrix_df['ACCESS_CODE'].unique().tolist(),
                                          default=matrix_df['ACCESS_CODE'].unique().tolist(), key="matrix_profiles")
            matrix_df = matrix_df[matrix_df['ACCESS_CODE'].isin(profile_filter)]

            st.dataframe(matrix_df, use_container_width=True, hide_index=True)

            st.subheader("Summary")
            summary_query = f"""
            SELECT pp.ACCESS_CODE, ap.DESCRIPTION, pp.GRANT_TARGET, COUNT(*) AS TOTAL_PRIVILEGES
            FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILE_PRIVILEGES"])} pp
            JOIN {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILES"])} ap ON pp.ACCESS_CODE = ap.ACCESS_CODE
            WHERE pp.IS_ACTIVE = TRUE
            GROUP BY pp.ACCESS_CODE, ap.DESCRIPTION, pp.GRANT_TARGET
            ORDER BY pp.ACCESS_CODE, pp.GRANT_TARGET
            """
            summary_df = session.sql(summary_query).to_pandas()
            st.dataframe(summary_df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Error loading privilege matrix: {e}")

    with tab3:
        st.subheader("Profile Detail Viewer")
        try:
            profiles = session.sql(f"""
                SELECT ACCESS_CODE FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILES"])}
                WHERE IS_ACTIVE = TRUE ORDER BY HIERARCHY_ORDER
            """).to_pandas()['ACCESS_CODE'].tolist()

            selected_profile = st.selectbox("Select Profile", profiles, key="profile_detail")

            detail_query = f"""
            SELECT OBJECT_TYPE, PRIVILEGE, GRANT_TARGET, NOTES, ADDED_AT, ADDED_BY
            FROM {get_fully_qualified_name(CONFIG["TABLES"]["ACCESS_PROFILE_PRIVILEGES"])}
            WHERE ACCESS_CODE = '{selected_profile}' AND IS_ACTIVE = TRUE
            ORDER BY GRANT_TARGET, OBJECT_TYPE, PRIVILEGE
            """
            detail_df = session.sql(detail_query).to_pandas()

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Database-Level Privileges", len(detail_df[detail_df['GRANT_TARGET'] == 'DATABASE']))
            with col2:
                st.metric("Schema-Level Privileges", len(detail_df[detail_df['GRANT_TARGET'] == 'SCHEMA']))

            st.dataframe(detail_df, use_container_width=True, hide_index=True)
        except Exception as e:
            st.error(f"Error loading profile details: {e}")


if __name__ == "__main__":
    main()
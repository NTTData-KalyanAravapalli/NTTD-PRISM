# PRISM Deployment Package v2.0.0
Portal for Role Integration, Security & Management

## Quick Start
1. Edit `config.sql` - set DB names, warehouse, admin user
2. Upload `streamlit/` files to the stage (see Step 8)
3. Run `00_install.sql`

## Files
| File | Description |
|---|---|
| config.sql | Customer settings (EDIT THIS) |
| 00_install.sql | Master installer |
| 01_prerequisites.sql | Roles + grants |
| 02_databases.sql | 3 databases + schemas |
| 03_tables.sql | 13 tables + sequences |
| 04_seed_data.sql | 267 privileges, 8 profiles, etc |
| 05_views.sql | 4 views |
| 06_procedures.sql | 21 stored procedures |
| 07_governance.sql | Tags + masking SPs |
| 08_streamlit.sql | Streamlit app creation |
| 09_tasks.sql | Weekly catalog sync |
| 10_post_install.sql | Verification |
| uninstall.sql | Clean removal |
| streamlit/ | App files (upload to stage) |

## Prerequisites
- ACCOUNTADMIN role
- Active warehouse

## What Gets Created
- 3 databases, 6 schemas
- 2 roles: PRISM_APP_ROLE, PRISM_GOV_ROLE
- 21 stored procedures
- 4 views, 1 task, 1 Streamlit app

## Uninstall
Run `uninstall.sql` (loads config.sql first)

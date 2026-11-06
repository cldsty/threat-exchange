#!/bin/sh
# Runs once, when the database volume is created. The service connects as a role
# without rights to change the schema; migrations grant it access to the tables.
set -eu

psql -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" \
    --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
CREATE ROLE threats_app LOGIN PASSWORD :'app_password';
SQL

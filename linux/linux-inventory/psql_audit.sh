#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <psql_user> <psql_password> <data_path> <psql host>"
    exit 1
fi



PSQL_USER="$1"
export PGPASSWORD="$2"
PSQL_HOST="$4"
DATA_PATH="$3"
echo "PSQL Auditing"


mkdir $DATA_PATH
cd $DATA_PATH

# List all databases
psql -h "$PSQL_HOST" -U "$PSQL_USER" -t -c "SELECT datname FROM pg_database;" > database_list.txt
let numlines="$(wc -l < database_list.txt) - 1"
head -n $numlines database_list.txt > tmp.txt; mv tmp.txt database_list.txt

echo "List of Databases:"
cat database_list.txt

while read selected_db; do
    
    psql -h "$PSQL_HOST" -U "$PSQL_USER" $selected_db -c "
    SELECT grantor,grantee,table_name,privilege_type,is_grantable,with_hierarchy
    FROM information_schema.role_table_grants WHERE table_catalog='${selected_db}' AND table_schema = 'public';" > $selected_db.txt
done <database_list.txt

echo "PSQL Auditing finished"


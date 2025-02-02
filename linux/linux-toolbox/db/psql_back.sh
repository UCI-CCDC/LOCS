#!/usr/bin/env sh

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <psql host> <psql_user> <psql_password> <data_path>"
    exit 1
fi


PSQL_HOST="$1"
PSQL_USER="$2"
export PGPASSWORD="$3"
DATA_PATH="$4"
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
    pg_dump -h "$PSQL_HOST" -U "$PSQL_USER" -d $selected_db > "$selected_db.sql"
done <database_list.txt

echo "PSQL Auditing finished"
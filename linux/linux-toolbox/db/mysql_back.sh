#!/usr/bin/env sh


if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <mysql_host> <mysql_user> <mysql_password> <path>"
    exit 1
fi


sep () {
    echo "======================================================================================================="
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}


MYSQL_HOST="$1"
MYSQL_USER="$2"
MYSQL_PASSWORD="$3"
DATA_PATH="$4"

mkdir $DATA_PATH
cd $DATA_PATH



echo "MySQL backups"
sep


databases=`mysql -h $MYSQL_HOST -u $MYSQL_USER --password=$MYSQL_PASSWORD -e "SHOW DATABASES;" | tr -d "| " | grep -v Database`
echo "$databases"
for db in $databases; do
    if [[ "$db" != "information_schema" ]] && [[ "$db" != "performance_schema" ]] && [[ "$db" != "mysql" ]] && [[ "$db" != _* ]] ; then
        echo "Dumping database: $db"
        mysqldump -h $MYSQL_HOST -u $MYSQL_USER --password=$MYSQL_PASSWORD --databases $db > $db.sql
       # gzip $OUTPUT/`date +%Y%m%d`.$db.sql
    fi
done



echo "MySQL backups Finished"

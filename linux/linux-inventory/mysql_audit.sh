#!/bin/sh

if [ "$(id -u)" -ne 0 ]; then
    printf 'Must be run as root, exiting!\n'
    exit 1
fi

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <mysql_user> <mysql_password> <path> <mysql_host>"
    exit 1
fi


sep () {
    echo "======================================================================================================="
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}


MYSQL_USER="$1"
MYSQL_PASSWORD="$2"
DATA_PATH="$3"

mkdir $DATA_PATH
cd $DATA_PATH

MYSQL_HOST="$4"

echo "MySQL Auditing"
sep


# Make sure MySQL logging is enabled

mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -e "SET GLOBAL general_log = 'ON';"
mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -e "SET GLOBAL log_output = 'FILE';"
mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -e "SET GLOBAL general_log_file = '/var/log/mysql.log'"
        
echo "MySQL logging has been enabled. Log file is on /var/log/mysql.log"

sep


# Log into MySQL and list databases
mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -h "$MYSQL_HOST" -e "SHOW DATABASES;" | awk '{if(NR>1) print $1}' > database_list.txt



# Get a list of all users

mysql -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -h "$MYSQL_HOST" -e "SELECT user, host FROM mysql.user;" | tail -n +2 | grep -vE '^performance|^mysql' > user_list.txt



if [ $? -ne 0 ]; then
    echo "Error: Unable to retrieve the list of users."
    exit 1
fi


while read selected_db; do
    
    sep
    echo "Enumerating $selected_db into $DATA_PATH/$selected_db.txt" 

    echo "GRANTS FOR DATABASE: $selected_db" > $selected_db.txt
    sep >> $selected_db.txt

    # # Iterate over each user and show grants
    while read -r user host; do
        
        echo "Grants for user '$user'@'$host':" >> $selected_db.txt
        
        mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -D "$selected_db" -e "SHOW GRANTS FOR '$user'@'$host';" | grep -vE '^Grants|^\+' >> $selected_db.txt
        dash_sep >> $selected_db.txt
    done < user_list.txt

    sep >> $selected_db.txt
    echo "Users with DROP, ALTER for database '$selected_db':" >> $selected_db.txt
    dash_sep >> $selected_db.txt
    
    mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -D "$selected_db" -e "SELECT user, host FROM mysql.user WHERE Drop_priv='Y' OR ALTER_priv='Y';" | tail -n +2 >> $selected_db.txt


    sep >> $selected_db.txt
    echo "Users with UPDATE, INSERT, CREATE, or DELETE privileges for database '$selected_db':" >> $selected_db.txt
    dash_sep >> $selected_db.txt
    
    mysql -u "$MYSQL_USER" --password="$MYSQL_PASSWORD" -h "$MYSQL_HOST" -D "$selected_db" -e "SELECT user, host FROM mysql.user WHERE Update_priv='Y' OR Insert_priv='Y' OR Create_priv='Y' OR Delete_priv='Y';" | tail -n +2 >> $selected_db.txt


done <database_list.txt
sep



echo "MySQL Audit Finished"

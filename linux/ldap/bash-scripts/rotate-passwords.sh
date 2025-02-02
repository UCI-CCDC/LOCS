#!/bin.bash
read -sp "manager pass:" mpass
echo ""
ldapsearch -x -LLL -b ou=People,dc=solar,dc=system -w "$mpass" uid | grep "uid:" | awk '{print $2}' | while read username; do
    new=$(openssl rand -base64 9)
    echo "$username,$new"
    ldappasswd -x -D cn=Manager,dc=solar,dc=system -w "$mpass" -s "$new" "uid=$username,ou=People,dc=solar,dc=system"
done
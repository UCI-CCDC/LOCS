#!/usr/bin/env bash

sep () {
    echo "======================================================================================================="
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}

empty_line () {
    echo ""
}

get_users() {
   grep "^$1:" /etc/group | cut -d: -f4 | tr ',' '\n'
}

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

# POSIX moment
stringContain() { case $2 in *$1* ) return 0;; *) return 1;; esac ;}

HOSTNAME=$(hostname || cat /etc/hostname)
IP_ADDR=$( ( ip a | grep -oE '([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}/[[:digit:]]{1,2}' | grep -v '127.0.0.1' ) || ( ifconfig | grep -oE 'inet.+([[:digit:]]{1,3}\.){3}[[:digit:]]{1,3}' | grep -v '127.0.0.1' ) )
OS=$( (hostnamectl | grep "Operating System" | cut -d: -f2) || (cat /etc/*-release  | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//' | sed 's/"//g') )

empty_line
echo -e "$HOSTNAME Summary"
sep
empty_line

printf "Hostname: "
echo -e $HOSTNAME
sep
empty_line

printf "IP Address: "
echo -e $IP_ADDR
sep
empty_line

printf "Script User: "
echo -e $USER
sep
empty_line

printf "Operating System: "
echo -e $OS
sep
empty_line

if command -v transactional-update; then
    echo "Transactional Server"
    dash_sep
    transactional-update status
    sep
    empty_line
fi

echo "Open ports and PIDs:"
dash_sep
if command_exists ss; then
    ss -tulpn | sort -k 1,1 -k 2,2 | awk 'NR==1; NR>1{print | "sort -V -k 4,4"}' | sed '1 s/Process/Process                     /'
elif command_exists sockstat; then
    sockstat -4
elif command_exists netstat; then
    netstat -an | grep LISTEN
elif command_exists lsof; then
    lsof -i -P -n | grep LISTEN
else
    echo "required tools for this section not found"
fi
sep
empty_line
echo "Running Container information:"
dash_sep

if ! command_exists docker; then
    echo "Docker command not found. Skipping..."
else
    running_container_info=$(docker ps --format "{{.Names}}\t{{.Status}}\t{{.Ports}}")

    if [ -z "$running_container_info" ]; then
        echo "No running containers found."
    else
        printf "%-34s %-40s %-30s\n" "Container Name" "Internal Ports" "External Ports"

        echo "$running_container_info" | while IFS=$'\t' read -r container_name status ports; do
	    if ! stringContain "(Paused)" "$status"; then
                # Extract internal and external ports
                internal_ports=$(echo "$ports" | awk -F '->' '{print $1}' | tr ',' '\n' | awk -F '/' '{print $1}' | tr '\n' ',')
                external_ports=$(echo "$ports" | awk -F '->' '{print $2}' | awk -F ',' '{print $1}' | tr '\n' ',')

                # Remove trailing commas
                internal_ports=$(echo "$internal_ports" | sed 's/,$//')
                external_ports=$(echo "$external_ports" | sed 's/,$//')
		
		if [ -z "$internal_ports" ]; then
			internal_ports="N/A"
		fi

		if [ -z "$external_ports" ]; then
			external_ports="N/A"
		fi
                # Print container information with consistent spacing
                printf "[+] %-30s %-40s %-30s\n" "$container_name" "$internal_ports" "$external_ports"
            fi
        done
    fi

    echo
    echo "Non-Running Container information:"
    dash_sep

    # Get non-running container information
    non_running_container_info=$(docker ps -a --filter "status=exited" --filter "status=paused" --filter "status=dead" --filter "status=restarting" --format "{{.Names}}\t{{.Status}}")

    # Check if there are non-running containers
    if [ -z "$non_running_container_info" ]; then
        echo "No non-running containers found."
    else
        # Print header for non-running containers
        printf "%-34s %-30s\n" "Container Name" "Status"

        # Iterate over each non-running container and print information
        echo "$non_running_container_info" | while IFS=$'\t' read -r container_name status; do
            # Print container information with consistent spacing
            printf "[-] %-30s %-30s\n" "$container_name" "$status"
        done
    fi
fi
sep
empty_line

echo "Human users"
dash_sep
awk -F: '{if (($3 >= 1000 || $1 == "root") && $1 != "nobody") printf "Username: %-15s UID: %-5s Home: %-20s Shell: %s\n", $1, $3, $6, $7}' /etc/passwd
sep
empty_line

echo "Admin users (sudo or wheel):"
dash_sep
get_users sudo
get_users wheel
sep
empty_line

if [ -e "/etc/krb5.conf" ]; then
    echo "MACHINE IS DOMAIN JOINED"
    dash_sep
    printf "Domain: "
    grep -o "^.*default_realm.*=.*" /etc/krb5.conf | awk '{print $3}'
    sep
    empty_line
else
    echo "MACHINE IS NOT DOMAIN JOINED"
    dash_sep
    echo "NO DOMAIN"
    sep
    empty_line
fi

echo "MOUNTS:"
dash_sep
grep -v '^#' /etc/fstab
sep
empty_line

echo "Processes possibly tied to services:"
dash_sep
ps aux | awk 'NR==1; /docker|samba|postfix|dovecot|smtp|psql|ssh|clamav|mysql|bind9|apache|smbfs|samba|openvpn|splunk|nginx|mysql|mariadb|ftp|slapd|amavisd|wazuh/ && !/awk/ {print $0}' | grep -v "grep"
sep
empty_line

if command -v kubectl; then
    echo "KUBERNETES:"
    dash_sep
    k=$(kubectl get nodes $HOSTNAME 2>/dev/null | grep "control-plane")
    if [ -z "$k" ]; then
        echo "THIS IS A KUBERNETES WORKER NODE"
    else
        echo "THIS IS A KUBERNETES CONTROL PLANE NODE"
        dash_sep
        kubectl get nodes -o wide
    fi
    sep
    empty_line
else
    echo "KUBERNETES NOT INSTALLED"
    dash_sep
    sep
    empty_line
fi


echo "Installed services (NOT NECESSARILY CRITICAL):"
dash_sep
sep

[ -e "/etc/ssh/sshd_config" ] && echo "OpenSSH"

[ -e "/etc/dropbear/dropbear_config" ] || [ -e "/etc/dropbear/config" ] || [ -e "/etc/default/dropbear" ] && echo "Dropbear"

[ -e "/etc/apache2/apache2.conf" ] || [ -e "/etc/apache2/httpd.conf" ] || [ -e "/etc/httpd/httpd.conf" ] && echo "Apache2"

[ -e "/etc/nginx/nginx.conf" ] || [ -e "/usr/local/nginx/conf/nginx.conf" ] && echo "Nginx"

[ -e "/etc/vsftpd.conf" ] || [ -e "/etc/vsftpd/vsftpd.conf" ] && echo "vsftpd"

[ -e "/etc/proftpd.conf" ] || [ -e "/etc/proftpd/proftpd.conf" ] && echo "ProFTPD"

[ -e "/etc/pure-ftpd.conf" ] || [ -e "/etc/pure-ftpd/pure-ftpd.conf" ] && echo "Pure-FTPd" 

[ -e "/etc/samba/smb.conf" ] && echo "Samba"

[ -e "/etc/postfix/main.cf" ] && echo "Postfix"

[ -e "/etc/dovecot/dovecot.conf" ] && echo "Dovecot"

[ -e "/etc/mail/sendmail.cf" ] && echo "Sendmail"

[ -e "/etc/exim4/exim4.conf" ] && echo "Exim"

[ -e "/etc/cups/cupsd.conf" ] && echo "CUPS"

[ -e "/etc/unrealircd/unrealircd.conf" ] && echo "UnrealIRCD"

[ -e "/etc/inspircd/inspircd.conf" ] && echo "InspIRCd" 

[ -e "/etc/openvpn/server.conf" ] && echo "OpenVPN"

[ -e "/etc/mysql/my.cnf" ] || [ -e "/etc/my.cnf" ] || [ -e "/usr/etc/my.cnf" ] || [ -e "/etc/mysql/mysql.conf.d/mysqld.cnf" ] && echo "MySQL"

[ -e "/etc/mongod.conf" ] || [ -e "/etc/mongodb.conf" ] && echo "MongoDB"

[ -e "/etc/redis/redis.conf" ] && echo "Redis"

[ -e "/etc/postgresql/postgresql.conf" ] && echo "PostgreSQL"

[ -e "/var/ossec/etc/ossec.conf" ] && echo "Wazuh"

[ -e "/opt/splunk/etc/system/local/web.conf" ] && echo "Splunk"

[ -e "/var/lib/docker/containers" ] && echo "Docker"

[ -e "/etc/php5/apache2/php.ini" ] && echo "PHP5 (apache2)"
[ -e "/etc/php5/cli/php.ini" ] && echo "PHP5 (cli)"
[ -e "/etc/php/7.0/apache2/php.ini" ] && echo "PHP7.0 (apache2)"
[ -e "/etc/php/7.0/cli/php.ini" ] && echo "PHP7.0 (cli)"
[ -e "/etc/php/7.1/apache2/php.ini" ] && echo "PHP7.1 (apache2)"
[ -e "/etc/php/7.1/cli/php.ini" ] && echo "PHP7.1 (cli)"
[ -e "/etc/php/7.2/apache2/php.ini" ] && echo "PHP7.2 (apache2)"
[ -e "/etc/php/7.2/cli/php.ini" ] && echo "PHP7.2 (cli)"
[ -e "/etc/php/7.3/apache2/php.ini" ] && echo "PHP7.3 (apache2)"
[ -e "/etc/php/7.3/cli/php.ini" ] && echo "PHP7.3 (cli)"
[ -e "/etc/php/7.4/apache2/php.ini" ] && echo "PHP7.4 (apache2)"
[ -e "/etc/php/7.4/cli/php.ini" ] && echo "PHP7.4 (cli)"
[ -e "/etc/php/8.0/apache2/php.ini" ] && echo "PHP8.0 (apache2)"
[ -e "/etc/php/8.0/cli/php.ini" ] && echo "PHP8.0 (cli)"
[ -e "/etc/php/8.1/apache2/php.ini" ] && echo "PHP8.1 (apache2)"
[ -e "/etc/php/8.1/cli/php.ini" ] && echo "PHP8.1 (cli)"
[ -e "/etc/php5/fpm/php.ini" ] && echo "PHP5 (fpm)"
[ -e "/etc/php/7.0/fpm/php.ini" ] && echo "PHP7.0 (fpm)"
[ -e "/etc/php/7.1/fpm/php.ini" ] && echo "PHP7.1 (fpm)"
[ -e "/etc/php/7.2/fpm/php.ini" ] && echo "PHP7.2 (fpm)"
[ -e "/etc/php/7.3/fpm/php.ini" ] && echo "PHP7.3 (fpm)"
[ -e "/etc/php/7.4/fpm/php.ini" ] && echo "PHP7.4 (fpm)"
[ -e "/etc/php/8.0/fpm/php.ini" ] && echo "PHP8.0 (fpm)"
[ -e "/etc/php/8.1/fpm/php.ini" ] && echo "PHP8.1 (fpm)"
[ -e "/etc/php.ini" ] && echo "PHP (unknown)"


sep

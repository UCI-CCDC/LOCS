#!/usr/bin/env bash

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "==================="

if [ $# -eq 0 ]; then
    echo "Usage: $0 <svc_name>"
    echo "SSH, FTP, APACHE, NGINX, SMB"
    exit 1
else 
    svc_name=$1
fi

if [ "$svc_name" = "FTP" ] ; then
    echo "FTP"
    echo "---"
    cat /etc/*ftp* | grep -v '#' | grep -E 'anonymous_enable|guest_enable|no_anon_password|write_enable|local_root|anon_root'
fi

if [ "$svc_name" = "APACHE" ] ; then
    echo "APACHE"
    echo "------"

    [ -e "/etc/httpd/conf/httpd.conf" ] && tail -n +1 /etc/httpd/conf/httpd.conf | grep -v '#' |grep -E '==>|VirtualHost|^[^[\t]ServerName|DocumentRoot|^[^[\t]ServerAlias|^[^[\t]*Proxy*'

    [ -e "/etc/httpd/conf/httpd.conf" ] && tail -n +1 /etc/httpd/conf.d/* | grep -v '#' |grep -E '==>|Directory|VirtualHost|^[^[\t]ServerName|DocumentRoot|^[^[\t]ServerAlias|^[^[\t]*Proxy*'


    [ -e "/etc/apache2/httpd.conf" ] && tail -n +1 /etc/apache2/httpd.conf | grep -v '#' |grep -E '==>|VirtualHost|^[^[\t]ServerName|DocumentRoot|^[^[\t]ServerAlias|^[^[\t]*Proxy*'
    

    [ -e "/etc/apache2/sites-enabled" ] && tail -n +1 /etc/apache2/sites-enabled/* | grep -v '#' |grep -E '==>|VirtualHost|^[^[\t]ServerName|DocumentRoot|^[^[\t]ServerAlias|^[^[\t]*Proxy*'

fi

if [ "$svc_name" = "NGINX" ] ; then
    echo "NGINX"
    echo "-----"

    [ -e "/etc/nginx/nginx.conf" ] && tail -n +1 /etc/nginx/nginx.conf | grep -v '#'  | grep -E '==>|server|^[^[\t]listen|^[^[\t]root|^[^[\t]server_name|proxy_*'

    [ -e "/etc/nginx/sites-enabled" ] && tail -n +1 /etc/nginx/sites-enabled/* | grep -v '#'  | grep -E '==>|server|^[^[\t]listen|^[^[\t]root|^[^[\t]server_name|proxy_*'
fi

if [ "$svc_name" = "SMB" ] ; then
    echo "SMB"
    echo "---"
    grep -E -A 6 "^\s*\[(.+)\]" /etc/samba/smb.conf | grep -v "^\s*#" | grep -v "^\s*$"
fi

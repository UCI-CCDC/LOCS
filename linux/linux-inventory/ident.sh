#!/usr/bin/env bash

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

FOUND=false

check_samba() {
    if command_exists net; then
        local IP_ADDRESS
        IP_ADDRESS=$(net ads info | grep 'LDAP server:' | awk '{print $3}')
        if [ -n "$IP_ADDRESS" ]; then
            echo "DC address from Samba: $IP_ADDRESS"
            FOUND=true
        else
            echo 'Got blank IP address from Samba, skipping'
        fi
    else
        echo 'net not found, skipping samba check'
    fi
}

check_resolvectl() {
    if command_exists resolvectl; then
        local REALM
        REALM=$(resolvectl domain | grep -E ': (.*)' -o | awk '{print $2}' | tail -1)
        local IP_ADDRESS
        IP_ADDRESS=$(resolvectl query "$REALM" | grep "$REALM: " | awk '{print $2}')
        if [ -n "$IP_ADDRESS" ]; then
            echo "DC address from resolvectl: $IP_ADDRESS"
            FOUND=true
        else
            echo 'Got blank IP address from resolvectl, skipping'
        fi
    else
        echo 'resolvectl not found, skipping systemd-resolved check'
    fi
}

check_krb() {
    if [ ! -f "/etc/krb5.conf" ]; then
        echo 'krb5.conf not found, skipping kerberos check'
    else
        local REALM
        REALM=$(grep '^[[:space:]]*default_realm' "/etc/krb5.conf" | awk '{print $3}')
        local IP_ADDRESS
        IP_ADDRESS=$(nslookup "$REALM" 2>/dev/null | grep 'Address' | tail -n 1 | awk '{print $2}')
        if [ -n "$IP_ADDRESS" ]; then
            echo "DC address from kerberos: $IP_ADDRESS"
            FOUND=true
        else
            echo 'Got blank IP address from kerberos, skipping'
        fi
    fi
}

check_sssd() {
    if [ ! -f "/etc/sssd/sssd.conf" ]; then
        echo 'sssd.conf not found, skipping kerberos check'
    else
        local REALM
        REALM=$(sed -n 's/^\[domain\/\(.*\)\]/\1/p' /etc/sssd/sssd.conf)
        local IP_ADDRESS
        IP_ADDRESS=$(nslookup "$REALM" 2>/dev/null | grep 'Address' | tail -n 1 | awk '{print $2}')
        if [ -n "$IP_ADDRESS" ]; then
            echo "DC address from sssd: $IP_ADDRESS"
            FOUND=true
        else
            echo 'Got blank IP address from sssd, skipping'
        fi
    fi
}

check_samba
check_resolvectl
check_krb
check_sssd

if [ $FOUND = true ]; then
    exit 0
else
    exit 1
fi


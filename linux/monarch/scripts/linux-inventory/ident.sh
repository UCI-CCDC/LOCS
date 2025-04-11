#!/bin/sh

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

FOUND=false

check_samba() {
    if command_exists net; then
        SAMBA_IP_ADDRESS=$(net ads info | grep 'LDAP server:' | awk '{print $3}')
        if [ -n "$SAMBA_IP_ADDRESS" ]; then
            echo "DC address from Samba: $SAMBA_IP_ADDRESS"
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
        RESOLVECTL_REALM=$(resolvectl domain | grep -E ': (.*)' -o | awk '{print $2}' | tail -1)
        RESOLVECTL_IP_ADDRESS=$(resolvectl query "$RESOLVECTL_REALM" | grep "$RESOLVECTL_REALM: " | awk '{print $2}')
        if [ -n "$RESOLVECTL_IP_ADDRESS" ]; then
            echo "DC address from resolvectl: $RESOLVECTL_IP_ADDRESS"
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
        KRB_REALM=$(grep '^[[:space:]]*default_realm' "/etc/krb5.conf" | awk '{print $3}')
        KRB_IP_ADDRESS=$(nslookup "$KRB_REALM" 2>/dev/null | grep 'Address' | tail -n 1 | awk '{print $2}')
        if [ -n "$KRB_IP_ADDRESS" ]; then
            echo "DC address from kerberos: $KRB_IP_ADDRESS"
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
        SSSD_REALM=$(sed -n 's/^\[domain\/\(.*\)\]/\1/p' /etc/sssd/sssd.conf)
        SSSD_IP_ADDRESS=$(nslookup "$SSSD_REALM" 2>/dev/null | grep 'Address' | tail -n 1 | awk '{print $2}')
        if [ -n "$SSSD_IP_ADDRESS" ]; then
            echo "DC address from sssd: $SSSD_IP_ADDRESS"
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


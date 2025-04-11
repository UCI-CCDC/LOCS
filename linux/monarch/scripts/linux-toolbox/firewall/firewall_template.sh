#!/bin/sh
# Check if iptables is installed.
check() {
    if ! command -v iptables >/dev/null 2>&1
    then
        echo 'fw.sh: iptables is not installed! Exiting.'
        exit 1
    fi
}


# Flush existing firewall configuration.
# Also saves old firewall config as a backup.
flush() {
    # Stop other firewall stuff that might be annoying
    systemctl stop firewalld || true
    systemctl stop ufw || true
    # Save existing iptables config before flushing it all
    iptables-save > /root/iptables-"$(date +%s)".rules
    # Flush all rules and allow all connections by default
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT


    iptables -F INPUT
    iptables -F OUTPUT
    iptables -F INPUT_ACCEPT
    iptables -F INPUT_DROP
    iptables -F OUTPUT_ACCEPT
    iptables -F OUTPUT_DROP

    iptables -F FORWARD_LOG
    iptables -F fw-fwd
    iptables -D FORWARD -j fw-fwd
}


setup_logging() {
    iptables -N INPUT_ACCEPT
    iptables -N OUTPUT_ACCEPT
    iptables -N FORWARD_LOG
    iptables -N fw-fwd

    iptables -N INPUT_DROP
    iptables -N OUTPUT_DROP

    # Don't actually to anything else but log
    iptables -A FORWARD_LOG -j LOG --log-prefix "[FORWARD_LOG]"

    iptables -A INPUT_ACCEPT -j LOG --log-prefix "[INPUT_ACCEPT]"
    iptables -A INPUT_ACCEPT -j ACCEPT

    iptables -A OUTPUT_ACCEPT -j LOG --log-prefix "[OUTPUT_ACCEPT]"
    iptables -A OUTPUT_ACCEPT -j ACCEPT

    iptables -A OUTPUT_DROP -j LOG --log-prefix "[OUTPUT_DROP]"
    iptables -A OUTPUT_DROP -j DROP

    iptables -A INPUT_DROP -j LOG --log-prefix "[INPUT_DROP]"
    iptables -A INPUT_DROP -j DROP
}

ensure_set() {
    if [ -z "$1" ]
    then
        echo "fw.sh: No $2 set! Please set this first"
        exit 1
    fi
}

# Apply a firewall.
# Parameters:
#     command: A command to run before applying the firewall.
apply() {
    local_subnet1=""
    local_subnet2=""
    ensure_set "$local_subnet1" "Local subnet 1"
    ensure_set "$local_subnet2" "Local subnet 2"

    # Check if iptables is installed before doing anything damaging.
    check
    # Flush current iptables configuration to make sure we are working with a clean slate.
    flush
    # Run a command before applying all firewall rules.
    if [ -n "$1" ]
    then
        echo "fw.sh: Evaluating pre-apply command '$1'"
        eval "$1"
    fi

    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT

    setup_logging


    # Input
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j INPUT_ACCEPT
    iptables -A INPUT -p tcp -m multiport --dports 25,143,110,80,443 -j INPUT_ACCEPT
    ## DB
    iptables -A INPUT -p tcp -s "$local_subnet1" -m multiport --dport 3306,5432,27017 -j INPUT_ACCEPT
    iptables -A INPUT -p tcp -s "$local_subnet2" -m multiport --dport 3306,5432,27017 -j INPUT_ACCEPT
    iptables -A INPUT -p tcp -s "$local_subnet1" -m multiport --sport 3306,5432,27017 -j INPUT_ACCEPT
    iptables -A INPUT -p tcp -s "$local_subnet2" -m multiport --sport 3306,5432,27017 -j INPUT_ACCEPT
    ## ICMP
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -j INPUT_DROP

    # Output
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    ## CCS
    iptables -A OUTPUT -p tcp -d 10.120.0.111 -j ACCEPT
    iptables -A OUTPUT -p udp -d 10.120.0.111 -j ACCEPT
    ## DB
    iptables -A OUTPUT -p tcp -d "$local_subnet1" -m multiport --dport 3306,5432,27017 -j OUTPUT_ACCEPT
    iptables -A OUTPUT -p tcp -d "$local_subnet2" -m multiport --dport 3306,5432,27017 -j OUTPUT_ACCEPT
    ## DNS
    iptables -A OUTPUT -p udp --dport 53 -j OUTPUT_ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j OUTPUT_ACCEPT
    ## LDAP / Kerberos
    #iptables -A OUTPUT -p tcp -m multiport --dports 53,88,135,139,389,445,464,3268,3269 -d <dc> -j OUTPUT_ACCEPT
    #iptables -A OUTPUT -p udp -m multiport --dports 53,135,138,445,464 -d <dc> -j OUTPUT_ACCEPT
    iptables -A OUTPUT -j OUTPUT_DROP

    # Forward
    iptables -I FORWARD -j fw-fwd
    ## DB
    iptables -A fw-fwd -p tcp -s "$local_subnet1,$local_subnet2" -m multiport --dport 3306,5432,27017 -j INPUT_ACCEPT
    iptables -A fw-fwd -p tcp -m multiport --dport 3306,5432,27017 -j INPUT_DROP
    iptables -A fw-fwd -j FORWARD_LOG

    # NAT
    # iptables -t nat -A PREROUTING -i <internal> -p tcp -m multiport --dports x,y,z -j REDIRECT --to-ports x
}

# Apply a firewall but allow incoming connections after a timeout to prevent lockouts.
# Parameters:
#     timeout: Seconds to wait before reverting default drop rule.
test() {
    if [ -z "$1" ]
    then
        timeout=10
        echo "fw.sh: Setting timeout to default of 10 seconds"
    else
        timeout="$1"
        echo "fw.sh: Setting timeout to $timeout seconds"
    fi

    apply "nohup sh -c 'sleep $timeout && iptables -D INPUT -j INPUT_DROP && iptables -D OUTPUT OUTPUT_DROP && iptables -D FORWARD -j fw-fwd' &"
}

usage() {
    echo 'Usage: fw.sh <command>'
    echo 'Commands available:'
    echo '    test <timeout> - Test a firewall configuration for <timeout> seconds.'
    echo '                     The timeout parameter is optional and defaults to 30 seconds.'
    echo '    apply - Apply the firewall permanently. Be careful with this option!'
    echo '            You should test the firewall with the test command first!'
    echo '    flush - Flush the applied firewall.'
    exit 1
}

if [ "test" = "$1" ]
then
    test "$2"
elif [ "apply" = "$1" ]
then
    apply
elif [ "flush" = "$1" ]
then
    flush
else
    usage
fi




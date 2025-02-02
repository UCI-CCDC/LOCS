#!/bin/bash
# Check if iptables is installed.
check() {
    if ! command -v iptables 2>&1 >/dev/null
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
    iptables-save > /root/iptables-$(date +%s).rules
    # Flush all rules and allow all connections by default
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    iptables -F INPUT
    iptables -F OUTPUT
    iptables -X
}


setup_logging() {
    iptables -N INPUT_ACCEPT
    iptables -N OUTPUT_ACCEPT

    iptables -N INPUT_DROP
    iptables -N OUTPUT_DROP

    iptables -A INPUT_ACCEPT -j LOG --log-prefix "[INPUT_ACCEPT]"
    iptables -A INPUT_ACCEPT -j ACCEPT

    iptables -A OUTPUT_ACCEPT -j LOG --log-prefix "[OUTPUT_ACCEPT]"
    iptables -A INPUT_ACCEPT -j ACCEPT

    iptables -A OUTPUT_DROP -j LOG --log-prefix "[OUTPUT_DROP]"
    iptables -A OUTPUT_DROP -j DROP

    iptables -A INPUT_DROP -j LOG --log-prefix "[INPUT_DROP]"
    iptables -A INPUT_DROP -j DROP
}

# Apply a firewall.
# Parameters:
#     command: A command to run before applying the firewall.
apply() {
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

    #setup_logging #ONLY DO THIS IF LOGGING IS NOT SETUP YET

    iptables -A INPUT -j INPUT_ACCEPT

    iptables -A OUTPUT -j OUTPUT_ACCEPT

    
    # examples:

    # Allow SSH connections
    #iptables -A INPUT -p tcp  -m multiport --dports 22,80 -j INPUT_ACCEPT

    # LDAP / Kerberos
    #iptables -A OUTPUT -p tcp -m multiport --dports 53,88,135,139,389,445,464,3268,3269 -j OUTPUT_ACCEPT
    #iptables -A OUTPUT -p udp -m multiport --dports 53,135,138,445,464 -j OUTPUT_ACCEPT
    



}

# Apply a firewall but allow incoming connections after a timeout to prevent lockouts.
# Parameters:
#     timeout: Seconds to wait before reverting default drop rule.
test() {
    if [ -z "$1" ]
    then
        timeout=180
        echo "fw.sh: Setting timeout to default of 210 seconds"
    else
        timeout="$1"
        echo "fw.sh: Setting timeout to $timeout seconds"
    fi

    apply "nohup sh -c 'sleep $timeout && iptables -P INPUT ACCEPT && iptables -P OUTPUT ACCEPT && iptables -P FORWARD ACCEPT' &"
}

usage() {
    echo 'Usage: fw.sh <command>'
    echo 'Commands available:'
    echo '    test <timeout> - Test a firewall configuration for <timeout> seconds.'
    echo '                     The timeout parameter is optional and defaults to 30 seconds.'
    echo '    apply - Apply the firewall permanently. Be careful with this option!'
    echo '            You should test the firewall with the `test` command first!'
    exit 1
}

if [ "test" == "$1" ]
then
    test "$2"
elif [ "apply" == "$1" ]
then
    apply
else
    usage
fi



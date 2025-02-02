#!/bin/bash
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

apply_basewall(){

    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT

    setup_logging

    #examples:
    #iptables -A INPUT -p tcp -m multiport -s xyz --dports xyz -j INPUT_ACCEPT
    #iptables -A INPUT -p tcp -m multiport --dports xyz -j INPUT_DROP


}

remove_basewall() {
    true;
    #examples:
    #iptables -D INPUT -p tcp -m multiport -s xyz --dports xyz -j INPUT_ACCEPT
    #iptables -D INPUT -p tcp -m multiport --dports xyz -j INPUT_DROP
}

if [ "$#" -eq 1 ] || [ -n "$AAA" ]; then
    echo 'Removing firewall'
    remove_basewall
else
    echo 'Apply firewall'
    apply_basewall
fi

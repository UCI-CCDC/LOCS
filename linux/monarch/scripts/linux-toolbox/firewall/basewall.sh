#!/bin/bash
setup_logging() {
    iptables -N FORWARD_LOG
    iptables -N INPUT_ACCEPT
    iptables -N OUTPUT_ACCEPT

    iptables -N INPUT_DROP
    iptables -N OUTPUT_DROP

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

apply_basewall(){

    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT

    setup_logging

    iptables -A INPUT -j INPUT_ACCEPT
    iptables -A OUTPUT -j OUTPUT_ACCEPT
    iptables -I FORWARD 1 -j FORWARD_LOG

    #examples:
    #iptables -A INPUT -p tcp -m multiport -s xyz --dports xyz -j INPUT_ACCEPT
    #iptables -A INPUT -p tcp -m multiport --dports xyz -j INPUT_DROP


}

remove_basewall() {
    #examples:
    #iptables -D INPUT -p tcp -m multiport -s xyz --dports xyz -j INPUT_ACCEPT
    #iptables -D INPUT -p tcp -m multiport --dports xyz -j INPUT_DROP

    iptables -D INPUT -j INPUT_ACCEPT
    iptables -D OUTPUT -j OUTPUT_ACCEPT
    iptables -D FORWARD -j FORWARD_LOG

}

if [ "$#" -eq 1 ]; then
    echo 'Removing firewall'
    remove_basewall
else
    echo 'Apply firewall'
    apply_basewall
fi

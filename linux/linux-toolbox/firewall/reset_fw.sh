# Check if iptables is installed.
check() {
    if ! command -v iptables 2>&1 >/dev/null
    then
        echo 'fw.sh: iptables is not installed! Exiting.'
        exit 1
    fi
}

check

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -F INPUT 
iptables -F OUTPUT

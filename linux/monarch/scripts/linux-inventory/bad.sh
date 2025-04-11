#!/usr/bin/env bash

HOSTNAME=$(hostname || cat /etc/hostname)
echo -e "HOST: $HOSTNAME"
echo "------------------"

sep () {
    echo "======================================================================================================="
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}

empty_line () {
    echo ""
}


SUIDS=$(find /bin /sbin /usr -perm -u=g+s -type f -exec ls -la {} \; | grep -E '(s7z|aa-exec|ab|agetty|alpine|ansible-playbook|ansible-test|aoss|apt|apt-get|ar|aria2c|arj|arp|as|ascii85|ascii-xfr|ash|aspell|at|atobm|awk|aws|base32|base58|base64|basenc|basez|bash|batcat|bc|bconsole|bpftrace|bridge|bundle|bundler|busctl|busybox|byebug|bzip2|c89|c99|cabal|cancel|capsh|cat|cdist|certbot|check_by_ssh|check_cups|check_log|check_memory|check_raid|check_ssl_cert|check_statusfile|chmod|choom|chown|chroot|clamscan|cmp|cobc|column|comm|composer|cowsay|cowthink|cp|cpan|cpio|cpulimit|crash|crontab|csh|csplit|csvtool|cupsfilter|curl|cut|dash|date|dd|debugfs|dialog|diff|dig|distcc|dmesg|dmidecode|dmsetup|dnf|docker|dos2unix|dosbox|dotnet|dpkg|dstat|dvips|easy_install|eb|ed|efax|elvish|emacs|enscript|env|eqn|espeak|ex|exiftool|expand|expect|facter|file|find|finger|fish|flock|fmt|fold|fping|ftp|gawk|gcc|gcloud|gcore|gdb|gem|genie|genisoimage|ghc|ghci|gimp|ginsh|git|grc|grep|gtester|gzip|hd|head|hexdump|highlight|hping3|iconv|iftop|install|ionice|ip|irb|ispell|jjs|joe|join|journalctl|jq|jrunscript|jtag|julia|knife|ksh|ksshell|ksu|kubectl|latex|latexmk|ldconfig|ld.so|less|lftp|ln|loginctl|logsave|look|lp|ltrace|lua|lualatex|luatex|lwp-download|lwp-request|mail|make|man|mawk|minicom|more|mosquitto|msfconsole|msgattrib|msgcat|msgconv|msgfilter|msgmerge|msguniq|mtr|multitime|mv|mysql|nano|nasm|nawk|nc|ncftp|neofetch|nft|nice|nl|nm|nmap|node|nohup|npm|nroff|nsenter|octave|od|openssl|openvpn|openvt|opkg|pandoc|paste|pax|pdb|pdflatex|pdftex|perf|perl|perlbug|pexec|pg|php|pic|pico|pidstat|pip|pkexec|pkg|posh|pr|pry|psftp|psql|ptx|puppet|pwsh|python|rake|rc|readelf|red|redcarpet|redis|restic|rev|rlogin|rlwrap|rpm|rpmdb|rpmquery|rpmverify|rsync|rtorrent|ruby|run-mailcap|run-parts|runscript|rview|rvim|sash|scanmem|scp|screen|script|scrot|sed|service|setarch|setfacl|setlock|sftp|sg|shuf|slsh|smbclient|snap|socat|socket|soelim|softlimit|sort|split|sqlite3|sqlmap|ss|ssh|ssh-agent|ssh-keygen|ssh-keyscan|sshpass|start-stop-daemon|stdbuf|strace|strings|sysctl|systemctl|systemd-resolve|tac|tail|tar|task|taskset|tasksh|tbl|tclsh|tcpdump|tdbtool|tee|telnet|terraform|tex|tftp|tic|time|timedatectl|timeout|tmate|tmux|top|torify|torsocks|troff|tshark|ul|unexpand|uniq|unshare|unsquashfs|unzip|update-alternatives|uudecode|uuencode|vagrant|valgrind|vi|view|vigr|vim|vimdiff|vipw|virsh|volatility|w3m|wall|watch|wc|wget|whiptail|whois|wireshark|wish|xargs|xdg-user-dir|xdotool|xelatex|xetex|xmodmap|xmore|xpad|xxd|xz|yarn|yash|yelp|yum|zathura|zip|zsh|zsoelim|zypper)$')


sep 
echo "SUID Binaries"
dash_sep
echo "$SUIDS"
sep
empty_line

CAPABILIITES=$(getcap -r / 2>/dev/null)
sep
echo "Binary Capabilities"
dash_sep
echo "$CAPABILIITES"
sep

WORLDWRITEABLES=$( find /etc /usr /bin/ /sbin /var/www /lib -perm -o=w -type f -exec ls {} -la \; )
sep
echo "World Writable Files"
dash_sep
echo "$WORLDWRITEABLES"
sep
empty_line


if [ -f "/etc/sudoers" ]; then
    sep
    echo "/etc/sudoers"
    dash_sep
    cat /etc/sudoers
    sep
    empty_line
fi

if [ -f "/etc/sudoers.d" ]; then
    sep
    echo "/etc/sudoers.d"
    dash_sep
    cat /etc/sudoers.d/*
    sep
    empty_line
fi

grep NOPASSWD /etc/sudoers /etc/sudoers.d/*
grep "\!authenticate" /etc/sudoers /etc/sudoers.d/*

# check if sudo is vulnerable (based on searchsploit)
sep 
echo "Sudo Version Check"
dash_sep
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
sep
empty_line


sep
echo "Looking for LD preload directives in /etc/ld.so.preload"
dash_sep
if [ -f /etc/ld.so.preload ]; then
    if [ -s /etc/ld.so.preload ]; then
        echo "/etc/ld.so.preload exists and is not empty! It contains: $(cat /etc/ld.so.preload)"
    else
        echo "/etc/ld.so.preload exists, but appears to be empty"
    fi
else
    echo "/etc/ld.so.preload does not exist!"
fi

if env | grep -q "LD_PRELOAD"; then
    warn "LD_PRELOAD env variable exists! (LD_PRELOAD=$LD_PRELOAD)"
fi

dash_sep
echo "check for any unauthorized library configuration in /etc/ld.so.conf.d, note down possibly malicious changes"
cat "/etc/ld.so.conf.d"

dash_sep
echo "check for any possibly malicious configuration in the /etc/ld.so.conf file"
cat "/etc/ld.so.conf"
sep
empty_line



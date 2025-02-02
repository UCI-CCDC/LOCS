#!/usr/bin/env bash

if [ "$#" -lt 1 ]; then
    if [ -n "$AAA" ]; then
        IP="$AAA"
    else
        echo "Usage: $0 <GRAYLOG_IP>"
        echo "Alternatively, set environment variable AAA."
        exit 1
    fi
else
    IP="$1"
fi

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

echo "Installing essential packages:"
if command_exists apt-get; then
    apt update -y
    apt-get install -y auditd rsyslog
fi

if command_exists yum; then
    yum check-update -y
    yum install -y audit rsyslog
fi

if command_exists pacman; then
    pacman -Syu --noconfirm
    pacman -S --noconfirm audit rsyslog
fi

if command_exists apk; then
    apk update --no-confirm
    apk add coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

PAM_PERMIT_PATH=$(find /lib/ -name "pam_permit.so" 2>/dev/null)
PAM_DENY_PATH=$(find /lib/ -name "pam_deny.so" 2>/dev/null)

cat << EOF >> /etc/audit/rules.d/audit.rules
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -k cron

-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

-w /root/.ssh -p wa -k rootkey

-w /usr/bin/whoami -p x -k recon
-w /etc/hostname -p r -k recon
-w /root/.bashrc -p wa -k shrc_mod
-w /root/.vimrc -p wa -k shrc_mod
-w /etc/pam.d/ -p wa -k pam


-w $PAM_PERMIT_PATH -p wa -k pam_so
-w $PAM_DENY_PATH -p wa -k pam_so

-w /usr/sbin/iptables -p x -k iptables
-w /usr/sbin/xtables-multi -p x -k iptables
-w /sbin/insmod -p x -k module_insertion

#LD preload
-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/ld.so.conf.d -p wa -k ld_preload
-w /etc/ld.so.conf -p wa -k ld_preload

-w /etc/update-motd.d/ -p wa -k motd
-w /etc/network/ -p wa -k network

-w /var/www -p wa -k webroot
EOF

cat << EOF >> /etc/audit/rules.d/audit.rules
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -k cron

-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd

-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

-w /root/.ssh -p wa -k rootkey

-w /usr/bin/whoami -p x -k recon
-w /etc/hostname -p r -k recon

-w /root/.bashrc -p wa -k shrc_mod
-w /root/.vimrc -p wa -k shrc_mod


-w /etc/pam.d/ -p wa -k pam
-w $PAM_PERMIT_PATH -p wa -k pam_so
-w $PAM_DENY_PATH -p wa -k pam_so

-w /usr/sbin/iptables -p x -k iptables
-w /usr/sbin/xtables-multi -p x -k iptables

-w /sbin/insmod -p x -k module_insertion

-w /etc/ld.so.preload -p wa -k ld_preload
-w /etc/ld.so.conf.d -p wa -k ld_preload
-w /etc/ld.so.conf -p wa -k ld_preload

#MOTD
-w /etc/update-motd.d/ -p wa -k motd

#NETWORK
-w /etc/network/ -p wa -k network

#check webroot for modification
-w /var/www -p wa -k webroot
EOF
#GIT
find / -name .git -exec dirname {} \; | while IFS= read -r file; do
    echo "-w $file -p wa -k git" >> "/etc/audit/rules.d/audit.rules"
done

cat << EOF > /etc/rsyslog.d/69-remote.conf
\$InputFileName /var/log/audit/audit.log
\$InputFileStateFile auth_log
\$InputFileTag auth_log
\$InputFileSeverity info
\$InputFileFacility local1
\$InputRunFileMonitor
*.* @@$IP:514 
EOF

echo 'module(load="imtcp")' >> /etc/rsyslog.conf

if command_exists systemctl; then
    systemctl restart rsyslog
    systemctl restart auditd
    systemctl restart rsyslogd
    systemctl restart audit
fi
if command_exists service; then
    service rsyslog restart
    systemctl auditd restart 
    systemctl rsyslogd restart
    systemctl audit restart
fi
#!/bin/sh

chattr +i /etc/passwd
chattr +i /etc/shadow
chattr -R +i /etc/pam.d
chattr -R +i $(find /lib/ -name "pam_deny.so" -exec dirname {} \;)
chattr +i /etc/ssh/sshd_config
chattr +i /etc/profile

if command -v pkexec; then
  chmod 0444 $(command -v pkexec)
fi

# thanks ucf :D
killall cron
killall crond
killall atd
killall anacron

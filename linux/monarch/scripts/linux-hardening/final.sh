#!/bin/sh

nexec() {
  if command -v "$1"; then
    chmod 0400 $(command -v "$1")
  fi
}

chattr +i /etc/passwd
chattr +i /etc/shadow
chattr -R +i /etc/pam.d
find /lib /usr/lib /usr/lib64 -name "pam_*.so" -exec chattr +i {} \;
chattr +i /etc/ssh/sshd_config
chattr +i /etc/profile
chattr +i /etc/sudoers
chattr -R +i /etc/sudoers.d
chattr +i /etc/doas.conf

nexec pkexec
nexec sudoedit
nexec visudo

# thanks ucf :D
killall cron
killall crond
killall atd
killall anacron

#!/bin/sh
# cron
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/cron.allow &
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/cron.deny &

inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/cron.d -r &
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/cron.daily -r &
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/cron.hourly -r &

inotifywait -m -e modify /etc/crontab &

inotifywait -m -e open /var/spool/cron -r &

# userspace
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/group &
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/passwd &
inotifywait -m -e open /etc/gshadow &
inotifywait -m -e open /etc/shadow &
inotifywait -m -e open /etc/security/opasswd &
# sudo
inotifywait -m -e open "$(which sudo)" &
inotifywait -m -e open /etc/sudoers &


inotifywait -m -e open /etc/sudoers.d -r &

# root ssh key
inotifywait -m -e open /root/.ssh --exclude authorized_keys -r &

for file in $(find /home -name .ssh  2>/dev/null); do
    	inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self "$file" -r &
done;
# recon ttp
inotifywait -m -e open "$(which whoami)" &
inotifywait -m -e open "$(which hostnamectl)" &
inotifywait -m -e open /etc/hostname &
# rc modification
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /root/.bashrc &
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /root/.vimrc &


#pam modification
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/pam.d -r &

# run: find /lib/ -name "pam_permit.so" to find where .so files are
# deb default: /lib/x86_64-linux-gnu/security/
PAM_PERMIT_PATH=$(find /lib/ -name "pam_permit.so" )
PAM_DIR=$(dirname "$PAM_PERMIT_PATH")
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self "$PAM_DIR" -r &

#iptables modification
inotifywait -m -e open "$(which iptables)" &
inotifywait -m -e open "$(which xtables-multi)" &

# Module insertion
inotifywait -m -e open "$(which insmod)" &


#LD_preload
inotifywait -m -e open /etc/ld.so.preload -r &
inotifywait -m -e open /etc/ld.so.conf.d -r &
inotifywait -m -e open /etc/ld.so.conf &

#MOTD
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self /etc/update-motd.d/ -r &

#GIT
# find / -name .git
for file in $(find / -name .git  2>/dev/null); do
    	GIT_DIR=$(dirname "$file")
    	inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self "$GIT_DIR" -r &
done;


#NETWORK
inotifywait -m -e open /etc/network -r &

#check webroot for modification
inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self  /var/www -r &

inotifywait -m -e open "$(which chpasswd)" &

inotifywait -m -e open "$(which chmod)" &
inotifywait -m -e open "$(which mysql)" &
inotifywait -m -e open "$(which psql)" &
inotifywait -m -e open "$(which mongosh)" &

#check ftproot for modification
#inotifywait -m -e modify,create,delete,attrib,moved_to,moved_from,move_self,delete_self  FTPROOT -r &


# wait for all scripts to exit (should never exit)
wait

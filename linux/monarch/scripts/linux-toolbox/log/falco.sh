#!/bin/sh

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

tar -xvf falco.tar.gz
cp -r falco-0.40.0-x86_64/* /

mkdir -p /etc/falco/rules.d
cat <<EOF > /etc/falco/rules.d/rules.yaml
- rule: Monitor Cron Configuration Changes
  desc: Detects modifications to cron-related files.
  condition: >
    open_read and
    (fd.name in (/etc/cron.allow, /etc/cron.deny, /etc/crontab) or fd.name startswith /etc/cron.d or fd.name startswith /etc/cron.daily or fd.name startswith /etc/cron.hourly)
  output: "Modification detected in cron configuration: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [cron, configuration]

- rule: Monitor Cat passwd
  desc: Detects if passwd is read with cat.
  condition: >
    open_read and
    (proc.name = cat) and
    (fd.name = /etc/passwd)
  output: "Cat passwd detected (Command: %proc.cmdline) by user: %user.name"
  priority: ALERT
  tags: [security]

- rule: Monitor Sudo Access
  desc: Detects sudo access and sudoers file modifications.
  condition: >
    open_read and
    (proc.name = sudo or fd.name startswith /etc/sudoers)
  output: "Sudo access or modification detected: %proc.name %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [privilege_escalation, security]

- rule: Monitor SSH Key Access
  desc: Detects access to SSH key directories.
  condition: >
    open_read and
    (fd.name startswith /root/.ssh or fd.name endswith /.ssh)
  output: "SSH key access detected: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [ssh, security]

- rule: Monitor Reconnaissance Commands
  desc: Detects execution of reconnaissance commands.
  condition: >
    proc.name in (whoami, hostnamectl) or fd.name = /etc/hostname
  output: "Recon command executed: %proc.name (Command: %proc.cmdline) by user: %user.name"
  priority: INFO
  tags: [reconnaissance, security]

- rule: Monitor PAM Modifications
  desc: Detects changes to PAM configuration files.
  condition: >
    open_write and
    fd.name startswith /etc/pam.d
  output: "PAM modification detected: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [pam, security]

- rule: Monitor Firewall Configuration Access
  desc: Detects access to iptables and firewall-related tools.
  condition: >
    open_read and
    proc.name in (iptables, xtables-multi)
  output: "Firewall tool accessed: %proc.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [network, firewall]

- rule: Monitor Module Insertions
  desc: Detects use of insmod for loading kernel modules.
  condition: >
    open_read and
    proc.name = insmod
  output: "Kernel module insertion detected: %proc.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [kernel, security]

- rule: Monitor LD Preload Modifications
  desc: Detects access to LD preload-related files.
  condition: >
    open_read and
    fd.name in (/etc/ld.so.preload, /etc/ld.so.conf, /etc/ld.so.conf.d)
  output: "LD_PRELOAD modification detected: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [ld_preload, security]

- rule: Monitor Webroot Modifications
  desc: Detects changes to the webroot directory.
  condition: >
    open_write and
    fd.name startswith /var/www
  output: "Webroot modification detected: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [web, security]

- rule: Monitor Database Access
  desc: Detects access to database clients.
  condition: >
    open_read and
    proc.name in (mysql, psql, mongosh)
  output: "Database access detected: %proc.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [database, security]

- rule: Monitor Network Configuration Access
  desc: Detects access to network configuration files.
  condition: >
    open_read and
    fd.name startswith /etc/network
  output: "Network configuration access detected: %fd.name (Command: %proc.cmdline) by user: %user.name"
  priority: WARNING
  tags: [network, security]
- rule: Load BPF Program
  desc: Detect attempts to load a BPF program into the kernel
  condition: evt.type=bpf and evt.dir=< and not proc.name in (ld.so, systemd, containerd)
  output: "BPF program loaded (user=%user.name command=%proc.cmdline pid=%proc.pid)"
  priority: WARNING
EOF

if command_exists systemctl; then
  echo "Installing for systemd"
  mkdir -p /etc/systemd/system
  cat <<EOF > /etc/systemd/system/falco.service
[Unit]
Description=Falco
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/falco
StandardOutput=journal
StandardError=journal
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now falco
elif command_exists rc-status; then
  echo "Installing for OpenRC"
  mkdir -p /etc/init.d
  cat <<EOF > /etc/init.d/falco
#!/sbin/openrc-run

description="Falco"
command="/usr/bin/falco"
command_background="yes"
pidfile="/run/falco.pid"
name="falco"

depend() {
    need net
}

start_pre() {
    checkpath --directory --mode 0755 /run
}
EOF

  chmod +x /etc/init.d/falco
  rc-update add falco
  rc-service falco start
else
  echo "Warning: No supported init system found; not installing"
fi

#!/bin/bash

if ! command -v curl; then
    echo "curl isn't installed, please install it first!"
    exit 1
fi

curl -L -o falco.tar.gz https://download.falco.org/packages/bin/x86_64/falco-0.40.0-static-x86_64.tar.gz
tar -xvf falco.tar.gz
cp -r falco-0.40.0-x86_64/* /
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

mkdir -p /etc/falco/rules.d
curl -L -o /etc/falco/rules.d/rules.yaml https://raw.githubusercontent.com/UCI-CCDC/LOCS/refs/heads/main/linux/linux-toolbox/log/rules.yaml

systemctl daemon-reload
systemctl enable --now falco

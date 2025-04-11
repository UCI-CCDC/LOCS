#!/usr/bin/env bash
HOSTNAME=$(hostname || cat /etc/hostname)
OS=$( (hostnamectl | grep "Operating System" | cut -d: -f2) || (cat /etc/*-release  | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//' | sed 's/"//g') )
echo -e "$HOSTNAME | $OS"
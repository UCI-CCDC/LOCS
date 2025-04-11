#!/bin/sh

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

if [ -f /etc/hostname ]; then
    cat /etc/hostname
elif command_exists 'hostname'; then
    hostname
elif command_exists 'hostnamectl'; then
    hostnamectl hostname
fi

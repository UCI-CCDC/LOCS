#!/usr/bin/env bash
command_exists() {
  command -v "$1" > /dev/null 2>&1
}

echo "Installing essential packages:"
if command_exists apt-get; then
    apt update -y
    apt-get install -y coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists yum; then
    yum check-update -y
    yum install -y bash coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists pacman; then
    pacman -Syu --noconfirm
    pacman -S --noconfirm coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi

if command_exists apk; then
    apk update --no-confirm
    apk add coreutils net-tools iproute2 iptables bash curl git net-tools vim wget grep tar jq gpg nano
fi
echo "Essential packages stage done."

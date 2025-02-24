#!/bin/sh

USER="$1"
PASS="$2"

if [ -z "$USER" ] || [ -z "$PASS" ]; then
    echo 'username and/or password not provided, failing'
    exit 1
fi

if command -v chpasswd >/dev/null 2>&1; then
    echo "$USER:$PASS" | chpasswd
elif command -v passwd >/dev/null 2>&1; then
    printf '%s\n%s\n' "$PASS" "$PASS" | passwd "$USER"
else
    echo 'chpasswd and passwd both not found, failing'
    exit 1
fi

echo "$PASS"
exit 0

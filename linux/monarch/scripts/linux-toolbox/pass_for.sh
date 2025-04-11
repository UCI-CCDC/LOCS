#!/usr/bin/env sh

username="$1"
password="$2"

if [ -n "$username" ] && [ -n "$password" ]; then
  echo "USERNAME AND PASSWORD PROVIDED"
elif [ -n "$AAA" ] && [ -n "$BBB" ]; then
  echo "USING ENVIRONMENT VARIABLES (EXPECTED WITH COORDINATE)"
  username="$AAA"
  password="$BBB"
else
  echo "USERNAME AND/OR PASSWORD NOT PROVIDED, FAILING"
  exit 1
fi

if command -v chpasswd >/dev/null 2>&1; then
  echo "$username:$password" | chpasswd
else
  printf "%s\n%s\n" "$password" "$password" | passwd "$username"
fi
echo "COMPLETED"

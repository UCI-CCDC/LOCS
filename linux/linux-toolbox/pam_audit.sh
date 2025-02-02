#!/usr/bin/env bash

echo "EXEC"
echo "======="
grep -r "pam_exec.so" /etc/pam.d/
echo ""
echo "======="

echo "NULLOK"
echo "======="
grep -r "nullok" /etc/pam.d/
echo ""
echo "======="

echo "DENY VERIFY"
echo "======="
MOD=$(find /lib/ -name "pam_deny.so")
if $(grep -r "pam_deny.so" $MOD); then 
    echo "pam_deny.so has NOT been tampered with"
else
    echo "pam_deny.so has been tampered with"
fi
echo ""
echo "======="

echo "PERMIT VERIFY"
echo "======="
MOD=$(find /lib/ -name "pam_permit.so")
if $(grep -r "pam_permit.so" $MOD); then 
    echo "pam_permit.so has NOT been tampered with"
else
    echo "pam_permit.so has been tampered with"
fi
echo ""
echo "======="

echo "PAM STACK VERIFY"
echo "======="
files=$(find /etc/pam.d/ -name "*-auth")

for file in $files; do
    if [ ! -f "$file" ]; then
        echo "File not found: $file"
        continue
    fi

    deny_line=$(grep -n 'pam_deny.so' "$file" | cut -d: -f1 | head -n 1)
    permit_line=$(grep -n 'pam_permit.so' "$file" | cut -d: -f1 | head -n 1)

    if [ -z $permit_line ]; then
        echo "pam_permit.so not found in $file. [INVESTIGATE!]"
        continue
    fi


    if [ -z $deny_line ]; then
        echo "pam_deny.so not found in $file. [INVESTIGATE!]"
        continue
    fi

    if ! [ $deny_line -lt $permit_line ]; then
        echo "pam_permit.so comes before pam_deny.so in $file | [INVESTIGATE!]"
    fi
done
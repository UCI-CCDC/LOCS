#!/usr/bin/env bash

command_exists() {
  command -v "$1" > /dev/null 2>&1
}

dash_sep () {
    echo "-------------------------------------------------------------------------------------------------------"
}
sep () {
    echo "======================================================================================================="
}

print_password_rule() {
    if [ -n "$2" ]; then
        if [ "$2" -ne 0 ]; then
            echo -e "[*] Password $1: $2"
        fi
    else
        echo -e "[*] Password $1: None"
    fi
}

if command_exists "apt-get"; then
    os="debian-based"
elif command_exists "yum"; then
    os="rhel-based"
elif command_exists "pacman"; then
    os="arch-based"
else
    os="unknown"
fi

HOSTNAME=$(hostname || cat /etc/hostname)
dash_sep
sep
echo -e "PASSWORD POLICY CHECKS FOR $HOSTNAME"
sep

get_password_policy() {
    if [ -n "$dictionary_checks" ]; then
        echo -e "[*] Passwords cannot be dictionary words: True"
        echo -e "[*] Passwords cannot be palindromes: True"
        echo -e "[*] Passwords cannot be the old password with case change only: True"
    else
        echo -e "[*] Passwords cannot be dictionary words: False"
        echo -e "[*] Passwords cannot be palindromes: False"
        echo -e "[*] Passwords cannot be the old password with case change only: False"
    fi

    if [ -n "$dictionary_checks" ]; then
        minlen=$(get_numeric_password_config "minlen" "")
        dcredit=$(get_numeric_password_config "dcredit" "-")
        ucredit=$(get_numeric_password_config "ucredit" "-")
        lcredit=$(get_numeric_password_config "lcredit" "-")
        ocredit=$(get_numeric_password_config "ocredit" "-")
        maxrepeat=$(get_numeric_password_config "maxrepeat" "")
        maxclassrepeat=$(get_numeric_password_config "maxclassrepeat" "")
        minclass=$(get_numeric_password_config "minclass" "")
        difok=$(get_numeric_password_config "difok" "")    
    fi

    # password expiry
    maxdays=$(grep -Eo '^PASS_MAX_DAYS\s*[0-9]+' /etc/login.defs | grep -Eo '[0-9]+')
    mindays=$(grep -Eo '^PASS_MIN_DAYS\s*[0-9]+' /etc/login.defs | grep -Eo '[0-9]+')
    warndays=$(grep -Eo '^PASS_WARN_AGE\s*[0-9]+' /etc/login.defs | grep -Eo '[0-9]+')

}

get_numeric_password_config() {
    local directive=$1
    local polarity=$2
    local config_file="/etc/pam.d/common-password"

    if [ "$os" == "debian-based" ]; then
        config_file="/etc/pam.d/common-password"
    elif [ "$os" == "rhel-based" ]; then
        config_file="/etc/pam.d/system-auth"
    elif [ "$os" == "arch-based" ]; then
        config_file="/etc/pam.d/system-auth"
    fi

    if [ -n "$dictionary_checks" ]; then
        grep_pattern="${directive}\s*=\s*${polarity}[0-9]+"
        value=$(grep -Eo "$grep_pattern" "$config_file" | grep -Eo '[0-9]+')

        if [ -z "$value" ]; then
            config_file="/etc/security/pwquality.conf"
            grep_pattern="^${directive}\s*=\s*${polarity}[0-9]+"
            value=$(grep -Eo "$grep_pattern" "$config_file" | grep -Eo '[0-9]+')
        fi

        echo "$value"
    fi
}

if command_exists "apt-get"; then
    dictionary_checks=$(grep "pam_pwquality.so" /etc/pam.d/common-password || grep "pam_cracklib.so" /etc/pam.d/common-password)
    get_password_policy

fi

if command_exists "yum"; then
    dictionary_checks=$(grep "pam_pwquality.so" /etc/pam.d/system-auth || grep "pam_cracklib.so" /etc/pam.d/system-auth)
    get_password_policy
fi

if command_exists "pacman"; then
    dictionary_checks=$(grep "pam_pwquality.so" /etc/pam.d/system-auth || grep "pam_cracklib.so" /etc/pam.d/system-auth)
    get_password_policy
fi

print_password_rule "minimum length" "$minlen"
print_password_rule "minimum digit characters" "$dcredit"
print_password_rule "minimum uppercase characters" "$ucredit"
print_password_rule "minimum lowercase characters" "$lcredit"
print_password_rule "minimum special characters" "$ocredit"
print_password_rule "maximum same consecutive characters" "$maxrepeat"
print_password_rule "maximum same consecutive characters in the same class" "$maxclassrepeat"
print_password_rule "minimum character classes" "$minclass"
print_password_rule "minimum characters not in old password" "$difok"

if [ -n "$maxdays" ]; then
    if [ "$maxdays" -le 365 ]; then
        echo -e "[*] Expiration date of 365 or fewer: True (current value is $maxdays)"
    else
        echo -e "[*] Expiration date of 365 or fewer: False (current value is $maxdays)"
    fi
else
    echo -e "[*] Expiration date of 365 or fewer: False (current value: None)"
fi

if [ -n "$mindays" ]; then
    if [ "$mindays" -ge 7 ]; then
        echo -e "[*] Minimum days between password changes set to 7 or more: True (current value is $mindays)"
    else
        echo -e "[*] Minimum days between password changes set to 7 or more: False (current value is $mindays)"
    fi
else
    echo -e "[*] Minimum days between password changes set to 7 or more: False (current value is None)"
fi

dash_sep
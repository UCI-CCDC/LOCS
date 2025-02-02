#!/bin/bash

clean_users_file() {
    if [ -f authorized_users.txt ]; then
        # Remove duplicate entries and blank lines from users.txt
        awk '!seen[$0]++' authorized_users.txt > temp_users.txt
        mv temp_users.txt authorized_users.txt
    sed -i '/^$/d' authorized_users.txt
    else
        echo "Error: authorized_users.txt not found."
        exit 1
    fi
}

# Function to remove users not present in users.txt
remove_users() {
    while IFS= read -r username; do
        # Check if the user exists and has UID >= 1000
        if id "$username" &>/dev/null && [ "$(id -u "$username")" -ge 1000 ]; then
            # Check if the user is in authorized_users.txt
            if ! grep -Fxq "$username" authorized_users.txt; then
                echo "Removing user: $username"
                userdel "$username"
            fi
        fi
    done < <(awk -F: '$3 >= 1000 {print $1}' /etc/passwd)
}

# Function to add users present in authorized_users.txt but not in /etc/passwd
add_users() {
    while IFS= read -r username; do
        # Check if the user already exists
        if ! id "$username" &>/dev/null; then
            echo "Adding user: $username"
            useradd -m "$username"
        fi
    done < authorized_users.txt
}

# Main script
if [ ! -f authorized_users.txt ]; then
    echo "Error: authorized_users.txt not found."
    exit 1
fi

#echo "Cleaning user file..."
clean_users_file

#echo "Removing users not in authorized_users.txt..."
remove_users

#echo "Adding users from authorized_users.txt..."
add_users

echo "Authorized users configured."

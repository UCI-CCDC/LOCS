#!/usr/bin/env bash

if [ "$#" -ne 3 ]; then
    if [ -n "$AAA" ] && [ -n "$BBB" ] && [ -n "$CCC" ]; then
        source_path="$AAA"
        destination_path="$BBB"
        password="$CCC"
    else
        echo "Usage: $0 <source_path> <destination_path> <password>"
        echo "Alternatively, set environment variables AAA, BBB, and CCC."
        exit 1
    fi
else
    source_path="$1"
    destination_path="$2"
    password="$3"
fi

if [ ! -d "$source_path" ]; then
    echo "Error: Source path '$source_path' does not exist or is not a directory."
    exit 1
fi

if [ ! -d "$destination_path" ]; then
    echo "Destination path '$destination_path' does not exist, creating it."
    mkdir -p "$destination_path"
fi

temp_archive="/tmp/backup_$(date +%Y%m%d%H%M%S).tar"
tar -cf "$temp_archive" -C "$source_path" .

if [ $? -ne 0 ]; then
    echo "Error: Failed to create the tar archive."
    exit 1
fi

gpg --batch --yes --passphrase "$password" -c "$temp_archive"

if [ $? -ne 0 ]; then
    echo "Error: Failed to encrypt the tar archive with GPG."
    exit 1
fi

mv "${temp_archive}.gpg" "$destination_path"

if [ $? -ne 0 ]; then
    echo "Error: Failed to move the encrypted file to the destination path."
    exit 1
fi

rm "$temp_archive"

echo "Locking down permissions of the created backup at $destination_path"
chmod 600 $destination_path

echo "Backup completed successfully and saved to $destination_path"
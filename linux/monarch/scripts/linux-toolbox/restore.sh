#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
    if [ -n "$AAA" ] && [ -n "$BBB" ]; then
        encrypted_archive="$AAA"
        destination_path="$BBB"
    else
        echo "Usage: $0 <encrypted_archive.gpg> <destination_path>"
        echo "Alternatively, set environment variables AAA and BBB."
        exit 1
    fi
else
    encrypted_archive="$1"
    destination_path="$2"
fi

if [ ! -f "$encrypted_archive" ]; then
    echo "Error: Encrypted archive '$encrypted_archive' not found."
    exit 1
fi

if [ ! -d "$destination_path" ]; then
    echo "Error: Destination path '$destination_path' does not exist or is not a directory."
    exit 1
fi

decrypted_archive="/tmp/restored_$(date +%Y%m%d%H%M%S).tar"
gpg --batch --yes --decrypt --output "$decrypted_archive" "$encrypted_archive"

if [ $? -ne 0 ]; then
    echo "Error: Failed to decrypt the GPG-encrypted archive."
    exit 1
fi

tar -xf "$decrypted_archive" -C "$destination_path"

if [ $? -ne 0 ]; then
    echo "Error: Failed to extract the contents from the decrypted archive."
    exit 1
fi

rm "$decrypted_archive"

echo "Restoration completed successfully to $destination_path"


#!/usr/bin/env bash

keywords="deployments statefulsets services ingress pv pvc secrets"

for type in $keywords; do
    output=$(kubectl get $type --all-namespaces | awk 'NR>1 {print $1, $2}')
    if [ "$output" = "" ]; then
        echo "No $type"
        continue
    else
        while IFS= read -r line; do
            if [ "$type" = "pv" ]; then
                mkdir -p $1$type
                name=$(echo "$line" | awk '{print $1}')
                echo "Processing $type $name"
                kubectl get $type $name -o yaml > "$backup_path$type/$name.yaml"
            else
                namespace=$(echo "$line" | awk '{print $1}')
                name=$(echo "$line" | awk '{print $2}')
                echo "Processing $type $name in namespace $namespace"
                mkdir -p "$1$namespace/$type"
                kubectl -n $namespace get $type $name -o yaml > "$1$namespace/$type/$name.yaml"
            fi
        done <<< "$output"
    fi
done

chmod 600 -R $1

echo "Backups made in $1"


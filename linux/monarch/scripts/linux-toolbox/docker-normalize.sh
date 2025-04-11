#!/bin/bash

if ! [ -f normalize.sh ]; then
    echo "Must keep normalize.sh in the same directory as $0"
    exit 1
fi

containers=$(sudo docker ps | awk '{if(NR>1) print $NF}')

for container in $containers
do
    docker cp normalize.sh $container:/root/
    output=$(docker exec -it $container sh /root/normalize.sh 2>&1 >/dev/null)

    # Check if the command was successful
    if [ $? -ne 0 ]; then
        # There was an error, handle it here
        echo "Error: $output"
    else
        # The command was successful, continue with your script
        echo "normalized container: $container"
    fi
done
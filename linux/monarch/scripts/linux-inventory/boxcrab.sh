#!/bin/bash
client() {
    server_addr="$1"

    if [ -z "$server_addr" ]
    then
        echo "Please specify a server for the client to call back to!"
        exit 1
    fi

    ./boxcrab-client-linux-x64 --server-address=http://"$server_addr" --enable-all-crabs true
}

server() {
    port="$1"

    if [ -z "$port" ]
    then
        echo "Please specify a port for the server to listen on!"
        exit 1
    fi

    echo "Listening on port 0.0.0.0:$port"
    echo "Visit website at http://localhost:$port/topology to see client data."
    ./boxcrab-server-linux-x64 --server-listen-address=0.0.0.0:"$port" --client-binaries-path=. --sqlite-database-path=database.db
}

usage() {
    echo 'Usage: boxcrab.sh <command>'
    echo 'Commands available:'
    echo '    client <server_addr> - Run the boxcrab client. Server address is in the form <ip>:<port>, ex: 127.0.0.1:8080'
    echo '    server <port> -      Run the boxcrab server. Port is a TCP port.'
    exit 1
}

if [ ! -f ./boxcrab-server-linux-x64 ] || [ ! -f ./boxcrab-client-linux-x64 ]
then
    echo "No boxcrab server or client binary detected!"
    echo "Please run this in the directory where you've downloaded boxcrab."
    exit 1
fi

if [ "client" == "$1" ]
then
    client "$2"
elif [ "server" == "$1" ]
then
    server "$2"
else
    usage
fi


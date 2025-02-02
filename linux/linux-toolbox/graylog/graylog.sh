#!/bin/bash
install_docker() {
    if command -v docker && command -v docker-compose; then
        return
    else
        # Install docker
        curl https://get.docker.com | sh
        # Install docker-compose
        # Note: this assumes /usr/bin is in path
        curl -SL https://github.com/docker/compose/releases/download/v2.32.0/docker-compose-linux-x86_64 -o /usr/bin/docker-compose
        chmod +x /usr/bin/docker-compose
    fi
}

download_zip() {
    curl -LO https://github.com/UCI-CCDC/CCDC/raw/refs/heads/master/linux-dev/linux-toolbox/graylog/graylog.zip
    unzip graylog.zip
    chown -R 1100:1100 .
}

if [ "$#" -ne 3 ]; then
    if [ -n "$AAA" ] && [ -n "$BBB" ] && [ -n "$CCC" ]; then
        root_pass="$AAA"
        external_ip="$BBB"
        elasticsearch_ip="$CCC"
    else
        echo "Usage: $0 <root_pass> <external_ip> <elasticsearch_ip>"
        echo "Alternatively, set environment variables AAA, BBB, and CCC."
        exit 1
    fi
else
    root_pass="$1"
    external_ip="$2"
    elasticsearch_ip="$3"
fi

if ! command -v curl || ! command -v unzip; then
    echo "curl and / or unzip isn't installed, please install it first!"
    exit 1
fi

install_docker
pushd $(pwd)
mkdir graylog
cd graylog
download_zip
GRAYLOG_PASSWORD_SECRET=$(< /dev/urandom tr -dc A-Z-a-z-0-9 | head -c96; echo)
GRAYLOG_ROOT_PASSWORD_SHA2=$(echo -n "$root_pass" | sha256sum | awk '{print $1}')
GRAYLOG_HTTP_EXTERNAL_URI="http://$external_ip:9090/"
GRAYLOG_ELASTICSEARCH_HOSTS="http://$elasticsearch_ip:9200/"
printf 'password secret:      %s\n' "$GRAYLOG_PASSWORD_SECRET"
printf 'root password sha:    %s\n' "$GRAYLOG_ROOT_PASSWORD_SHA2"
printf 'elasticsearch hosts:  %s\n' "$GRAYLOG_ELASTICSEARCH_HOSTS"
printf 'graylog external uri: %s\n' "$GRAYLOG_HTTP_EXTERNAL_URI"
cat <<EOF > docker-compose-graylog.yml
version: '3'
services:
  # MongoDB: https://hub.docker.com/_/mongo/
  mongo:
    image: mongo:3
    networks:
      - graylog
    volumes:
      - ./graylog_mongo_data/_data:/data/db
  # Graylog: https://hub.docker.com/r/graylog/graylog/
  graylog:
    image: graylog/graylog:3.2
    environment:
      - GRAYLOG_PASSWORD_SECRET=$GRAYLOG_PASSWORD_SECRET
      - GRAYLOG_ROOT_PASSWORD_SHA2=$GRAYLOG_ROOT_PASSWORD_SHA2
      - GRAYLOG_HTTP_EXTERNAL_URI=$GRAYLOG_HTTP_EXTERNAL_URI
      - GRAYLOG_ELASTICSEARCH_HOSTS=$GRAYLOG_ELASTICSEARCH_HOSTS
      - "GRAYLOG_SERVER_JAVA_OPTS=-Xms4096m -Xmx4096m"
    networks:
      - graylog
    depends_on:
      - mongo
    ports:
      # Graylog web interface and REST API
      - 9090:9000
      # Syslog TCP
      - 1514:1514
      # Syslog UDP
      - 1514:1514/udp
      # GELF TCP
      - 12201:12201
      # GELF UDP
      - 12201:12201/udp
      - 5144:5144
      - 5044:5044
      - 514:514
    volumes:
      - ./graylog_graylog_data/_data:/usr/share/graylog/data
networks:
  graylog:
    driver: bridge
EOF
docker-compose -f docker-compose-graylog.yml up -d
popd

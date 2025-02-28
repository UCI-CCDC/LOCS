#!/bin/bash

install_docker() {
    if ! command -v docker; then
        # Install docker
        curl https://get.docker.com | sh
    fi

    # Install docker-compose
    if ! command -v docker-compose; then
        # Note: this assumes /usr/bin is in path
        curl -SL https://github.com/docker/compose/releases/download/v2.32.0/docker-compose-linux-x86_64 -o /usr/bin/docker-compose
        chmod +x /usr/bin/docker-compose
    fi
}
download_zip() {
    curl -LO https://github.com/UCI-CCDC/LOCS/raw/refs/heads/main/linux/linux-toolbox/graylog/elasticsearch.zip
    unzip elasticsearch.zip
    chown -R 1000:1000 .
}

if ! command -v curl || ! command -v unzip; then
    echo "curl and / or unzip isn't installed, please install it first!"
    exit 1
fi

install_docker
pushd $(pwd)
mkdir elastic
cd elastic
download_zip
cat <<EOF > docker-compose-elastic.yml
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch-oss:6.8.5
    environment:
      - http.host=0.0.0.0
      - network.host=0.0.0.0
      - transport.host=localhost
      - "ES_JAVA_OPTS=-Xms2048m -Xmx2048m"
    ulimits:
      memlock:
        soft: -1
        hard: -1
    ports:
      - 9200:9200
      - 9300:9300
    volumes:
      - ./graylog_elasticsearch_data/_data:/usr/share/elasticsearch/data
EOF

docker-compose -f docker-compose-elastic.yml up -d
popd

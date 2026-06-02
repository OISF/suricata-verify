FROM ubuntu:24.04
RUN apt-get -y update && \
    apt-get -y install caddy tshark
COPY /server.sh /server.sh
COPY /index.html /srv/www/index.html
FROM ubuntu:24.04
RUN apt update && apt install -y caddy
COPY Caddyfile /etc/caddy/Caddyfile
COPY index.txt /srv/index.txt
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
FROM python:3.12-slim

# Install rclone
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip && \
    curl -O https://downloads.rclone.org/current/rclone-current-linux-amd64.zip && \
    unzip rclone-current-linux-amd64.zip && \
    cp rclone-*-linux-amd64/rclone /usr/local/bin/ && \
    rm -rf rclone-* && \
    apt-get purge -y curl unzip && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install cloudhop
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -e .

# Config volume (user mounts their rclone.conf here)
VOLUME ["/root/.config/rclone", "/root/.cloudhop"]

# Expose web UI port
EXPOSE 8787

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

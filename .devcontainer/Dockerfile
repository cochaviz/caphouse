FROM mcr.microsoft.com/devcontainers/go

# Install libpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    # clear apt cache
    && rm -rf /var/lib/apt/lists/*

# Install ClickHouse repository
RUN sudo apt-get install -y apt-transport-https ca-certificates curl gnupg \
    # Download the ClickHouse GPG key and store it in the keyring
    && curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg \
    # Get the system architecture
    && ARCH=$(dpkg --print-architecture) \
    # Add the ClickHouse repository to apt sources
    && echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list \
    # Update apt package lists
    && sudo apt-get update \
    # Install ClickHouse server and client
    && sudo apt-get install -y clickhouse-client \
    # clear apt cache
    && rm -rf /var/lib/apt/lists/*

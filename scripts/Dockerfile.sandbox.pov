FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    build-essential \
    python3 \
    python3-pip \
    vim \
    nano \
    file \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 and Claude Code CLI
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code

# Install Joern
ENV JOERN_VERSION=4.0.322
RUN wget -q "https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-install.sh" \
    && chmod +x joern-install.sh \
    && ./joern-install.sh --version=${JOERN_VERSION} --install-dir=/opt/joern \
    && rm joern-install.sh
ENV PATH="/opt/joern/joern-cli:${PATH}"

# Claude Code refuses --dangerously-skip-permissions when running as root
RUN useradd -m -s /bin/bash sandbox \
    && mkdir -p /workspace \
    && chown sandbox:sandbox /workspace

USER sandbox
WORKDIR /workspace

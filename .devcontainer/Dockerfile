FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install additional OS packages
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    git-lfs \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

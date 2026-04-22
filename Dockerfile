# Update Dockerfile for xssmap container

# Build arguments for the XSSMap repository and commit SHA
ARG XSSMAP_REPO=https://github.com/darksilenxe/XSSMap.git
ARG XSSMAP_SHA=<commit-sha>

# Install dependencies

# Use a non-interactive method to clone the XSSMap repository
RUN git init xssmap \
    && cd xssmap \
    && git remote add origin ${XSSMAP_REPO} \
    && git fetch --depth=1 origin ${XSSMAP_SHA} \
    && git checkout ${XSSMAP_SHA} \
    && cd .. \
    && rm -rf xssmap/.git \
    || { echo 'Failed to fetch XSSMap repository. Please check the repository URL or commit SHA.'; exit 1; }
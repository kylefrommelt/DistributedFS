# Multi-stage Dockerfile for DistributedFS
FROM ubuntu:22.04 AS base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libboost-all-dev \
    libssl-dev \
    python3 \
    python3-pip \
    python3-dev \
    sqlite3 \
    libsqlite3-dev \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build C++ components
FROM base AS cpp-builder
RUN mkdir -p build && cd build && cmake .. && make -j$(nproc)

# Setup Python environment
FROM base AS python-builder
COPY src/python/requirements.txt /app/src/python/
RUN cd src/python && pip3 install --no-cache-dir -r requirements.txt

# Production image
FROM ubuntu:22.04 AS production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libboost-system1.74.0 \
    libboost-filesystem1.74.0 \
    libboost-thread1.74.0 \
    libssl3 \
    python3 \
    python3-pip \
    sqlite3 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -s /bin/bash distributedfs

# Set working directory
WORKDIR /app

# Copy built artifacts from builders
COPY --from=cpp-builder /app/build/distributedfs /app/bin/
COPY --from=cpp-builder /app/build/libdistributedfs_lib.a /app/lib/
COPY --from=python-builder /usr/local/lib/python3.10/dist-packages /usr/local/lib/python3.10/dist-packages/

# Copy application code
COPY src/ /app/src/
COPY config/ /app/config/
COPY README.md /app/

# Create necessary directories
RUN mkdir -p /app/storage /app/logs /app/temp && \
    chown -R distributedfs:distributedfs /app

# Switch to app user
USER distributedfs

# Set environment variables
ENV PYTHONPATH=/app/src/python
ENV PATH="/app/bin:${PATH}"

# Expose ports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3 -c "import requests; requests.get('http://localhost:5000/api/health')" || exit 1

# Default command
CMD ["python3", "/app/src/python/app.py"]

# Development image
FROM base AS development

# Install development dependencies
RUN apt-get update && apt-get install -y \
    gdb \
    valgrind \
    cppcheck \
    clang-format \
    doxygen \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Install Python development dependencies
COPY src/python/requirements.txt /app/src/python/
RUN cd src/python && pip3 install -r requirements.txt

# Set up development environment
ENV PYTHONPATH=/app/src/python
ENV PATH="/app/build:${PATH}"

# Default command for development
CMD ["/bin/bash"] 
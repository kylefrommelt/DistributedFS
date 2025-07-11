#!/bin/bash
# DistributedFS Quick Setup Script
# For Ubuntu/Debian systems

set -e

echo "🚀 Setting up DistributedFS Development Environment"
echo "=================================================="

# Check if running on supported system
if ! command -v apt-get &> /dev/null; then
    echo "❌ This script is designed for Ubuntu/Debian systems"
    echo "Please install dependencies manually for your system"
    exit 1
fi

# Install system dependencies
echo "📦 Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
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
    git

# Build C++ components
echo "🔨 Building C++ components..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)
cd ..

# Setup Python environment
echo "🐍 Setting up Python environment..."
cd src/python
python3 -m pip install --user -r requirements.txt
cd ../..

# Run tests
echo "🧪 Running tests..."
echo "C++ Tests:"
cd build && ctest --verbose
cd ..

echo "Python Tests:"
cd tests/python && python3 -m pytest test_api.py -v
cd ../..

# Create storage directories
echo "📁 Creating storage directories..."
mkdir -p storage logs temp

echo ""
echo "✅ Setup complete! DistributedFS is ready to use."
echo ""
echo "Quick Start:"
echo "  C++ Engine:    ./build/distributedfs"
echo "  Python API:    cd src/python && python3 app.py"
echo "  Docker:        make docker-build && make docker-run"
echo "  Help:          make help"
echo ""
echo "🎯 Perfect for your NetApp Software Engineer application!"
echo "📚 See README.md for detailed documentation" 
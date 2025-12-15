#!/usr/bin/env bash

set -euo pipefail

echo "🧹 Cleaning old platform files..."
rm -f platform/linux-x64.a platform/linux-x64.rh platform/metadata_linux-x64.rm

echo "🚀 Running jump-start..."
./jump-start.sh

echo "🔨 Building platform..."
roc run --linker=legacy build.roc

echo "📦 Creating bundle..."
roc build --bundle .tar.br platform/main.roc

echo "✅ Bundle creation complete!"

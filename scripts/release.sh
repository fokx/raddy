#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Raddy Workspace Release Helper
#
# Usage:
#   ./scripts/release.sh patch       # 0.6.0 -> 0.6.1
#   ./scripts/release.sh minor       # 0.6.0 -> 0.7.0
#   ./scripts/release.sh major       # 0.6.0 -> 1.0.0
#   ./scripts/release.sh 0.7.0       # Set explicit version
# ==============================================================================

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <patch|minor|major|VERSION>"
    echo "Example: $0 patch"
    echo "Example: $0 0.7.0"
    exit 1
fi

TARGET="$1"

# Check if git working directory is clean
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: Git working tree is dirty. Please commit or stash changes first."
    exit 1
fi

echo "==> Bumping workspace versions..."
if [[ "$TARGET" =~ ^(patch|minor|major)$ ]]; then
    cargo set-version --bump "$TARGET" --workspace
else
    cargo set-version "$TARGET" --workspace
fi

# Update Cargo.lock
echo "==> Updating Cargo.lock..."
cargo check --quiet

# Extract new version
NEW_VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4)
TAG="v${NEW_VERSION}"

echo "==> New version: ${NEW_VERSION} (${TAG})"

# Commit and tag
git add Cargo.toml Cargo.lock crates/*/Cargo.toml
git commit -m "chore(release): bump version to ${TAG}"
git tag -a "${TAG}" -m "Release ${TAG}"

echo ""
echo "🎉 Version bumped and tagged successfully!"
echo "To publish and trigger automatic GHCR Docker build, run:"
echo "    git push origin main --tags"

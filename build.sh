#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="jasonbaker/sandbox"
TAG="${1:-latest}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

echo "🐳 Building ${IMAGE_NAME}:${TAG} for ${PLATFORMS}..."

# Create a builder if one doesn't already exist
if ! docker buildx inspect sandbox-builder &>/dev/null; then
  echo "🔧 Creating buildx builder 'sandbox-builder'..."
  docker buildx create --name sandbox-builder --use --driver docker-container
  docker buildx inspect --bootstrap
else
  docker buildx use sandbox-builder
fi

# Publish OCI layers with maximum Zstd compression, including inherited layers.
docker buildx build \
  --builder sandbox-builder \
  --platform "${PLATFORMS}" \
  -f Dockerfile \
  -t "${IMAGE_NAME}:${TAG}" \
  --output "type=registry,compression=zstd,compression-level=22,force-compression=true,oci-mediatypes=true" \
  --push \
  .

echo "✅ Built and pushed ${IMAGE_NAME}:${TAG} for ${PLATFORMS}"
echo ""
echo "Run the sandbox: ./sandbox.sh"

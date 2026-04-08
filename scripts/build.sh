#!/bin/bash

set -e

# Get version from VERSION file or git tag
tool_name="advanced-sftp-exporter"
if [ -f VERSION ]; then
  VERSION=$(cat VERSION)
else
  VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
fi

# Get build information
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_HASH=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GO_VERSION=$(go version | awk '{print $3}')

echo "Building $tool_name version $VERSION"
echo "  Build Date: $BUILD_DATE"
echo "  Build Hash: $BUILD_HASH"
echo "  Go Version: $GO_VERSION"

# Output directory
OUTDIR=bin
mkdir -p "$OUTDIR"

# Supported platforms
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/386"
  "linux/arm"
  "linux/ppc64le"
  "linux/s390x"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
  "windows/386"
  "freebsd/amd64"
  "freebsd/arm64"
)

# Build ldflags
LDFLAGS="-X 'main.Version=$VERSION' -X 'main.BuildDate=$BUILD_DATE' -X 'main.BuildHash=$BUILD_HASH' -X 'main.GoVersion=$GO_VERSION'"

for PLATFORM in "${PLATFORMS[@]}"; do
  IFS="/" read -r GOOS GOARCH <<< "$PLATFORM"
  EXT=""
  if [ "$GOOS" = "windows" ]; then
    EXT=".exe"
  fi
  OUTPUT_NAME="$OUTDIR/${tool_name}-${VERSION}.${GOOS}-${GOARCH}${EXT}"
  echo "Building for $GOOS/$GOARCH -> $OUTPUT_NAME"
  env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "$LDFLAGS" -o "$OUTPUT_NAME" *.go
done

echo "All binaries built in $OUTDIR/"
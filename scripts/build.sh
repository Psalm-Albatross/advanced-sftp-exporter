#!/bin/bash

set -e

# Get version from VERSION file or git tag
tool_name="advanced-sftp-exporter"
if [ -f VERSION ]; then
  VERSION=$(cat VERSION)
else
  VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")
fi

echo "Building $tool_name version $VERSION"

# Output directory
OUTDIR=bin
mkdir -p "$OUTDIR"

# Supported platforms
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

for PLATFORM in "${PLATFORMS[@]}"; do
  IFS="/" read -r GOOS GOARCH <<< "$PLATFORM"
  OUTPUT_NAME="$OUTDIR/${tool_name}-${VERSION}.${GOOS}-${GOARCH}"
  echo "Building for $GOOS/$GOARCH -> $OUTPUT_NAME"
  env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-X 'main.Version=$VERSION'" -o "$OUTPUT_NAME" main.go
done

echo "All binaries built in $OUTDIR/"
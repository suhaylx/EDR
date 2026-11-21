#!/bin/sh
set -eu
# Deliberately do not vendor third-party GPL source into the TuranSec repository.
# Use on a development machine with outbound GitHub access.
repo='https://github.com/Cisco-Talos/clamav.git'
target="${1:-vendor-src/clamav}"
if [ -e "$target" ]; then
    printf 'Refusing to overwrite existing path: %s\n' "$target" >&2
    exit 1
fi
mkdir -p "$(dirname "$target")"
git clone --depth 1 --branch clamav-1.5.5 --single-branch --filter=blob:none "$repo" "$target"
printf 'Upstream URL: %s\nPinned tag: clamav-1.5.5\n' "$repo"
printf 'Upstream commit: '
git -C "$target" rev-parse HEAD
printf 'Review README.md, COPYING.txt and third-party notices before redistribution.\n'

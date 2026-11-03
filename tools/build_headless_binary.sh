#!/usr/bin/env bash
# Builds the headless agentgateway binary for amd64 or arm64 from the locked dependency
# set, natively or as a cross-compile, and checks that the requested version metadata
# made it into the result. Used by Dockerfile.headless and usable in any Rust 1.99
# Debian trixie environment that has the matching cross compiler.
#
# Usage: VERSION=<version> GIT_REVISION=<sha> [PROFILE=quick-release] \
#          tools/build_headless_binary.sh <amd64|arm64> <output-path>
set -euo pipefail

arch="${1:?target architecture is required}"
output="${2:?output path is required}"
profile="${PROFILE:-quick-release}"

: "${VERSION:?VERSION is required}"
: "${GIT_REVISION:?GIT_REVISION is required}"
if [[ "$VERSION" == unknown || "$GIT_REVISION" == unknown ]]; then
  echo "VERSION and GIT_REVISION must not be 'unknown'" >&2
  exit 1
fi

case "$arch" in
  amd64)
    target=x86_64-unknown-linux-gnu
    cross_prefix=x86_64-linux-gnu
    # jemalloc needs the page size up front when it cannot probe the target.
    export JEMALLOC_SYS_WITH_LG_PAGE=12
    ;;
  arm64)
    target=aarch64-unknown-linux-gnu
    cross_prefix=aarch64-linux-gnu
    # Runs on hosts with any page size up to 64KB (4KB/16KB/64KB).
    export JEMALLOC_SYS_WITH_LG_PAGE=16
    ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "$host" != "$target" ]]; then
  env_target="${target//-/_}"
  export "CC_${env_target}=${cross_prefix}-gcc"
  export "CXX_${env_target}=${cross_prefix}-g++"
  export "AR_${env_target}=${cross_prefix}-ar"
  export "CARGO_TARGET_${env_target^^}_LINKER=${cross_prefix}-gcc"
fi

rustup target add "$target"
export VERSION GIT_REVISION
cargo build --locked -p agentgateway-app --bin agentgateway \
  --no-default-features --features crypto-aws-lc,jemalloc,mimalloc \
  --target "$target" --profile "$profile"

mkdir -p "$(dirname "$output")"
cp "${CARGO_TARGET_DIR:-target}/$target/$profile/agentgateway" "$output"

# Run the metadata check only where the binary can execute. A cross-compiled binary is
# still searched for the revision, which embeds it as a plain string.
if [[ "$host" == "$target" ]]; then
  build_info="$("$output" --version)"
  grep -qF "\"version\": \"$VERSION\"" <<<"$build_info"
  grep -qF "\"git_revision\": \"$GIT_REVISION\"" <<<"$build_info"
else
  grep -qaF "$GIT_REVISION" "$output"
  grep -qaF "$VERSION" "$output"
fi

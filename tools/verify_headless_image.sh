#!/usr/bin/env bash
# Verifies a headless image against the deployed gateway configuration before publication.
# Uses a disposable CA created here; no credentials are needed or read.
#
# Usage: tools/verify_headless_image.sh <image> <version> <git-revision> <harness-checkout>
set -euo pipefail

image="${1:?image is required}"
version="${2:?version is required}"
revision="${3:?git revision is required}"
resources="${4:?harness checkout is required}/infrastructure/central-egress"

work="$(mktemp -d)"
container=""
cleanup() {
  if [[ -n "$container" ]]; then
    docker rm -f "$container" >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "::error::$*" >&2
  exit 1
}

expect_equal() {
  [[ "$2" == "$3" ]] || fail "$1: expected '$3', got '$2'"
}

inspect() {
  docker image inspect --format "$1" "$image"
}

# Copies a literal block out of a Kubernetes manifest, so the check uses the real files.
extract_block() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys

source, key, destination = sys.argv[1:]
lines = open(source, encoding="utf-8").read().splitlines()
header = f"  {key}: |"
if lines.count(header) != 1:
    raise SystemExit(f"expected one {key} block in {source}")
block = []
for line in lines[lines.index(header) + 1:]:
    if line and not line.startswith("    "):
        break
    block.append(line[4:])
open(destination, "w", encoding="utf-8").write("\n".join(block).rstrip("\n") + "\n")
PY
}

echo "Checking image metadata"
expect_equal "user" "$(inspect '{{.Config.User}}')" "65532:65532"
expect_equal "entrypoint" "$(inspect '{{json .Config.Entrypoint}}')" '["/app/agentgateway"]'
expect_equal "command" "$(inspect '{{json .Config.Cmd}}')" '["-f","/etc/agentgateway/config.yaml"]'
expect_equal "revision label" "$(inspect '{{index .Config.Labels "org.opencontainers.image.revision"}}')" "$revision"
expect_equal "version label" "$(inspect '{{index .Config.Labels "org.opencontainers.image.version"}}')" "$version"

build_info="$(docker run --rm "$image" --version)"
grep -qF "\"version\": \"$version\"" <<<"$build_info" || fail "binary version is not $version"
grep -qF "\"git_revision\": \"$revision\"" <<<"$build_info" || fail "binary revision is not $revision"

echo "Checking that the image has no CA trust store"
created="$(docker create "$image")"
docker export "$created" | tar -tf - >"$work/rootfs.txt"
docker rm "$created" >/dev/null
if grep -E '^(etc/ssl|etc/pki)(/|$)|\.(crt|pem)$' "$work/rootfs.txt"; then
  fail "the image contains certificate files"
fi

echo "Preparing the deployed configuration with a disposable CA"
mkdir -p "$work/config" "$work/dynamic-ca" "$work/upstream-ca"
extract_block "$resources/configmap.yaml" config.yaml "$work/config/config.yaml"
extract_block "$resources/upstream-ca-bundle.yaml" ca-bundle.pem "$work/upstream-ca/ca-bundle.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$work/root.key" 2>/dev/null
openssl req -x509 -new -key "$work/root.key" -sha384 -days 2 \
  -subj "/CN=CI Inspection Root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out "$work/root.crt"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/dynamic-ca/issuer.key" 2>/dev/null
openssl req -new -key "$work/dynamic-ca/issuer.key" -subj "/CN=CI Inspection Issuer" -out "$work/issuer.csr"
cat >"$work/issuer.ext" <<'EXT'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
EXT
openssl x509 -req -in "$work/issuer.csr" -CA "$work/root.crt" -CAkey "$work/root.key" -sha384 -days 2 \
  -extfile "$work/issuer.ext" -out "$work/dynamic-ca/issuer.crt" 2>/dev/null
chmod -R a+rX "$work/config" "$work/dynamic-ca" "$work/upstream-ca"

run_options=(
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 1g --cpus 1
  -v "$work/config:/etc/agentgateway:ro"
  -v "$work/dynamic-ca:/var/run/secrets/egress-proxy/dynamic-ca:ro"
  -v "$work/upstream-ca:/etc/egress-proxy/upstream-ca:ro"
)

echo "Validating the configuration"
docker run --rm "${run_options[@]}" "$image" --validate-only -f /etc/agentgateway/config.yaml

echo "Starting the gateway under the Deployment's restrictions"
container="$(docker run -d "${run_options[@]}" -p 127.0.0.1::3128 -p 127.0.0.1::15021 "$image")"
proxy="http://$(docker port "$container" 3128/tcp | head -n 1)"
ready="http://$(docker port "$container" 15021/tcp | head -n 1)/healthz/ready"
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 -o /dev/null "$ready"; then
    break
  fi
  sleep 1
done
curl -fsS --max-time 2 -o /dev/null "$ready" || fail "the gateway did not become ready"
process_id="$(docker inspect --format '{{.State.Pid}}' "$container")"
expect_equal "process user" "$(ps -o uid= -p "$process_id" | tr -d ' ')" "65532"

status() {
  curl -sS --proxy "$proxy" --cacert "$work/root.crt" --max-time 30 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true
}

marker="verify-query-marker-$$"
echo "Checking inspected connections, including an IP address without SNI"
for url in "https://pypi.org/simple/pip/?$marker" "https://1.1.1.1/?$marker"; do
  code="$(status "$url")"
  echo "$code ${url%%\?*}"
  [[ "$code" =~ ^[234][0-9][0-9]$ ]] || fail "$url should pass verification, got $code"
done
if ! curl -sSv --proxy "$proxy" --cacert "$work/root.crt" --max-time 30 -o /dev/null https://pypi.org/simple/pip/ 2>&1 \
  | grep -q 'issuer:.*CI Inspection Issuer'; then
  fail "the connection was not inspected by the issuer"
fi

echo "Checking that bad upstream certificates and loopback are rejected"
for url in \
  https://wrong.host.badssl.com/ \
  https://expired.badssl.com/ \
  https://untrusted-root.badssl.com/ \
  https://dv-g3b-emudhra.we-have-a-problem.com/ \
  https://dv-g3b-aaa-emudhra.we-have-a-problem.com/ \
  https://127.0.0.1/; do
  code="$(status "$url")"
  echo "$code $url"
  expect_equal "$url" "$code" "503"
done

echo "Checking the access log"
docker logs "$container" >"$work/gateway.log" 2>&1
grep -qF 'pypi.org' "$work/gateway.log" || fail "the access log recorded no requests"
if grep -qF "$marker" "$work/gateway.log"; then
  fail "the access log contains a decrypted query string"
fi
if grep -qF 'PRIVATE KEY' "$work/gateway.log"; then
  fail "the log contains private key material"
fi

echo "Image verification passed"

#!/usr/bin/env bash
set -euo pipefail

DOCKERFILE="${DOCKERFILE:-tools/kmstool/Dockerfile}"
PLATFORM="${PLATFORM:-linux/amd64}"
OUTPUT_DIR="${OUTPUT_DIR:-.tmp/kmstool-artifacts}"
INSTALL_DIR="${INSTALL_DIR:-vendor/alpine-x64}"

for variable in OUTPUT_DIR INSTALL_DIR; do
  value="${!variable}"
  case "${value}" in
    ''|'/'|'.'|'..'|/*|../*|*/../*|*/..)
      echo "ERROR: ${variable} must be a non-root relative path: ${value}" >&2
      exit 1
      ;;
  esac
done

CHECKSUMS_FILE="${INSTALL_DIR}/SHA256SUMS"
committed_sums=''
if [[ -f "${CHECKSUMS_FILE}" ]]; then
  committed_sums="$(cat "${CHECKSUMS_FILE}")"
fi

rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

DOCKER_BUILDKIT=1 docker build \
  --platform "${PLATFORM}" \
  --target kmstool-artifacts \
  --output "type=local,dest=${OUTPUT_DIR}" \
  -f "${DOCKERFILE}" \
  .

rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/lib"

cp "${OUTPUT_DIR}/bin/kmstool_enclave_cli" \
  "${INSTALL_DIR}/kmstool_enclave_cli"
cp "${OUTPUT_DIR}/lib/libnsm.so" \
  "${INSTALL_DIR}/lib/libnsm.so"
cp "${OUTPUT_DIR}/lib/libgcc_s.so.1" \
  "${INSTALL_DIR}/lib/libgcc_s.so.1"
chmod 0755 "${INSTALL_DIR}/kmstool_enclave_cli"

for required in \
  "${INSTALL_DIR}/kmstool_enclave_cli" \
  "${INSTALL_DIR}/lib/libnsm.so" \
  "${INSTALL_DIR}/lib/libgcc_s.so.1"
do
  [[ -e "${required}" ]] || {
    echo "ERROR: generated artifact is missing: ${required}" >&2
    exit 1
  }
done

[[ -x "${INSTALL_DIR}/kmstool_enclave_cli" ]] || {
  echo "ERROR: kmstool_enclave_cli is not executable" >&2
  exit 1
}

(
  cd "${INSTALL_DIR}"
  sha256sum kmstool_enclave_cli lib/libnsm.so lib/libgcc_s.so.1 > SHA256SUMS
)

if [[ -n "${committed_sums}" && "${UPDATE_VENDOR_SUMS:-0}" != '1' ]]; then
  if [[ "${committed_sums}" != "$(cat "${CHECKSUMS_FILE}")" ]]; then
    echo 'ERROR: rebuilt vendor artifacts do not match committed SHA256SUMS' >&2
    echo '       (set UPDATE_VENDOR_SUMS=1 for an intentional update)' >&2
    exit 1
  fi
fi

echo '[kmstool-vendor] installed package-owned runtime artifacts:'
printf '  %s\n' \
  "${INSTALL_DIR}/kmstool_enclave_cli" \
  "${INSTALL_DIR}/lib/libnsm.so" \
  "${INSTALL_DIR}/lib/libgcc_s.so.1"
echo "[kmstool-vendor] build evidence remains under ${OUTPUT_DIR}"

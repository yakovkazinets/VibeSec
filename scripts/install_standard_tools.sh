#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
config_path="${repo_root}/config/tools.json"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "component=standard-tool-installer result=invalid_configuration cause=unsupported-platform next=use-a-Linux-x86_64-runner docs=docs/troubleshooting.md" >&2
  exit 3
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT
staging="${temporary_directory}/staging"
mkdir -p "$staging"

for tool in cosign opengrep osv-scanner syft; do
  readarray -t metadata < <(python3 - "$config_path" "$tool" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]
print(item["url"])
print(item["archive"])
print(item["sha256"])
PY
)
  url="${metadata[0]}"
  artifact="${metadata[1]}"
  expected="${metadata[2]}"
  curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary_directory}/${artifact}" "$url"
  actual="$(sha256sum "${temporary_directory}/${artifact}" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "component=${tool} result=tool_error cause=checksum-mismatch next=stop-and-verify-the-official-release docs=docs/troubleshooting.md" >&2
    exit 2
  fi
  if [[ "$artifact" == *.tar.gz ]]; then
    python3 "${repo_root}/scripts/extract_tool_archive.py" \
      "${temporary_directory}/${artifact}" "$tool" "${staging}/${tool}"
  else
    install -m 0755 "${temporary_directory}/${artifact}" "${staging}/${tool}"
  fi
  if [[ "$tool" == "opengrep" ]]; then
    readarray -t signature_metadata < <(python3 - "$config_path" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))["opengrep"]
for key in ("signature_url", "certificate_url", "certificate_identity", "certificate_oidc_issuer"):
    print(item[key])
PY
)
    curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary_directory}/opengrep.sig" "${signature_metadata[0]}"
    curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary_directory}/opengrep.cert" "${signature_metadata[1]}"
    "${staging}/cosign" verify-blob \
      --certificate "${temporary_directory}/opengrep.cert" \
      --signature "${temporary_directory}/opengrep.sig" \
      --certificate-identity "${signature_metadata[2]}" \
      --certificate-oidc-issuer "${signature_metadata[3]}" \
      "${temporary_directory}/${artifact}"
  fi
done


# Publish only after all tools, including Opengrep's signature, validate.
mkdir -p "$destination"
for tool in cosign opengrep osv-scanner syft; do
  install -m 0755 "${staging}/${tool}" "${destination}/.${tool}.new"
  mv -f "${destination}/.${tool}.new" "${destination}/${tool}"
done

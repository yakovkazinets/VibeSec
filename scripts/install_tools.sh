#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
config_path="${repo_root}/config/tools.json"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "component=tool-installer result=invalid_configuration cause=unsupported-platform next=use-a-Linux-x86_64-runner docs=docs/troubleshooting.md" >&2
  exit 3
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT
staging="${temporary_directory}/staging"
mkdir -p "$staging"

for tool in trivy gitleaks actionlint; do
  url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["url"])' "$config_path" "$tool")"
  archive="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["archive"])' "$config_path" "$tool")"
  expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["sha256"])' "$config_path" "$tool")"
  curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary_directory}/${archive}" "$url"
  actual="$(sha256sum "${temporary_directory}/${archive}" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "component=${tool} result=tool_error cause=checksum-mismatch next=stop-and-verify-the-official-release docs=docs/troubleshooting.md" >&2
    exit 2
  fi
  python3 "${repo_root}/scripts/extract_tool_archive.py" \
    "${temporary_directory}/${archive}" "$tool" "${staging}/${tool}"
done

# Do not publish any executable until every download, checksum, and archive has
# passed validation. Each final file replacement is atomic.
mkdir -p "$destination"
for tool in trivy gitleaks actionlint; do
  install -m 0755 "${staging}/${tool}" "${destination}/.${tool}.new"
  mv -f "${destination}/.${tool}.new" "${destination}/${tool}"
done

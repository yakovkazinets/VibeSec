#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
config_path="${repo_root}/config/tools.json"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The minimal-profile installer currently supports Linux x86_64 only." >&2
  exit 3
fi

mkdir -p "$destination"
temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT

for tool in trivy gitleaks actionlint; do
  url="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["url"])' "$config_path" "$tool")"
  archive="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["archive"])' "$config_path" "$tool")"
  expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["sha256"])' "$config_path" "$tool")"
  curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary_directory}/${archive}" "$url"
  actual="$(sha256sum "${temporary_directory}/${archive}" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "Checksum verification failed for ${tool}." >&2
    exit 2
  fi
  tar -xzf "${temporary_directory}/${archive}" -C "$temporary_directory"
  install -m 0755 "${temporary_directory}/${tool}" "${destination}/${tool}"
done

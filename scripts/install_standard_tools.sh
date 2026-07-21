#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
config_path="${repo_root}/config/tools.json"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The Standard-profile installer supports Linux x86_64 only." >&2
  exit 3
fi

mkdir -p "$destination"
temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT

for tool in opengrep osv-scanner syft; do
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
    echo "Checksum verification failed for ${tool}." >&2
    exit 2
  fi
  if [[ "$artifact" == *.tar.gz ]]; then
    tar -xzf "${temporary_directory}/${artifact}" -C "$temporary_directory"
    install -m 0755 "${temporary_directory}/${tool}" "${destination}/${tool}"
  else
    install -m 0755 "${temporary_directory}/${artifact}" "${destination}/${tool}"
  fi
done

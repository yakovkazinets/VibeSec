#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
temporary_directory="$(mktemp -d)"
trap 'rm -rf -- "$temporary_directory"' EXIT
mkdir -p "$destination"

for tool in cosign syft; do
  readarray -t metadata < <(python3 - "$repo_root/config/tools.json" "$tool" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]
print(item["url"])
print(item["archive"])
print(item["sha256"])
PY
)
  curl --fail --location --proto '=https' --tlsv1.2 --output "$temporary_directory/${metadata[1]}" "${metadata[0]}"
  printf '%s  %s\n' "${metadata[2]}" "$temporary_directory/${metadata[1]}" | sha256sum --check --status
  if [[ "${metadata[1]}" == *.tar.gz ]]; then
    python3 "$repo_root/scripts/extract_tool_archive.py" "$temporary_directory/${metadata[1]}" "$tool" "$temporary_directory/$tool"
  else
    install -m 0755 "$temporary_directory/${metadata[1]}" "$temporary_directory/$tool"
  fi
done

for tool in cosign syft; do
  install -m 0755 "$temporary_directory/$tool" "$destination/.$tool.new"
  mv -f "$destination/.$tool.new" "$destination/$tool"
done

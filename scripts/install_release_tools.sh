#!/usr/bin/env bash
set -euo pipefail

repo_root="${1:-.}"
destination="${2:-${repo_root}/.tools/bin}"
exec python3 "$repo_root/scripts/install_profile_tools.py" \
  --profile standard \
  --vibesec-root "$repo_root" \
  --destination "$destination"

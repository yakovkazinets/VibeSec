#!/usr/bin/env bash
set -uo pipefail

repo_root="${1:-.}"
results_dir="${2:-${repo_root}/results}"
vibesec_root="${3:-${repo_root}}"
tool_dir="${VIBESEC_TOOL_DIR:-${vibesec_root}/.tools/bin}"
minimum_severity="${VIBESEC_MIN_SEVERITY:-high}"
enforcement="${VIBESEC_ENFORCEMENT:-observe}"
mkdir -p "$results_dir"
chmod 700 "$results_dir"
rm -f -- \
  "${results_dir}/normalized.json" "${results_dir}/report.md" \
  "${results_dir}/coverage.json" "${results_dir}/policy-result.json" \
  "${results_dir}/inventory.json" "${results_dir}/finding-groups.json" \
  "${results_dir}/prioritized-findings.json" \
  "${results_dir}/sbom.cyclonedx.json" "${results_dir}/sbom.spdx.json" \
  "${results_dir}/trivy.json" "${results_dir}/gitleaks.json" \
  "${results_dir}/actionlint.txt"
legacy_raw="${results_dir}/raw"
if [[ -L "$legacy_raw" || -f "$legacy_raw" ]]; then
  rm -f -- "$legacy_raw"
elif [[ -d "$legacy_raw" ]]; then
  rm -rf -- "$legacy_raw"
fi

raw_dir="$(mktemp -d "${TMPDIR:-/tmp}/vibesec-minimal-raw.XXXXXX")"
chmod 700 "$raw_dir"
trap 'rm -rf -- "$raw_dir"' EXIT
trivy_raw="${raw_dir}/trivy.json"
gitleaks_raw="${raw_dir}/gitleaks.json"
actionlint_raw="${raw_dir}/actionlint.txt"
network_mode="${VIBESEC_NETWORK_MODE:-online}"

tool_error_args=()
tool_error_count=0
record_tool_error() {
  local tool="$1"
  local message="$2"
  tool_error_args+=(--tool-error "$tool" "$message")
  tool_error_count=$((tool_error_count + 1))
}

if [[ "$network_mode" == offline ]]; then
  "${tool_dir}/trivy" --config "${vibesec_root}/config/trivy-standard.yaml" filesystem --scanners vuln,misconfig,secret --format json --output "$trivy_raw" --exit-code 0 --no-progress --skip-db-update --offline-scan "$repo_root"
else
  "${tool_dir}/trivy" --config "${vibesec_root}/config/trivy-standard.yaml" filesystem --scanners vuln,misconfig,secret --format json --output "$trivy_raw" --exit-code 0 --no-progress "$repo_root"
fi
trivy_status=$?
if [[ $trivy_status -ne 0 ]]; then record_tool_error trivy "Trivy exited with status ${trivy_status}"; echo '{"Results":[]}' > "$trivy_raw"; fi
trivy_state=ran
if [[ $trivy_status -ne 0 ]]; then trivy_state=tool_error; fi

"${tool_dir}/gitleaks" git --no-banner --redact \
  --config "${vibesec_root}/config/gitleaks-standard.toml" \
  --gitleaks-ignore-path "${vibesec_root}/config/gitleaks-standard-ignore.txt" \
  --report-format json --report-path "$gitleaks_raw" "$repo_root"
gitleaks_status=$?
if [[ $gitleaks_status -gt 1 ]]; then record_tool_error gitleaks "Gitleaks exited with status ${gitleaks_status}"; fi
[[ -f "$gitleaks_raw" ]] || echo '[]' > "$gitleaks_raw"
gitleaks_state=ran
if [[ $gitleaks_status -gt 1 ]]; then gitleaks_state=tool_error; fi

actionlint_state=not_applicable
actionlint_status=0
workflow_files=()
if [[ -d "${repo_root}/.github/workflows" ]]; then
  while IFS= read -r -d '' workflow; do
    workflow_files+=("$workflow")
  done < <(find "${repo_root}/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0)
fi
if [[ ${#workflow_files[@]} -gt 0 ]]; then
  "${tool_dir}/actionlint" -no-color \
    -config-file "${vibesec_root}/config/actionlint-standard.yaml" \
    -shellcheck "" -pyflakes "" "${workflow_files[@]}" > "$actionlint_raw" 2>&1
  actionlint_status=$?
  if [[ $actionlint_status -gt 1 ]]; then record_tool_error actionlint "actionlint exited with status ${actionlint_status}"; echo -n > "$actionlint_raw"; fi
  actionlint_state=ran
  if [[ $actionlint_status -gt 1 ]]; then actionlint_state=tool_error; fi
else
  echo -n > "$actionlint_raw"
fi

write_coverage() {
  local normalization_failed="${1:-no}"
  local command=(
    python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" coverage
    --vibesec-root "$vibesec_root" --output "${results_dir}/coverage.json"
    --trivy-state "$trivy_state" --gitleaks-state "$gitleaks_state" --actionlint-state "$actionlint_state"
    --network-mode "$network_mode"
  )
  if [[ "$normalization_failed" == yes ]]; then command+=(--normalization-failed); fi
  "${command[@]}"
}

python3 "${vibesec_root}/scripts/normalize_results.py" \
  --input trivy "$trivy_raw" \
  --input gitleaks "$gitleaks_raw" \
  --input actionlint "$actionlint_raw" \
  --output "${results_dir}/normalized.json"
normalize_status=$?
if [[ $normalize_status -ne 0 ]]; then
  write_coverage yes || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" normalized --profile minimal --exit-code 3 --output "${results_dir}/normalized.json" || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" policy --profile minimal --exit-code 3 --output "${results_dir}/policy-result.json" || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" report --profile minimal --exit-code 3 --output "${results_dir}/report.md" || true
  exit 3
fi

if [[ $tool_error_count -eq 0 ]]; then
  python3 "${vibesec_root}/scripts/append_tool_errors.py" --results "${results_dir}/normalized.json"
else
  python3 "${vibesec_root}/scripts/append_tool_errors.py" \
    --results "${results_dir}/normalized.json" \
    "${tool_error_args[@]}"
fi
append_status=$?
if [[ $append_status -ne 0 ]]; then
  write_coverage yes || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" normalized --profile minimal --exit-code 3 --output "${results_dir}/normalized.json" || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" policy --profile minimal --exit-code 3 --output "${results_dir}/policy-result.json" || true
  python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" report --profile minimal --exit-code 3 --output "${results_dir}/report.md" || true
  exit 3
fi

write_coverage || exit 3

python3 "${vibesec_root}/scripts/policy_gate.py" \
  --results "${results_dir}/normalized.json" \
  --policy "${vibesec_root}/policy/severity-thresholds.yml" \
  --baseline "${vibesec_root}/policy/baseline.json" \
  --suppressions "${vibesec_root}/policy/suppressions.yml" \
  --minimum-severity "$minimum_severity" --enforcement "$enforcement" \
  --report "${results_dir}/report.md"
policy_status=$?
python3 "${vibesec_root}/scripts/write_minimal_artifacts.py" policy \
  --profile minimal --exit-code "$policy_status" --output "${results_dir}/policy-result.json" || exit 3
exit "$policy_status"

#!/usr/bin/env bash
set -uo pipefail

repo_root="${1:-.}"
results_dir="${2:-${repo_root}/results}"
tool_dir="${VIBESEC_TOOL_DIR:-${repo_root}/.tools/bin}"
minimum_severity="${VIBESEC_MIN_SEVERITY:-high}"
enforcement="${VIBESEC_ENFORCEMENT:-observe}"
mkdir -p "$results_dir"
rm -f -- \
  "${results_dir}/normalized.json" "${results_dir}/report.md" \
  "${results_dir}/coverage.json" "${results_dir}/policy-result.json" \
  "${results_dir}/trivy.json" "${results_dir}/gitleaks.json" "${results_dir}/actionlint.txt"

tool_error_args=()
tool_error_count=0
record_tool_error() {
  local tool="$1"
  local message="$2"
  tool_error_args+=(--tool-error "$tool" "$message")
  tool_error_count=$((tool_error_count + 1))
}

"${tool_dir}/trivy" filesystem --scanners vuln,misconfig,secret --format json --output "${results_dir}/trivy.json" --exit-code 0 --no-progress "$repo_root"
trivy_status=$?
if [[ $trivy_status -ne 0 ]]; then record_tool_error trivy "Trivy exited with status ${trivy_status}"; echo '{"Results":[]}' > "${results_dir}/trivy.json"; fi
trivy_state=ran
if [[ $trivy_status -ne 0 ]]; then trivy_state=tool_error; fi

"${tool_dir}/gitleaks" git --no-banner --redact --report-format json --report-path "${results_dir}/gitleaks.json" "$repo_root"
gitleaks_status=$?
if [[ $gitleaks_status -gt 1 ]]; then record_tool_error gitleaks "Gitleaks exited with status ${gitleaks_status}"; fi
[[ -f "${results_dir}/gitleaks.json" ]] || echo '[]' > "${results_dir}/gitleaks.json"
gitleaks_state=ran
if [[ $gitleaks_status -gt 1 ]]; then gitleaks_state=tool_error; fi

"${tool_dir}/actionlint" -no-color > "${results_dir}/actionlint.txt" 2>&1
actionlint_status=$?
if [[ $actionlint_status -gt 1 ]]; then record_tool_error actionlint "actionlint exited with status ${actionlint_status}"; echo -n > "${results_dir}/actionlint.txt"; fi
actionlint_state=ran
if [[ $actionlint_status -gt 1 ]]; then actionlint_state=tool_error; fi

write_coverage() {
  local normalization_failed="${1:-no}"
  local command=(
    python3 "${repo_root}/scripts/write_minimal_artifacts.py" coverage
    --vibesec-root "$repo_root" --output "${results_dir}/coverage.json"
    --trivy-state "$trivy_state" --gitleaks-state "$gitleaks_state" --actionlint-state "$actionlint_state"
  )
  if [[ "$normalization_failed" == yes ]]; then command+=(--normalization-failed); fi
  "${command[@]}"
}

python3 "${repo_root}/scripts/normalize_results.py" \
  --input trivy "${results_dir}/trivy.json" \
  --input gitleaks "${results_dir}/gitleaks.json" \
  --input actionlint "${results_dir}/actionlint.txt" \
  --output "${results_dir}/normalized.json"
normalize_status=$?
if [[ $normalize_status -ne 0 ]]; then
  write_coverage yes || true
  python3 "${repo_root}/scripts/write_minimal_artifacts.py" policy --profile minimal --exit-code 3 --output "${results_dir}/policy-result.json" || true
  python3 "${repo_root}/scripts/write_minimal_artifacts.py" report --profile minimal --exit-code 3 --output "${results_dir}/report.md" || true
  exit 3
fi

if [[ $tool_error_count -eq 0 ]]; then
  python3 "${repo_root}/scripts/append_tool_errors.py" --results "${results_dir}/normalized.json"
else
  python3 "${repo_root}/scripts/append_tool_errors.py" \
    --results "${results_dir}/normalized.json" \
    "${tool_error_args[@]}"
fi
append_status=$?
if [[ $append_status -ne 0 ]]; then
  write_coverage yes || true
  python3 "${repo_root}/scripts/write_minimal_artifacts.py" policy --profile minimal --exit-code 3 --output "${results_dir}/policy-result.json" || true
  python3 "${repo_root}/scripts/write_minimal_artifacts.py" report --profile minimal --exit-code 3 --output "${results_dir}/report.md" || true
  exit 3
fi

write_coverage || exit 3

python3 "${repo_root}/scripts/policy_gate.py" \
  --results "${results_dir}/normalized.json" \
  --policy "${repo_root}/policy/severity-thresholds.yml" \
  --baseline "${repo_root}/policy/baseline.json" \
  --suppressions "${repo_root}/policy/suppressions.yml" \
  --minimum-severity "$minimum_severity" --enforcement "$enforcement" \
  --report "${results_dir}/report.md"
policy_status=$?
python3 "${repo_root}/scripts/write_minimal_artifacts.py" policy \
  --profile minimal --exit-code "$policy_status" --output "${results_dir}/policy-result.json" || exit 3
exit "$policy_status"

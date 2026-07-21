#!/usr/bin/env bash
set -uo pipefail

repo_root="${1:-.}"
results_dir="${2:-${repo_root}/results}"
tool_dir="${VIBESEC_TOOL_DIR:-${repo_root}/.tools/bin}"
minimum_severity="${VIBESEC_MIN_SEVERITY:-high}"
enforcement="${VIBESEC_ENFORCEMENT:-observe}"
mkdir -p "$results_dir"

tool_errors='[]'
record_tool_error() {
  local tool="$1"
  local message="$2"
  tool_errors="$(python3 -c 'import hashlib,json,sys; a=json.loads(sys.argv[1]); t=sys.argv[2]; m=sys.argv[3]; a.append({"tool":t,"category":"execution","rule_id":"tool-error","severity":"low","file":"","line":None,"description":m,"confidence":"unknown","fingerprint":hashlib.sha256((t+"\\0"+m).encode()).hexdigest(),"result_type":"tool_error"}); print(json.dumps(a))' "$tool_errors" "$tool" "$message")"
}

"${tool_dir}/trivy" filesystem --scanners vuln,misconfig,secret --format json --output "${results_dir}/trivy.json" --exit-code 0 --no-progress "$repo_root"
trivy_status=$?
if [[ $trivy_status -ne 0 ]]; then record_tool_error trivy "Trivy exited with status ${trivy_status}"; echo '{"Results":[]}' > "${results_dir}/trivy.json"; fi

"${tool_dir}/gitleaks" git --no-banner --redact --report-format json --report-path "${results_dir}/gitleaks.json" "$repo_root"
gitleaks_status=$?
if [[ $gitleaks_status -gt 1 ]]; then record_tool_error gitleaks "Gitleaks exited with status ${gitleaks_status}"; fi
[[ -f "${results_dir}/gitleaks.json" ]] || echo '[]' > "${results_dir}/gitleaks.json"

"${tool_dir}/actionlint" -no-color > "${results_dir}/actionlint.txt" 2>&1
actionlint_status=$?
if [[ $actionlint_status -gt 1 ]]; then record_tool_error actionlint "actionlint exited with status ${actionlint_status}"; echo -n > "${results_dir}/actionlint.txt"; fi

python3 "${repo_root}/scripts/normalize_results.py" \
  --input trivy "${results_dir}/trivy.json" \
  --input gitleaks "${results_dir}/gitleaks.json" \
  --input actionlint "${results_dir}/actionlint.txt" \
  --output "${results_dir}/normalized.json"
normalize_status=$?
if [[ $normalize_status -ne 0 ]]; then exit 3; fi

python3 -c 'import json,sys; p=sys.argv[1]; e=json.loads(sys.argv[2]); d=json.load(open(p)); d["results"].extend(e); open(p,"w").write(json.dumps(d,indent=2)+"\\n")' "${results_dir}/normalized.json" "$tool_errors"

python3 "${repo_root}/scripts/policy_gate.py" \
  --results "${results_dir}/normalized.json" \
  --policy "${repo_root}/policy/severity-thresholds.yml" \
  --baseline "${repo_root}/policy/baseline.json" \
  --suppressions "${repo_root}/policy/suppressions.yml" \
  --minimum-severity "$minimum_severity" --enforcement "$enforcement" \
  --report "${results_dir}/report.md"

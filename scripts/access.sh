#!/usr/bin/env bash
# Never inherit shell tracing into credential handling.
set +x
set -euo pipefail

error() {
  printf 'ERROR: %s\n' "$*" >&2
}

# Validate every input used by this operation before making any Azure request.
timeout_seconds="$(python3 - <<'PY'
import os
import re
import sys


def reject(message):
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


operation = os.environ.get("INPUT_OPERATION", "")
if operation not in ("add", "remove"):
    reject("operation must be add or remove.")

value = os.environ.get("INPUT_TIMEOUT_SECONDS", "")
if not re.fullmatch(r"[0-9]{1,10}", value) or not 1 <= int(value) <= 2147483647:
    reject("timeout-seconds must be an integer between 1 and 2147483647.")

name = r"[a-z0-9](?:[a-z0-9_.-]{0,78}[a-z0-9_])?"
profile_pattern = (
    r"/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"/resourceGroups/(?P<resource_group>[\w().-]{1,90})"
    r"/providers/Microsoft\.Network/networkSecurityPerimeters/" + name
    + r"/profiles/" + name
)


def valid_id(value, pattern):
    match = re.fullmatch(pattern, value, re.IGNORECASE)
    return match is not None and not match.group("resource_group").endswith(".")


if operation == "add":
    if not valid_id(os.environ.get("INPUT_PROFILE_ID", ""), profile_pattern):
        reject("profile-id must be a full Microsoft.Network NSP profile ARM ID with valid resource names.")
    if not re.fullmatch(r"[a-z0-9]{3,24}", os.environ.get("INPUT_STORAGE_ACCOUNT", "")):
        reject("storage-account must contain 3-24 lowercase letters or digits.")
    container = os.environ.get("INPUT_CONTAINER_NAME", "")
    if container not in ("$root", "$web", "$logs") and (
        not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", container) or "--" in container
    ):
        reject("container-name must be a valid Azure Blob container name.")
    for variable in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get(variable, "")):
            reject(f"{variable} must be a positive GitHub run identifier.")
else:
    rule_pattern = profile_pattern + r"/accessRules/gha-[0-9]+-[0-9]+-[0-9a-f]{24}"
    rule_id = os.environ.get("INPUT_RULE_ID", "")
    if not valid_id(rule_id, rule_pattern) or len(rule_id.rsplit("/", 1)[-1]) > 80:
        reject("rule-id must be the full action-generated gha-<run-id>-<attempt>-<24 hex digits> ARM rule ID.")

print(int(value))
PY
)"

[[ -n "${GITHUB_OUTPUT:-}" ]] || { error 'GITHUB_OUTPUT is required.'; exit 1; }
umask 077
workdir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/azure-nsp-access.XXXXXXXX")"
deadline=$((SECONDS + timeout_seconds))
rollback_rule=''
rule_id="${INPUT_RULE_ID:-}"
http_status=''
active_pid=''

# Each command is bounded by both the operation deadline and a short request cap.
request_seconds() {
  local remaining=$((deadline - SECONDS))
  if ((remaining <= 0)); then
    error 'Operation deadline exceeded.'
    return 1
  fi
  if ((remaining > $1)); then
    remaining=$1
  fi
  printf '%s\n' "$remaining"
}

run_bounded() {
  local seconds status=0
  seconds="$(request_seconds 30)" || return 1
  # Bash can interrupt wait immediately, rather than defer signal traps until an
  # external command finishes. timeout forwards termination to its child group.
  timeout --signal=TERM --kill-after=2s "${seconds}s" "$@" &
  active_pid=$!
  wait "$active_pid" || status=$?
  active_pid=''
  return "$status"
}

pause_poll() {
  local seconds
  seconds="$(request_seconds 5)" || return 1
  run_bounded sleep "$seconds"
}

arm_request() {
  local method=$1 seconds
  local -a body=()
  seconds="$(request_seconds 30)" || return 1
  if [[ "$method" == PUT ]]; then
    body=(--data-binary "@$workdir/rule.json")
  fi
  if ! run_bounded curl --silent --show-error --ipv4 --proto '=https' --tlsv1.2 \
    --connect-timeout "$seconds" --max-time "$seconds" \
    --request "$method" --header "@$workdir/authorization" \
    --header 'Content-Type: application/json' "${body[@]}" \
    --output "$workdir/response.json" --write-out '%{http_code}' \
    --url "https://management.azure.com${encoded_rule_id}?api-version=2024-07-01" \
    >"$workdir/http-status" 2>"$workdir/request-error"; then
    error "ARM $method request failed or timed out."
    cat "$workdir/request-error" >&2
    return 1
  fi
  http_status="$(<"$workdir/http-status")"
}

arm_absent() {
  # Authentication and authorization failures must never count as successful cleanup.
  [[ "$http_status" != 401 && "$http_status" != 403 ]] || return 1
  [[ "$http_status" == 404 ]] || jq -e '.error.code == "ResourceNotFound"' \
    "$workdir/response.json" >/dev/null 2>&1
}

arm_success() {
  [[ "$http_status" =~ ^2[0-9][0-9]$ ]]
}

report_arm_error() {
  error "ARM $1 returned HTTP $http_status for $rule_id."
  # Only structured service errors are logged; headers and bearer tokens are never logged.
  jq -r 'select(.error != null) | "ARM error: \(.error.code): \(.error.message)"' \
    "$workdir/response.json" >&2 2>/dev/null || true
}

remove_rule() {
  arm_request DELETE || return 1
  if arm_absent; then
    printf 'Temporary NSP rule is already absent: %s\n' "$rule_id"
    return 0
  fi
  if ! arm_success; then
    report_arm_error DELETE
    return 1
  fi

  # A successful DELETE response is not enough: confirm that this exact rule disappeared.
  while true; do
    arm_request GET || return 1
    if arm_absent; then
      printf 'Removed temporary NSP rule: %s\n' "$rule_id"
      return 0
    fi
    if ! arm_success; then
      report_arm_error GET
      return 1
    fi
    pause_poll || { error "Timed out waiting for deletion of $rule_id."; return 1; }
  done
}

finish() {
  local status=$?
  trap - EXIT
  trap '' HUP INT TERM
  if [[ -n "$active_pid" ]]; then
    kill -TERM "$active_pid" 2>/dev/null || true
    wait "$active_pid" 2>/dev/null || true
    active_pid=''
  fi
  if ((status != 0)) && [[ -n "$rollback_rule" ]]; then
    printf 'Rolling back this failed invocation\047s temporary NSP rule.\n' >&2
    # Rollback has its own budget even if readiness exhausted the original deadline.
    deadline=$((SECONDS + timeout_seconds))
    if ! remove_rule; then
      error "ROLLBACK FAILED: remove this exact rule manually or with operation remove: $rollback_rule"
    fi
  fi
  rm -rf -- "$workdir"
  exit "$status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! token="$(run_bounded az account get-access-token --resource https://management.azure.com/ \
  --query accessToken --output tsv --only-show-errors)"; then
  error 'Could not obtain an ARM token. Run azure/login@v3 before this action.'
  exit 1
fi
if [[ -z "$token" || "$token" == *$'\n'* || "$token" == *$'\r'* ]]; then
  error 'Azure CLI returned an invalid ARM token.'
  exit 1
fi
# Keep the bearer token out of command arguments and logs, in a private temporary file.
printf 'Authorization: Bearer %s\n' "$token" >"$workdir/authorization"
unset token

if [[ "$INPUT_OPERATION" == add ]]; then
  seconds="$(request_seconds 10)"
  if ! discovered_ip="$(curl --silent --show-error --fail --ipv4 --proto '=https' --tlsv1.2 \
    --connect-timeout "$seconds" --max-time "$seconds" --max-filesize 64 \
    --url https://api.ipify.org)"; then
    error 'Could not discover the runner public IPv4 address over HTTPS.'
    exit 1
  fi
  runner_ip="$(RUNNER_PUBLIC_IP="$discovered_ip" python3 - <<'PY'
import ipaddress
import os
import sys

try:
    address = ipaddress.ip_address(os.environ["RUNNER_PUBLIC_IP"].strip())
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global or (
        address.is_multicast or address.is_reserved or address.is_unspecified
    ):
        raise ValueError("not a public/global unicast IPv4 address")
except ValueError:
    print("ERROR: IP discovery did not return a public/global unicast IPv4 address.", file=sys.stderr)
    sys.exit(1)
print(address)
PY
)"
  random="$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
  rule_name="gha-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${random}"
  ((${#rule_name} <= 80)) || { error 'Generated rule name exceeds 80 characters.'; exit 1; }
  rule_id="${INPUT_PROFILE_ID}/accessRules/${rule_name}"
  jq -n --arg prefix "$runner_ip/32" \
    '{properties: {direction: "Inbound", addressPrefixes: [$prefix]}}' >"$workdir/rule.json"

  # Publish before PUT, including when PUT fails after Azure accepted the request.
  printf 'rule-id=%s\nrunner-ip=%s\n' "$rule_id" "$runner_ip" >>"$GITHUB_OUTPUT"
fi

encoded_rule_id="$(RULE_ID="$rule_id" python3 - <<'PY'
import os
import urllib.parse
print(urllib.parse.quote(os.environ["RULE_ID"], safe="/"))
PY
)"

if [[ "$INPUT_OPERATION" == remove ]]; then
  remove_rule
  exit 0
fi

# Arm rollback before PUT: failed or interrupted requests can still create a rule.
rollback_rule=$rule_id
printf 'Granting temporary NSP access for %s/32 using %s.\n' "$runner_ip" "$rule_id"
arm_request PUT
if ! arm_success; then
  report_arm_error PUT
  exit 1
fi

while true; do
  arm_request GET
  if ! arm_success; then
    report_arm_error GET
    exit 1
  fi
  state="$(jq -er '.properties.provisioningState | strings' "$workdir/response.json")" || {
    error 'ARM response did not include a provisioning state.'
    exit 1
  }
  case "$state" in
    Succeeded)
      if ! jq -e --arg prefix "$runner_ip/32" \
        '.properties.direction == "Inbound" and .properties.addressPrefixes == [$prefix]' \
        "$workdir/response.json" >/dev/null; then
        error "Provisioned rule does not match this invocation's exact IPv4 /32."
        exit 1
      fi
      break
      ;;
    Failed|Canceled)
      error "NSP rule provisioning ended in $state."
      exit 1
      ;;
  esac
  printf 'Waiting for NSP rule provisioning (%s).\n' "$state"
  pause_poll || { error 'Timed out waiting for NSP rule provisioning.'; exit 1; }
done

printf 'Waiting for Entra-authenticated blob listing.\n'
while true; do
  if ((SECONDS >= deadline)); then
    error "Authenticated readiness failed for $INPUT_STORAGE_ACCOUNT/$INPUT_CONTAINER_NAME."
    if [[ -f "$workdir/probe-error" ]]; then
      cat "$workdir/probe-error" >&2
    fi
    exit 1
  fi
  if run_bounded env -u AZURE_STORAGE_KEY -u AZURE_STORAGE_CONNECTION_STRING \
    -u AZURE_STORAGE_SAS_TOKEN -u AZURE_STORAGE_SERVICE_ENDPOINT \
    az storage blob list --account-name "$INPUT_STORAGE_ACCOUNT" \
    --container-name "$INPUT_CONTAINER_NAME" --num-results 1 \
    --auth-mode login --only-show-errors --output none \
    >"$workdir/probe-output" 2>"$workdir/probe-error"; then
    break
  fi
  if ! pause_poll; then
    error "Authenticated readiness failed for $INPUT_STORAGE_ACCOUNT/$INPUT_CONTAINER_NAME."
    cat "$workdir/probe-error" >&2
    exit 1
  fi
done

printf 'NSP access is ready; authenticated blob listing succeeded.\n'
# The caller must now remove this rule in an always() step after its workload.
rollback_rule=''

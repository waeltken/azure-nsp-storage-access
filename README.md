# Azure NSP storage access

A YAML composite GitHub Action that temporarily admits an ordinary `ubuntu-latest` runner's current public IPv4 address to an existing Azure Network Security Perimeter (NSP) profile. It creates one unique inbound `/32` rule per invocation, waits for ARM provisioning, and verifies an **Entra-authenticated blob listing in the specified container** before returning.

The action never changes the perimeter's **Enforced** mode, storage settings, shared-key policy, or existing rules. It uses the Azure public cloud ARM API `2024-07-01`; there is no JavaScript runtime, bundled code, or dependency installation.

## Prerequisites and permissions

- An existing NSP profile, with the target storage account associated and enforced. This action does not create the perimeter, profile, association, account, or container, and does not make a private-only storage endpoint public.
- An ordinary GitHub-hosted Ubuntu runner with Bash, Azure CLI (`az`), `curl`, `jq`, Python 3, and GNU `timeout` available. These are available on `ubuntu-latest`. IPv4 HTTPS access to `api.ipify.org`, Azure ARM, Azure sign-in, and the Blob endpoint is required.
- Run [`azure/login@v3`](https://github.com/Azure/login) **before** this action, using Azure OIDC federation. Give the job `id-token: write` and configure a federated identity credential for the actual repository and branch or environment, with audience `api://AzureADTokenExchange`. Match the repository's actual subject format, including immutable owner/repository IDs where enabled. Restrict the environment to trusted deployment branches and reviewers as appropriate.
- Assign the login identity **Network Contributor at the existing NSP profile ARM ID**, not at subscription scope. This permits profile access-rule reads, writes, and deletes. Network Contributor can modify other rules in that profile too: only trusted workflows should receive this identity. No Owner role or permission to change storage settings is needed.
- Assign **Storage Blob Data Reader** at the target container (or a containing storage scope) for the authenticated readiness probe. Its scope can be `/subscriptions/SUBSCRIPTION/resourceGroups/GROUP/providers/Microsoft.Storage/storageAccounts/ACCOUNT/blobServices/default/containers/CONTAINER`. Storage management-plane Reader and account-key lookup permissions are not required.
- A Terraform backend that writes or leases state needs **Storage Blob Data Contributor** separately, normally at the state container. Data Contributor also satisfies the probe; do not add Data Reader redundantly in that case. Configure the backend to use Entra authentication, not shared keys.

The ARM profile ID has this full form, without a trailing slash:

```text
/subscriptions/SUBSCRIPTION-UUID/resourceGroups/GROUP/providers/Microsoft.Network/networkSecurityPerimeters/PERIMETER/profiles/PROFILE
```

Provision roles and federation before running the workflow; Azure RBAC propagation is independent of network-rule propagation.

Inspect the consuming repository's OIDC configuration before creating its Azure credential:

```bash
gh api repos/OWNER/REPO/actions/oidc/customization/sub \
  --jq '{use_default, use_immutable_subject, sub_claim_prefix}'
```

With the default claim template, append `:environment:production` for a job using
that environment, or `:ref:refs/heads/main` for a main-branch job without an
environment. Repositories created after July 15, 2026 use a prefix such as
`repo:OWNER@OWNER-ID/REPO@REPO-ID`; older repositories may still use
`repo:OWNER/REPO`. Custom claim templates require their exact configured subject.
Do not disable immutable claims to make an old credential example work. See
[GitHub's immutable subject reference](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims).

## Usage

This example assumes Terraform configuration in the repository root, an `azurerm` backend configured for the named state account/container, and repository or environment variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `NSP_PROFILE_ID`, and `TFSTATE_STORAGE_ACCOUNT`.

```yaml
name: Terraform
on:
  workflow_dispatch:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write

jobs:
  terraform:
    runs-on: ubuntu-latest
    environment: production
    env:
      ARM_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
      ARM_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
      ARM_SUBSCRIPTION_ID: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      ARM_USE_OIDC: 'true'
      ARM_USE_AZUREAD: 'true'
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: azure/login@v3
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - uses: hashicorp/setup-terraform@v3
      - name: Grant this runner access and wait for readiness
        id: nsp
        uses: waeltken/azure-nsp-storage-access@v1
        with:
          profile-id: ${{ vars.NSP_PROFILE_ID }}
          storage-account: ${{ vars.TFSTATE_STORAGE_ACCOUNT }}
          container-name: tfstate
      - name: Terraform workload
        run: |
          terraform init -input=false
          terraform plan -input=false
      - name: Revoke this invocation's access
        if: ${{ always() && steps.nsp.outputs.rule-id != '' }}
        uses: waeltken/azure-nsp-storage-access@v1
        with:
          operation: remove
          rule-id: ${{ steps.nsp.outputs.rule-id }}
```

**The final `always()` cleanup step is mandatory.** A composite action has no post-job hook. The additional nonempty-ID condition skips removal only when add never produced a rule ID, for example if login or input validation failed. Do not use `continue-on-error` on production grants or cleanup. Keep the Azure login session valid until cleanup finishes. Use the same action version for both steps; pin a reviewed release commit SHA instead of a floating version tag where your supply-chain policy requires it.

Each job, concurrent run, or matrix entry must perform its own add and remove. Never discover the IP again for cleanup: remove the exact `rule-id` output from that invocation.

## Inputs

| Input | Required | Default | Meaning |
| --- | --- | --- | --- |
| `operation` | No | `add` | Exactly `add` or `remove`. |
| `profile-id` | For add | — | Full existing Microsoft.Network NSP profile ARM ID. |
| `storage-account` | For add | — | Account to probe; 3–24 lowercase letters or digits. |
| `container-name` | For add | — | Existing valid Blob container name, including `$root`, `$web`, or `$logs` if needed. |
| `rule-id` | For remove | — | Exact full ARM rule ID returned by add, with an action-generated `gha-<run-id>-<attempt>-<24 hex digits>` name. Profile IDs, other resource types, and ordinary rule names are rejected. |
| `timeout-seconds` | No | `300` | Positive integer deadline, 1–2147483647 seconds. Each network/CLI request is additionally bounded to at most 30 seconds; IP discovery to at most 10 seconds. Failed-add rollback gets a separate deadline of the same length. |

Unused operation-specific inputs are ignored. All inputs needed for the selected operation are validated before any Azure request or mutation. Input expressions enter Bash through environment variables, not generated shell code.

## Outputs

| Output | Meaning |
| --- | --- |
| `rule-id` | Full ARM ID of the invocation's unique rule. Written **before PUT**, so a failed or interrupted create can still be cleaned up. Add only. |
| `runner-ip` | Validated public/global unicast IPv4 address, without `/32`. Add only. |

Rule names are `gha-<GitHub run ID>-<run attempt>-<96 random bits in hex>`, at most 80 characters. Each rule contains exactly one inbound address prefix, the discovered IPv4 `/32`. Concurrent invocations never edit a shared IP list or reuse a common rule name.

## Readiness, failures, and cleanup

Add polls ARM until provisioning succeeds and then polls `az storage blob list --auth-mode login --num-results 1` against the exact account/container. This checks the List Blobs operation used by Terraform backend workspace discovery: a container metadata read can succeed while blob listing is still denied during perimeter propagation. Results are discarded, and the readiness probe does not download blob contents. It clears ambient storage-key, connection-string, SAS, and endpoint overrides. A successful ARM response or container metadata read alone is **not** readiness. The probe does not prove that a later Terraform write has sufficient RBAC permissions.

A failed add, a readiness timeout, or a handled cancellation attempts internal rollback of its own rule, including when PUT may have partially succeeded. The original failure remains a failure, and rollback errors report the exact rule ID that needs attention. The caller's final cleanup remains necessary after a successful add and is also safe after internal rollback.

Remove validates the supplied action-generated rule ID, deletes only that resource, and polls until it disappears. An exact HTTP 404 or ARM `ResourceNotFound` is idempotent success. Authentication, permission, transport, deadline, and other ARM errors are failures, not silently ignored. A successful delete response is followed by an absence check; disappearance from ARM does not imply that every distributed enforcement cache has already converged.

**Cleanup cannot be guaranteed if the runner disappears, is force-killed, loses connectivity or credentials, or its cleanup budget is exhausted.** Cancellation traps and `always()` are best effort, not a lease or server-side expiration. There is no automatic TTL, permanent broad CIDR, public allow-all rule, or scheduled janitor.

### Finding and removing a stale rule

Sign in as an operator with access-rule permissions. List the profile's action-generated rules, inspecting creation times, IPs, and GitHub run IDs before deciding that any rule is stale:

```bash
PROFILE_ID='/subscriptions/SUBSCRIPTION-UUID/resourceGroups/GROUP/providers/Microsoft.Network/networkSecurityPerimeters/PERIMETER/profiles/PROFILE'
az rest --method get \
  --url "https://management.azure.com${PROFILE_ID}/accessRules?api-version=2024-07-01" \
  --query "value[?starts_with(name, 'gha-')].{name:name,id:id,createdAt:systemData.createdAt,prefixes:properties.addressPrefixes}" \
  --output json
```

Follow `nextLink` if the list is paginated. The name identifies the GitHub run and attempt; ensure that run is no longer using the rule. Copy **one exact stale rule ID** from the result and remove it with `operation: remove` in an authenticated workflow, or manually:

```bash
RULE_ID='FULL-RULE-ID-COPIED-FROM-THE-LIST'
az rest --method delete \
  --url "https://management.azure.com${RULE_ID}?api-version=2024-07-01"
# Confirm this exact resource is absent; only ResourceNotFound/HTTP 404 means gone.
az rest --method get \
  --url "https://management.azure.com${RULE_ID}?api-version=2024-07-01"
```

Do not bulk-delete every `gha-` rule: other jobs may still be using theirs. Do not change home-office or other pre-existing rules to recover from a stale invocation.

## Security boundary

A public `/32` is still **shared source trust**, not a runner identity. Other traffic using the same public egress address can pass that network rule while it exists. Entra authentication and narrowly scoped data-plane authorization remain required; keep shared keys disabled. Restrict who can change the workflow or obtain its OIDC identity. If discovery and storage use different source addresses, or egress changes mid-job, readiness or the workload can fail; this action never broadens the prefix to compensate.

The action writes its ARM bearer header only into a private temporary directory, never into command arguments or outputs, and removes it on normal/handled exit. It does not enable debug or shell tracing and never prints tokens. As with any action, do not run untrusted code alongside credentials on the same runner.

## Static checks

The credential-free `Static checks` workflow parses action/workflow YAML and runs Bash syntax checking and ShellCheck. It does not sign in to Azure or run deployments. Live end-to-end use requires the real Azure prerequisites above.

## Live integration check

The manually dispatched `Integration smoke` workflow exercises real Azure resources
from `ubuntu-latest`: denied access before granting, authenticated readiness, two
overlapping invocation rules, isolated deletion, idempotent removal, failed-setup
rollback, and preservation of the cleanup output after a failed composite step.
It verifies that all of its rule IDs are absent at the end. By default, it does
not download blob contents. Supplying the optional `state-key` input also runs
`terraform init` against that existing backend with direct OIDC and CLI auth
disabled. That check can read the existing state but does not print its contents
or run Terraform plan/apply. Use a state key the test identity may safely read.

Use a disposable identity with only the profile-scoped Network Contributor and
container-scoped Blob Data Reader roles above. Configure its exact main-branch
OIDC subject for this repository and supply the workflow inputs. Remove that
identity and its role assignments afterward. Consumers must federate their own
calling repository; using this public action does not require trusting the action
repository with their deployment identity.

## License

[MIT](LICENSE).

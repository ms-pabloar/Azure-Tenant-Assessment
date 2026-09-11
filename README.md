# Azure Tenant Assessment

**Automated Azure tenant-wide analysis aligned with the Microsoft Azure Well-Architected Framework (WAF), Zero Trust security model, and Azure Landing Zone (ALZ) best practices.**

> **This script is read-only and does NOT deploy, modify, create, or delete any Azure resource.** It performs analysis exclusively through read-only API calls (`GET` requests and Azure Resource Graph queries). Your environment remains completely unchanged after execution.

---

## What It Does

This script performs a comprehensive, automated assessment of an entire Azure tenant — across all subscriptions — and generates a set of interactive reports with prioritized findings, cost insights, network topology diagrams, and actionable recommendations.

It evaluates **every subscription** the authenticated identity has access to, analyzing resources against **6 WAF pillars** (Security, Reliability, Cost Optimization, Operational Excellence, Performance Efficiency) plus **Zero Trust** and **ALZ/CAF readiness** checks.

### Key Capabilities

- **30+ specialized analysis functions** covering networking, compute, databases, storage, identity, containers, monitoring, BCDR, cost, modernization, and more
- **Real Azure Monitor metrics** (CPU, network, DTU, IOPS, requests) to identify underutilized and idle resources
- **6-month cost trend analysis** per subscription, broken down by service, with monthly sparklines
- **Reservation and Savings Plan purchase analysis** using Azure-calculated 30/60-day usage, hourly commitments, coverage, utilization, and projected savings
- **Network topology visualization** — interactive SVG diagram showing VNets, subnets, NSGs, peering connections, public IPs, NAT Gateways, and internet egress paths
- **Zero Trust maturity assessment** across Network, Compute, and Platform layers
- **ALZ/CAF readiness evaluation** including management group hierarchy, policy enforcement, and naming conventions
- **Tag compliance analysis** against configurable mandatory tags
- **Expiring secrets and certificates** detection in Key Vaults (30/60/90-day windows)
- **Private endpoint adoption** tracking across supported services

---

## Output Files

The script generates **7 files** in a timestamped output directory:

| File | Description |
|------|-------------|
| `Assessment_Report.html` | Full interactive report with 16 blade sections, severity/pillar/category filters, search, and export capabilities |
| `Executive_Report.html` | Concise executive summary optimized for PDF generation (Ctrl+P in Chrome/Edge) |
| `Network_Topology.html` | Interactive SVG network diagram — VNets, subnets, peering, public IPs, NAT Gateways, edge devices |
| `Network_Topology.drawio` | Same topology in editable Draw.io format (open at [draw.io](https://app.diagrams.net)) |
| `Assessment_Data.json` | Complete structured data export — subscriptions, findings, resources, topology (for programmatic analysis) |
| `Findings.csv` | Flat CSV export of all findings — ready for Excel, Power BI, or data lake ingestion |
| `Assessment_Log.txt` | Detailed execution log with timestamps, progress, warnings, and errors |

All output is **self-contained HTML** — no external dependencies, no internet required to view the reports. Just open in any modern browser.

---

## Requirements

### Runtime

- **PowerShell 7.0+** (cross-platform; runs on Windows, Linux, macOS, and Azure Cloud Shell)
- **Az PowerShell Modules** — `Az.Accounts` 3.0.0+ (other Az modules are auto-imported as needed)

### Permissions

The script requires **read-only** access. No write permissions are needed.

| Permission | Scope | Required? | Purpose |
|------------|-------|-----------|---------|
| **Reader** | Each subscription | **Yes** | Resource enumeration, configuration analysis, network topology |
| **Cost Management Reader** | Each subscription | Optional | Cost trends and Savings Plan recommendations; gracefully skipped if unavailable |
| **Reservation Reader** | Billing scope | Optional | Existing reservation inventory, utilization, and purchase recommendations |
| **Key Vault Secrets List** | Key Vaults (data-plane) | Optional | Expiring secrets/certificates detection; skip with `-SkipKeyVaultDataPlane` |
| **Management Group Reader** | Tenant Root Group | Optional | ALZ/CAF readiness analysis (MG hierarchy, tenant-level policies) |
| **Microsoft Graph** | Tenant | Optional | Conditional Access and PIM verification; auto-connects if `Microsoft.Graph.Authentication` module is installed |

> **Minimum viable**: A single `Reader` role assignment at the subscription level is sufficient to run the assessment. All optional features degrade gracefully with clear status messages.

---

## Usage

### Azure Cloud Shell (Recommended)

```powershell
# 1. Upload the script to Cloud Shell (drag & drop or use the Upload button)

# 2. Run the assessment (the existing Cloud Shell session is reused automatically)
./Azure-Tenant-Assessment.ps1

# 3. Download the output folder when complete
```

### Local Machine

```powershell
# 1. Start PowerShell 7 and run against the customer's tenant
pwsh
./Azure-Tenant-Assessment.ps1 -TenantId '<customer-tenant-id>' -UseDeviceAuthentication -SkipGraphLogin
```

The script installs the Az rollup in `CurrentUser` scope when it is missing. In restricted environments, install it before the assessment:

```powershell
Install-Module Az -Scope CurrentUser -Force -AllowClobber
Connect-AzAccount -Tenant '<customer-tenant-id>' -UseDeviceAuthentication

# Reuse that session without another Azure login
./Azure-Tenant-Assessment.ps1 -SkipLogin -TenantId '<customer-tenant-id>' -SkipGraphLogin
```

### Common Options

```powershell
# Assess a single subscription
./Azure-Tenant-Assessment.ps1 -SkipLogin -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Assess selected subscriptions in batches with isolated parallel workers
./Azure-Tenant-Assessment.ps1 -SkipLogin `
	-SubscriptionId @('sub-id-1','sub-id-2','sub-id-3') `
	-BatchSize 20 -MaxParallelism 4 -OutputPath './LargeTenant'

# Resume an interrupted run using the same output and checkpoint paths
./Azure-Tenant-Assessment.ps1 -SkipLogin -Resume `
	-OutputPath './LargeTenant' -CheckpointPath './LargeTenant/.checkpoint' `
	-BatchSize 20 -MaxParallelism 4

# Retry only subscriptions whose last checkpoint is Failed
./Azure-Tenant-Assessment.ps1 -SkipLogin -RetryFailedOnly `
	-OutputPath './LargeTenant' -CheckpointPath './LargeTenant/.checkpoint' `
	-MaxParallelism 4

# Fast mode — skip Azure Monitor metrics collection
./Azure-Tenant-Assessment.ps1 -SkipLogin -SkipMetrics

# Custom output directory
./Azure-Tenant-Assessment.ps1 -SkipLogin -OutputPath "./MyAssessment"

# Customize underutilization thresholds
./Azure-Tenant-Assessment.ps1 -SkipLogin -CpuLowPercent 15 -MetricDays 14

# Custom mandatory tags for compliance analysis
./Azure-Tenant-Assessment.ps1 -SkipLogin -MandatoryTags @('Environment','Owner','CostCenter','Project')

# Use 60 days of eligible usage for commitment purchase recommendations
./Azure-Tenant-Assessment.ps1 -CommitmentLookbackDays 60

# Azure AI inventory and best-practice checks are automatic and reuse Resource Graph.
# Add Azure Monitor utilization metrics only when required.
./Azure-Tenant-Assessment.ps1 -IncludeAIMetrics -MetricDays 7

# Lightweight GitHub governance (one organization request; no repository crawl)
$env:GH_TOKEN = '<fine-grained token>' # GITHUB_TOKEN or `gh auth login` are also supported
./Azure-Tenant-Assessment.ps1 -GitHubOrganization @('contoso')

# Add the latest aggregate 28-day GitHub Copilot report
./Azure-Tenant-Assessment.ps1 -GitHubOrganization @('contoso') -IncludeGitHubCopilot

# Aggregate Microsoft 365 Copilot adoption (requires Graph Reports.Read.All)
./Azure-Tenant-Assessment.ps1 -IncludeM365Copilot -CopilotUsagePeriod D28
```

Azure AI inventory and configuration checks reuse the existing Resource Graph result and add no Azure API calls. `-IncludeAIMetrics` performs at most one metric-definition request and one batched metric request per discovered AI account. GitHub and Copilot integrations run once in the coordinator, never once per subscription or worker.

External integrations are optional and non-blocking. GitHub credentials are read from `GH_TOKEN`, `GITHUB_TOKEN`, or an existing `gh auth login` session; Microsoft 365 Copilot uses an existing Microsoft Graph session with `Reports.Read.All`, `M365_COPILOT_ACCESS_TOKEN`, or the current Az Graph token. Tokens are never written to worker configuration, checkpoints, logs, or reports. Remove environment tokens after execution when they are no longer required.

### All Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SubscriptionId` | string[] | *(all)* | Analyze one or more subscription IDs |
| `-SkipLogin` | switch | false | Explicitly skip `Connect-AzAccount`; Cloud Shell sessions are detected automatically |
| `-TenantId` | string | *(current tenant)* | Authenticate to and assess an explicit Microsoft Entra tenant |
| `-UseDeviceAuthentication` | switch | false | Use device-code Azure authentication when a browser cannot open locally |
| `-SkipGraphLogin` | switch | false | Skip optional interactive Microsoft Graph login; CA/PIM remain manual checks when token reuse is unavailable |
| `-OutputPath` | string | `./AzureAssessment_<timestamp>` | Output directory for all generated files |
| `-BatchSize` | int | `20` | Maximum subscriptions in each processing batch |
| `-MaxParallelism` | int | `1` | Isolated subscription worker processes; use `3`–`5` for large tenants to limit API throttling |
| `-WorkerTimeoutMinutes` | int | `180` | Maximum runtime for one isolated subscription worker before it is terminated and checkpointed as failed |
| `-ProgressIntervalSeconds` | int | `60` | Interval (30–900 seconds) for subscription progress, elapsed time, ETA, and estimated finish updates |
| `-IncludeAIMetrics` | switch | false | Query supported Azure Monitor usage, latency, availability, safety, and PTU metrics for discovered AI accounts |
| `-GitHubOrganization` | string[] | *(none)* | Run one lightweight governance query per organization using `GITHUB_TOKEN` or an existing `gh` login |
| `-IncludeGitHubCopilot` | switch | false | Download the latest aggregate 28-day Copilot report for each specified GitHub organization |
| `-IncludeM365Copilot` | switch | false | Query aggregate Microsoft 365 Copilot adoption; requires Microsoft Graph `Reports.Read.All` |
| `-CopilotUsagePeriod` | string | `D28` | Microsoft 365 Copilot report period: `D7`, `D28`, `D90`, or `D180` |
| `-CheckpointPath` | string | `<OutputPath>/.checkpoint` | Persistent checkpoint and per-subscription JSON directory |
| `-Resume` | switch | false | Restore completed subscriptions and process pending or failed subscriptions |
| `-RetryFailedOnly` | switch | false | Restore completed results and process only subscriptions whose latest checkpoint failed |
| `-SkipMetrics` | switch | false | Skip Azure Monitor metrics collection (faster execution) |
| `-SkipKeyVaultDataPlane` | switch | false | Skip Key Vault secret/certificate enumeration |
| `-SkipBackupDetails` | switch | false | Skip detailed backup item enumeration |
| `-MetricDays` | int | 7 | Metrics analysis window in days (7 or 14) |
| `-CommitmentLookbackDays` | int | 30 | Azure commitment recommendation lookback (`30` or `60` days) |
| `-CpuLowPercent` | int | 10 | CPU % threshold for underutilized VM detection |
| `-CpuIdlePercent` | int | 5 | CPU % threshold for idle VM detection |
| `-NetLowMB` | int | 5 | Network throughput (MB/h) threshold |
| `-AppRequestLowPerHour` | int | 10 | App Service request/hour threshold |
| `-SqlDtuLowPercent` | int | 10 | SQL DTU % threshold |
| `-SqlCpuLowPercent` | int | 10 | SQL CPU % threshold |
| `-DiskLowIops` | int | 5 | Disk IOPS threshold |
| `-IncludeALZ` | switch | false | Backward compatibility flag (ALZ runs by default) |
| `-MandatoryTags` | string[] | `Environment, Owner, CostCenter, Application, Department` | Required tags for compliance |

---

## Assessment Coverage

### Well-Architected Framework Pillars

| Pillar | Areas Covered |
|--------|---------------|
| **Security** | NSG rules, DDoS protection, encryption at rest/transit, HTTPS enforcement, firewall configurations, Defender for Cloud plans, Key Vault access policies, RBAC, managed identities, private endpoints, TDE, disk encryption |
| **Reliability** | High availability (zones/sets), storage replication (LRS vs GRS/ZRS), SQL failover groups, Cosmos DB multi-region, App Service redundancy, backup coverage, ASR replication health, retention policies |
| **Cost Optimization** | Underutilized VMs/databases/disks (real metrics), orphaned resources (disks, NICs, public IPs), Azure Hybrid Benefit eligibility, reservation coverage, Advisor cost recommendations, 6-month cost trends |
| **Operational Excellence** | Diagnostic settings coverage, Azure Monitor agents, tag compliance, resource locks on critical resources, policy assignments, ALZ/CAF readiness, subscription hygiene |
| **Performance Efficiency** | VM right-sizing, storage tier optimization, App Service plan utilization, database SKU analysis, modernization opportunities (legacy OS, IaaS→PaaS) |
| **Zero Trust** | Network micro-segmentation, Azure Firewall inspection, private endpoints, JIT access, MFA enforcement, Conditional Access policies, PIM adoption, SIEM integration |

### Analysis Functions (30+)

| Function | What It Analyzes |
|----------|-----------------|
| `Analyze-Networking` | VNets, subnets, NSGs, route tables, VPN gateways, ExpressRoute, firewalls, Network Watcher, DDoS |
| `Analyze-VirtualMachines` | VM status, disk encryption, monitoring agents, Hybrid Benefit, scale sets |
| `Analyze-AppServices` | HTTPS-only, FTP state, managed identity, authentication, Always On, diagnostics |
| `Analyze-Databases` | SQL firewall rules, TDE, failover groups, geo-replication, PostgreSQL/MySQL config |
| `Analyze-Storage` | HTTPS-only, firewall rules, key rotation, blob versioning, soft delete, replication tier |
| `Analyze-KeyVaults` | Purge protection, network ACLs, RBAC mode, secret/certificate expiration |
| `Analyze-OrphanedResources` | Unattached disks, unused NICs, idle public IPs |
| `Analyze-SecurityCenter` | Defender for Cloud plan enablement across all resource types |
| `Analyze-AKS` | Kubernetes RBAC, network policy, Azure CNI, pod security, auth methods |
| `Analyze-ZeroTrust` | Network/Compute/Platform layer Zero Trust maturity |
| `Analyze-UnderutilizedResources` | Real Azure Monitor metrics for CPU, network, DTU, IOPS, requests |
| `Analyze-Modernization` | End-of-support OS detection, legacy SQL, IaaS→PaaS migration candidates |
| `Analyze-CostAdvisor` | Azure Advisor cost recommendations, Hybrid Benefit opportunities |
| `Analyze-BCDR` | Backup vault coverage, backup status, retention, ASR replication health |
| `Analyze-HighAvailability` | Zone/geo redundancy, storage replication, failover groups |
| `Analyze-TagCompliance` | Mandatory tag coverage, untagged resources, compliance percentage |
| `Analyze-DiagnosticSettings` | Diagnostic settings for NSGs, LBs, SQL, Storage, App Gateways, Firewalls, AKS |
| `Analyze-PrivateEndpoints` | Private endpoint adoption across SQL, Storage, Key Vault, Cosmos DB, App Services |
| `Analyze-PolicyCompliance` | Azure Policy assignment status, exemptions, initiative coverage |
| `Analyze-ResourceLocks` | Delete/ReadOnly locks on critical resources |
| `Analyze-ExpiringSecrets` | Key Vault secrets/certificates expiring within 30/60/90 days |
| `Analyze-CrossPillarCorrelation` | Multi-pillar patterns (e.g., unencrypted + no backup = compounding risk) |
| `Analyze-ALZReadiness` | Management group structure, platform subscriptions, policy enforcement, naming |
| `Analyze-SubscriptionHygiene` | Unused subscriptions, service principal cleanup, orphaned identities |
| `Analyze-CosmosOSSDatabase` | Cosmos DB, PostgreSQL, MySQL — backup, encryption, replication |
| *...and more* | Additional checks for reservations, hybrid infrastructure, DevOps security, application security |

---

## Data Collection Methods

### Azure Resource Graph (Primary)
The script uses **Azure Resource Graph** (`Search-AzGraph`) for bulk resource queries across subscriptions in batches of 20. This is significantly faster than individual `Get-Az*` calls and allows cross-subscription analysis in a single query.

### Azure Monitor Metrics
Real-time utilization data is collected via `Get-AzMetric` with configurable time windows:
- **7-day window** → 1-hour granularity (168 data points per resource)
- **14-day window** → 6-hour granularity (56 data points per resource)

### Cost Management API
Cost data is collected via the Azure Cost Management REST API (`Microsoft.CostManagement/query`):
- **6-month lookback** with monthly granularity
- **Grouped by service name** (Virtual Machines, Storage, Networking, etc.)
- **Automatic throttling recovery** — retries HTTP 429 responses up to 6 times, honoring Azure retry headers with exponential backoff as fallback
- Requires `Cost Management Reader` role (optional; gracefully skipped)

### Reservation and Savings Plan Recommendations

Purchase recommendations come from Azure's billing recommendation engines rather than static public prices:

- **Reservations** use `Microsoft.Consumption/reservationRecommendations` to compare actual PAYG cost against 1-year and 3-year reservation scenarios by SKU, family, region, quantity, and scope.
- **Savings Plans** use `Microsoft.CostManagement/benefitRecommendations` with hourly eligible charges, commitment amount, coverage, projected utilization, wastage, and 1-year/3-year terms.
- **Existing Reservations** use 30 daily summaries from `Microsoft.Consumption/reservationSummaries` to report reserved hours, used hours, unused hours, and weighted utilization. If summary access is unavailable, the inventory falls back to the 7-day utilization aggregate from `Microsoft.Capacity`.
- Existing eligible Reservations and Savings Plans are accounted for by Azure's recommendation model.
- A recommendation must meet conservative savings and utilization thresholds. Matching underutilized VMs are marked `Review first` so rightsizing happens before commitment purchase.
- Only one overlapping option per subscription is marked `Preferred`; other valid options remain visible as alternatives.

Unused hours quantify idle committed capacity, not an exact currency loss. Realized monetary savings require reservation purchase charges and the customer's billing agreement, so the report does not manufacture a dollar estimate. These recommendations support financial review and do not purchase or modify any Azure benefit.

### Microsoft Graph (Optional)
If the `Microsoft.Graph.Authentication` module is installed, the script auto-connects to verify:
- Conditional Access policies
- PIM (Privileged Identity Management) adoption
- Directory role assignments

---

## Security & Integrity

### What This Script Does NOT Do

- **Does NOT create** any Azure resources
- **Does NOT modify** any configurations, settings, or policies
- **Does NOT delete** any resources or data
- **Does NOT write** to any Azure storage, database, or service
- **Does NOT send** data to any external endpoint — all output stays local
- **Does NOT require** or use any write permissions

The script operates exclusively through **read-only API calls** (`GET` requests, Resource Graph queries, and Azure Monitor metric reads).

### Authenticode Signature

The script is digitally signed with an Authenticode certificate. The signature guarantees:
- **Integrity** — the script has not been modified since it was signed
- **Authenticity** — the script comes from the original author

### Runtime Integrity Check

At startup, the script checks its Authenticode signature when the host supports it. By default, an invalid, missing, or untrusted signature produces a warning and execution continues. This avoids blocking execution on customer workstations that do not trust the author's certificate.

Do not use `-RequireValidSignature` on a customer workstation unless the signing certificate is trusted there. Windows execution policy is evaluated before the script starts and cannot be overridden by script code. For a downloaded file, inspect it and remove the Mark of the Web with `Unblock-File .\Azure-Tenant-Assessment.ps1`. If organizational `MachinePolicy` or `UserPolicy` blocks scripts, the customer's administrator must allow execution.

Use strict enforcement when the signing certificate is trusted on the computer:

```powershell
./Azure-Tenant-Assessment.ps1 -RequireValidSignature
```

In strict mode, execution is blocked unless PowerShell reports the signature status as `Valid`.

### SOC/EDR Compatibility

The script is distributed as **plain-text PowerShell** with no encoding, compression, or obfuscation. Security teams can freely inspect the source code. There are no:
- Base64-encoded payloads
- GZip decompression at runtime
- Temporary file writes for execution
- `Invoke-Expression` calls
- Hidden or encoded command execution

---

## Cloud Shell Considerations

For large tenants (50+ subscriptions), execution can take several hours. The script includes built-in resilience:

- **Resource-aware execution** — skips detailed collection and analysis modules when Resource Graph confirms the applicable resource type does not exist
- **Centralized inventory reuse** — reuses resource, tag, Marketplace, private endpoint, and resource-group data instead of listing the same resources repeatedly
- **Diagnostic settings fast path** — treats an empty successful Resource Graph result as authoritative, avoiding one API call per resource
- **Tenant-wide benefit cache** — queries Reservations and Savings Plans inventory once, including when no benefits exist
- **Keep-alive heartbeat** — writes to console at `-ProgressIntervalSeconds` intervals to prevent Cloud Shell idle timeout
- **Persistent default output** — when `$HOME/clouddrive` is mounted and `-OutputPath` is omitted, reports and checkpoints are stored there automatically
- **Session reuse** — detects the authenticated Cloud Shell context and avoids a duplicate `Connect-AzAccount` session
- **Token refresh** — automatically refreshes Azure access tokens every 15 minutes to prevent expiration
- **Network retry** — retries subscription context switches up to 3 times with exponential backoff on transient DNS/network failures
- **Early abort** — detects persistent network failures (3+ consecutive) and generates the report with data collected so far, rather than failing silently

**Recommendation:** For sessions exceeding 2 hours, run inside `tmux` to survive browser disconnections:

```bash
cd "$HOME/clouddrive"
tmux new -s assessment
pwsh
./Azure-Tenant-Assessment.ps1 -SkipLogin -MaxParallelism 3 -BatchSize 20
```

---

## Execution Time

### Resumable large-tenant execution

After every subscription, the assessment writes an atomic JSON checkpoint and refreshes:

- `Assessment_Partial.html` — progress dashboard refreshed at the configured progress interval
- `Assessment_Partial.json` — current consolidated findings and resources
- `Findings_Partial.csv` — findings collected so far
- `.checkpoint/subscriptions/<subscription-id>.json` — complete per-subscription result
- `.checkpoint/manifest.json` — completed, failed, and pending status
- `.checkpoint/consolidated.json` — final consolidated result after report generation

Parallel mode uses separate PowerShell processes, so each subscription has an isolated Az context and script state. The authenticated context is exported to a temporary file only while workers run and is deleted afterward. Start with `-MaxParallelism 3`; increase to `5` only when Azure API throttling remains low.

| Tenant Size | Estimated Time | With `-SkipMetrics` |
|-------------|----------------|---------------------|
| 1–5 subscriptions | 5–15 minutes | 2–5 minutes |
| 10–20 subscriptions | 15–45 minutes | 5–15 minutes |
| 50+ subscriptions | 1–4 hours | 30–60 minutes |

Metrics collection (`Get-AzMetric`) remains the most time-consuming operation when applicable resources exist. Use `-SkipMetrics` for a faster initial assessment. For the shortest read-only posture run, combine it with `-SkipKeyVaultDataPlane` and `-SkipBackupDetails`; resource-type skips are applied automatically in every mode.

---

## Disclaimer

This project is provided "AS IS", without warranty of any kind.

This script is an independent community project and is not officially supported, endorsed, or maintained by Microsoft.

Use at your own risk. Always validate scripts in a non-production environment before deploying to production systems.

The author assumes no liability for damages, data loss, service interruption, unexpected costs, or other issues resulting from the use of this script.

---

## License

This script is proprietary and confidential. Unauthorized copying, modification, distribution, or reverse engineering is prohibited. See the confidentiality notice in the script header for details.

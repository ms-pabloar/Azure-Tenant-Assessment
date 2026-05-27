# Azure-Tenant-Assessment
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
| **Cost Management Reader** | Each subscription | Optional | 6-month cost trend analysis; gracefully skipped if unavailable |
| **Key Vault Secrets List** | Key Vaults (data-plane) | Optional | Expiring secrets/certificates detection; skip with `-SkipKeyVaultDataPlane` |
| **Management Group Reader** | Tenant Root Group | Optional | ALZ/CAF readiness analysis (MG hierarchy, tenant-level policies) |
| **Microsoft Graph** | Tenant | Optional | Conditional Access and PIM verification; auto-connects if `Microsoft.Graph.Authentication` module is installed |

> **Minimum viable**: A single `Reader` role assignment at the subscription level is sufficient to run the assessment. All optional features degrade gracefully with clear status messages.

---

## Usage

### Azure Cloud Shell (Recommended)

```powershell
# 1. Upload the script to Cloud Shell (drag & drop or use the Upload button)

# 2. Run the assessment (Cloud Shell is already authenticated)
./Azure-Tenant-Assessment.ps1 -SkipLogin

# 3. Download the output folder when complete
```

### Local Machine

```powershell
# 1. Authenticate to Azure
Connect-AzAccount

# 2. Run the assessment
./Azure-Tenant-Assessment.ps1
```

### Common Options

```powershell
# Assess a single subscription
./Azure-Tenant-Assessment.ps1 -SkipLogin -SubscriptionId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Fast mode — skip Azure Monitor metrics collection
./Azure-Tenant-Assessment.ps1 -SkipLogin -SkipMetrics

# Custom output directory
./Azure-Tenant-Assessment.ps1 -SkipLogin -OutputPath "./MyAssessment"

# Customize underutilization thresholds
./Azure-Tenant-Assessment.ps1 -SkipLogin -CpuLowPercent 15 -MetricDays 14

# Custom mandatory tags for compliance analysis
./Azure-Tenant-Assessment.ps1 -SkipLogin -MandatoryTags @('Environment','Owner','CostCenter','Project')
```

### All Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `-SubscriptionId` | string | *(all)* | Analyze a specific subscription only |
| `-SkipLogin` | switch | false | Skip `Connect-AzAccount`; use existing session |
| `-OutputPath` | string | `./AzureAssessment_<timestamp>` | Output directory for all generated files |
| `-SkipMetrics` | switch | false | Skip Azure Monitor metrics collection (faster execution) |
| `-SkipKeyVaultDataPlane` | switch | false | Skip Key Vault secret/certificate enumeration |
| `-SkipBackupDetails` | switch | false | Skip detailed backup item enumeration |
| `-MetricDays` | int | 7 | Metrics analysis window in days (7 or 14) |
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
- Requires `Cost Management Reader` role (optional; gracefully skipped)

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

At startup, the script validates its own digital signature before executing any code:

```
╔══════════════════════════════════════════════════════════════╗
║  SCRIPT INTEGRITY CHECK FAILED                             ║
║  This script has been modified or the signature is missing. ║
║  Execution blocked for security. Contact the author.       ║
╚══════════════════════════════════════════════════════════════╝
```

If the script has been altered in any way — even a single character — execution is blocked immediately.

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

- **Keep-alive heartbeat** — writes to console every 30 seconds to prevent Cloud Shell idle timeout (20 minutes)
- **Token refresh** — automatically refreshes Azure access tokens every 15 minutes to prevent expiration
- **Network retry** — retries subscription context switches up to 3 times with exponential backoff on transient DNS/network failures
- **Early abort** — detects persistent network failures (3+ consecutive) and generates the report with data collected so far, rather than failing silently

**Recommendation:** For sessions exceeding 2 hours, run inside `tmux` to survive browser disconnections:

```bash
tmux new -s assessment
pwsh
./Azure-Tenant-Assessment.ps1 -SkipLogin
```

---

## Execution Time

| Tenant Size | Estimated Time | With `-SkipMetrics` |
|-------------|----------------|---------------------|
| 1–5 subscriptions | 5–15 minutes | 2–5 minutes |
| 10–20 subscriptions | 15–45 minutes | 5–15 minutes |
| 50+ subscriptions | 1–4 hours | 30–60 minutes |

Metrics collection (`Get-AzMetric`) is the most time-consuming operation. Use `-SkipMetrics` for a faster initial assessment, then run with metrics enabled for the full analysis.

---

## Disclaimer

This project is provided "AS IS", without warranty of any kind.
This script is an independent community project and is not officially supported, endorsed, or maintained by Microsoft.
Use at your own risk. Always validate scripts in a non-production environment before deploying to production systems.
The author assumes no liability for damages, data loss, service interruption, unexpected costs, or other issues resulting from the use of this script.

---

## License

This script is proprietary and confidential. Unauthorized copying, modification, distribution, or reverse engineering is prohibited. See the confidentiality notice in the script header for details.


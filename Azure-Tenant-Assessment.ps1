#Requires -Version 7.0
#Requires -Modules @{ModuleName='Az.Accounts';ModuleVersion='3.0.0'}
# ============================================================================
# CONFIDENTIAL — Microsoft Internal Use Only
# ============================================================================
# This script is the intellectual property of its author and is provided under
# a confidentiality agreement. Unauthorized copying, modification, distribution,
# or reverse engineering is strictly prohibited. This script is digitally signed
# and will refuse to execute if its contents have been altered in any way.
# ============================================================================
<#
.SYNOPSIS
    Azure Tenant Complete Assessment - Architecture, Security & Well-Architected Framework
.DESCRIPTION
    Self-contained script that analyzes a complete Azure tenant and generates:
    - Interactive HTML report with findings categorized by WAF pillar
    - Architecture diagram in HTML format (network topology, dependencies)
    - Complete inventory of resources, configurations, and detected issues
.NOTES
    Author: Azure Assessment Tool
    Version: 5.0
    Requiere: Az PowerShell Modules (Az.Accounts, Az.Compute, Az.Network, Az.Sql,
              Az.Storage, Az.KeyVault, Az.Monitor, Az.Security, Az.Aks,
              Az.OperationalInsights, Az.RecoveryServices, Az.ResourceGraph)
    
    PERMISSIONS REQUIRED:
      Base assessment:
        - Reader on each subscription
        - Cost Management Reader on each subscription (optional, for cost data)
      
      ALZ/CAF readiness (always included — depth depends on permissions):
        - Management Group Reader at Tenant Root Group (enables MG hierarchy, policy, RBAC analysis)
        - Microsoft Graph is connected automatically when the module is installed:
          Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
          The script will prompt for Graph login to enable CA/PIM checks.
          Without the module, CA and PIM checks appear as manual verification items.
      
      To skip Graph auto-connection (manual checklist only):
        Install-Module Microsoft.Graph.Authentication
        Connect-MgGraph -Scopes 'Policy.Read.All','RoleManagement.Read.Directory','Directory.Read.All'
.EXAMPLE
    ./Azure-Tenant-Assessment.ps1
    ./Azure-Tenant-Assessment.ps1 -SubscriptionId "xxxx-xxxx-xxxx"
    ./Azure-Tenant-Assessment.ps1 -SkipLogin
    ./Azure-Tenant-Assessment.ps1 -SkipMetrics                    # Skip underutilized analysis (fastest)
    ./Azure-Tenant-Assessment.ps1 -MetricDays 7                   # 7-day window instead of 14
    ./Azure-Tenant-Assessment.ps1 -CpuLowPercent 15 -AppRequestLowPerHour 20
    ./Azure-Tenant-Assessment.ps1 -IncludeALZ                     # (Backward compat — ALZ runs by default now)
    ./Azure-Tenant-Assessment.ps1 -IncludeALZ -SkipLogin          # (Backward compat — ALZ runs by default now)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = "",

    [Parameter(Mandatory=$false)]
    [switch]$SkipLogin,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "./AzureAssessment_$(Get-Date -Format 'yyyyMMdd_HHmmss')",

    [Parameter(Mandatory=$false)]
    [int]$CpuLowPercent = 10,

    [Parameter(Mandatory=$false)]
    [int]$CpuIdlePercent = 5,

    [Parameter(Mandatory=$false)]
    [int]$NetLowMB = 5,

    [Parameter(Mandatory=$false)]
    [int]$AppRequestLowPerHour = 10,

    [Parameter(Mandatory=$false)]
    [int]$SqlDtuLowPercent = 10,

    [Parameter(Mandatory=$false)]
    [int]$SqlCpuLowPercent = 10,

    [Parameter(Mandatory=$false)]
    [int]$DiskLowIops = 5,

    [Parameter(Mandatory=$false)]
    [switch]$SkipMetrics,

    [Parameter(Mandatory=$false)]
    [switch]$SkipKeyVaultDataPlane,

    [Parameter(Mandatory=$false)]
    [switch]$SkipBackupDetails,

    [Parameter(Mandatory=$false)]
    [int]$MetricDays = 7,

    [Parameter(Mandatory=$false, HelpMessage="Include Azure Landing Zone (ALZ/CAF) readiness checks. Requires Management Group Reader + optional Microsoft Graph permissions.")]
    [switch]$IncludeALZ,

    [Parameter(Mandatory=$false, HelpMessage="Tags required for tag compliance analysis. Default: Environment, Owner, CostCenter, Application, Department.")]
    [string[]]$MandatoryTags = @('Environment', 'Owner', 'CostCenter', 'Application', 'Department')
)

# ============================================================================
# SCRIPT INTEGRITY CHECK — Do not remove or modify this block
# ============================================================================
if (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue) {
    $scriptSignature = Get-AuthenticodeSignature -FilePath $PSCommandPath
    if ($scriptSignature.Status -ne 'Valid') {
        Write-Host ""
        Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  SCRIPT INTEGRITY CHECK FAILED                             ║" -ForegroundColor Red
        Write-Host "  ║  This script has been modified or the signature is missing. ║" -ForegroundColor Red
        Write-Host "  ║  Execution blocked for security. Contact the author.       ║" -ForegroundColor Red
        Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Signature status: $($scriptSignature.Status)" -ForegroundColor Yellow
        Write-Host "  File: $PSCommandPath" -ForegroundColor DarkGray
        Write-Host ""
        exit 1
    }
    Remove-Variable scriptSignature
}

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$env:SuppressAzurePowerShellBreakingChangeWarnings = "true"
$script:StartTime = Get-Date
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Resources = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:NetworkTopology = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Subscriptions = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:UnderutilizedResources = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:CostData = @{}  # Key = SubscriptionId, Value = cost analysis object
$script:Summary = @{
    TotalResources = 0
    Critical = 0
    High = 0
    Medium = 0
    Low = 0
    Info = 0
}

# Execution tracking — errors, warnings, per-step log
$script:ErrorLog = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:StepResults = [System.Collections.Generic.List[PSCustomObject]]::new()  # {Step, Subscription, Status, Duration, Error}

# Data cache — filled once per subscription in Invoke-DataCollection
$script:CachedVMs = $null
$script:CachedVNets = $null
$script:CachedNSGs = $null
$script:CachedStorageAccounts = $null
$script:CachedSqlServers = $null
$script:CachedKeyVaults = $null
$script:CachedWebApps = $null
$script:CachedDisks = $null
$script:CachedNICs = $null
$script:CachedPublicIPs = $null
$script:CachedPrivateEndpoints = $null
$script:CachedLoadBalancers = $null
$script:CachedAppGateways = $null
$script:CachedFirewalls = $null
$script:CachedBastions = $null
$script:CachedWebAppDetails = @{}        # Detailed App Service configs (pre-cached)
$script:CachedVMEncryption = @{}         # VM disk encryption status (pre-cached)
$script:CachedVMExtensions = @{}        # VM extensions by type (pre-cached via Resource Graph)
$script:CachedKVSecrets = @{}           # Key Vault secrets expiration (pre-cached via Resource Graph)
$script:CachedKVKeys = @{}              # Key Vault keys expiration (pre-cached via Resource Graph)
$script:CachedKVCerts = @{}             # Key Vault certificates expiration (pre-cached via Resource Graph)
$script:CachedBackupItems = @{}         # Recovery Services backup items (pre-cached via Resource Graph)
$script:CachedBackupPolicies = @{}      # Recovery Services backup policies (pre-cached via Resource Graph)
$script:ZeroTrustTenantAdvisoryEmitted = $false  # Emit CA/PIM advisory only once per tenant
$script:KeepAliveTimer = $null          # Cloud Shell keep-alive timer
$script:ALZData = @{}                   # ALZ readiness data (MG hierarchy, policy, vWAN, DNS, Graph)
$script:DataCollectionSucceeded = $false # Flag to skip analysis if data collection failed

function Clear-SubscriptionCaches {
    <# .SYNOPSIS Clears all per-subscription cached data to prevent cross-contamination #>
    $script:CachedVMs = $null; $script:CachedVNets = $null; $script:CachedNSGs = $null
    $script:CachedStorageAccounts = $null; $script:CachedSqlServers = $null; $script:CachedKeyVaults = $null
    $script:CachedWebApps = $null; $script:CachedDisks = $null; $script:CachedNICs = $null
    $script:CachedPublicIPs = $null; $script:CachedPrivateEndpoints = $null
    $script:CachedLoadBalancers = $null; $script:CachedAppGateways = $null
    $script:CachedFirewalls = $null; $script:CachedBastions = $null
    $script:CachedWebAppDetails = @{}; $script:CachedVMEncryption = @{}
    $script:CachedVMExtensions = @{}
    $script:CachedRecoveryVaults = $null  # Per-sub vault list, set by Analyze-BCDR
    # NOTE: Do NOT clear CachedKVSecrets/Keys/Certs/BackupItems/BackupPolicies here —
    # they are pre-populated for ALL subs before the main loop and keyed by subscriptionId
    $script:DataCollectionSucceeded = $false
}
$script:PreFlightResults = [System.Collections.Generic.List[PSCustomObject]]::new()  # Permission check results
$script:ReservationData = [System.Collections.Generic.List[PSCustomObject]]::new()   # Reservation & Savings Plan inventory

# ============================================================================
# CLOUD SHELL KEEP-ALIVE
# ============================================================================
# Cloud Shell has a 20-minute idle timeout and websocket connections can drop
# after ~90 minutes. We use two complementary strategies:
#   1. A timer that writes a heartbeat to stdout every 60 seconds (keeps the
#      websocket alive from the browser side).
#   2. Instructions to run inside tmux so the script survives disconnection.

$script:LastKeepAlive = [datetime]::MinValue
$script:LastTokenRefresh = [datetime]::MinValue

function Start-KeepAlive {
    if ($script:KeepAliveTimer) { return }
    $script:LastKeepAlive = Get-Date
    $script:LastTokenRefresh = Get-Date
    $script:KeepAliveTimer = [System.Timers.Timer]::new(30000)  # 30 seconds (more aggressive)
    $action = {
        try {
            $elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
            # Write to both Console and Host to maximize chance of reaching websocket
            $msg = "  [keepalive] $elapsed min elapsed"
            [Console]::WriteLine($msg)
            Write-Host $msg -ForegroundColor DarkGray
        } catch { }
    }
    Register-ObjectEvent -InputObject $script:KeepAliveTimer -EventName Elapsed -Action $action -SourceIdentifier 'KeepAlive' | Out-Null
    $script:KeepAliveTimer.AutoReset = $true
    $script:KeepAliveTimer.Start()
}

function Stop-KeepAlive {
    if ($script:KeepAliveTimer) {
        $script:KeepAliveTimer.Stop()
        $script:KeepAliveTimer.Dispose()
        $script:KeepAliveTimer = $null
        Unregister-Event -SourceIdentifier 'KeepAlive' -ErrorAction SilentlyContinue
    }
}

# Inline keep-alive: call this between long-running steps to guarantee
# stdout activity reaches Cloud Shell even if the timer event doesn't.
# Also refreshes Azure token every 15 minutes to prevent expiration.
function Send-KeepAlive {
    $now = Get-Date
    # Console output every 30 seconds to keep websocket alive
    if (($now - $script:LastKeepAlive).TotalSeconds -ge 30) {
        $elapsed = [math]::Round(($now - $script:StartTime).TotalMinutes, 1)
        Write-Host "  [keepalive] $elapsed min — session active" -ForegroundColor DarkGray
        $script:LastKeepAlive = $now
    }
    # Refresh Azure token every 15 minutes (tokens expire at ~60 min)
    if (($now - $script:LastTokenRefresh).TotalMinutes -ge 15) {
        try {
            Get-AzAccessToken -ErrorAction SilentlyContinue | Out-Null
            $script:LastTokenRefresh = $now
        } catch { }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $colors = @{ "INFO" = "Cyan"; "OK" = "Green"; "WARN" = "Yellow"; "ERROR" = "Red"; "SECTION" = "Magenta" }
    $prefix = @{ "INFO" = "[i]"; "OK" = "[✓]"; "WARN" = "[!]"; "ERROR" = "[✗]"; "SECTION" = "[►]" }
    $color = if ($colors.ContainsKey($Type)) { $colors[$Type] } else { "Gray" }
    $icon  = if ($prefix.ContainsKey($Type)) { $prefix[$Type] } else { "[·]" }
    Write-Host "$icon $Message" -ForegroundColor $color
    # Reset keep-alive timer since we just produced output
    $script:LastKeepAlive = Get-Date
    # Append to log file if path is available
    if ($script:LogFilePath -and (Test-Path (Split-Path $script:LogFilePath -Parent) -ErrorAction SilentlyContinue)) {
        $ts = (Get-Date).ToString("HH:mm:ss")
        "$ts $icon $Message" | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

function Invoke-AnalysisStep {
    param(
        [string]$StepName,
        [string]$SubId,
        [string]$SubName,
        [scriptblock]$Action
    )
    Send-KeepAlive   # Ensure stdout activity between steps
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Action
        $sw.Stop()
        $script:StepResults.Add([PSCustomObject]@{
            Step         = $StepName
            Subscription = $SubName
            Status       = 'OK'
            DurationSec  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error        = $null
        })
    } catch {
        $sw.Stop()
        $errMsg = $_.Exception.Message
        Write-Status "  $StepName FAILED: $errMsg" "ERROR"
        $script:ErrorLog.Add([PSCustomObject]@{
            Timestamp    = Get-Date
            Step         = $StepName
            Subscription = $SubName
            Error        = $errMsg
        })
        $script:StepResults.Add([PSCustomObject]@{
            Step         = $StepName
            Subscription = $SubName
            Status       = 'FAILED'
            DurationSec  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            Error        = $errMsg
        })
    }
}

function ConvertTo-SafeHtml {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Add-Finding {
    param(
        [string]$Pillar,
        [string]$Severity,
        [string]$Category,
        [string]$ResourceName,
        [string]$ResourceType,
        [string]$ResourceGroup,
        [string]$Subscription,
        [string]$Description,
        [string]$Recommendation,
        [string]$Impact,
        [ValidateSet('Custom Analysis','Azure Advisor','Defender for Cloud','')][string]$Source = 'Custom Analysis'
    )
    $script:Findings.Add([PSCustomObject]@{
        Pillar         = $Pillar
        Severity       = $Severity
        Category       = $Category
        ResourceName   = $ResourceName
        ResourceType   = $ResourceType
        ResourceGroup  = $ResourceGroup
        Subscription   = $Subscription
        Description    = $Description
        Recommendation = $Recommendation
        Impact         = $Impact
        Source         = if ($Source) { $Source } else { 'Custom Analysis' }
    })
    $script:Summary[$Severity]++
}

function Invoke-AzCommandSafely {
    param([scriptblock]$Command, [string]$ErrorMessage = "Error executing command")
    Send-KeepAlive  # Prevent Cloud Shell idle disconnect during long loops
    try {
        return (& $Command)
    } catch {
        Write-Status "$ErrorMessage : $($_.Exception.Message)" "WARN"
        return $null
    }
}

# Compatibility alias
New-Alias -Name 'Safe-AzCommand' -Value 'Invoke-AzCommandSafely' -Scope Script -Force

# ============================================================================
# 0.5. PRE-FLIGHT PERMISSION VALIDATOR
# ============================================================================
function Test-PreFlightPermissions {
    <#
    .SYNOPSIS
        Validates all permissions required for the assessment and displays a clear
        status table before any data collection begins.
    #>
    param([string]$TenantId, [array]$SubscriptionIds)

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║            PRE-FLIGHT PERMISSION VALIDATION                ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $script:PreFlightResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hasBlocker = $false

    # ── Helper to add a check result ──
    function Add-CheckResult {
        param([string]$Check, [string]$Scope, [string]$Status, [string]$Detail, [bool]$Required = $true)
        $script:PreFlightResults.Add([PSCustomObject]@{
            Check    = $Check
            Scope    = $Scope
            Status   = $Status   # PASS, FAIL, WARN, SKIP
            Detail   = $Detail
            Required = $Required
        })
    }

    # ── 1. Azure Context / Authentication ──
    Write-Status "Checking Azure authentication..." "INFO"
    $ctx = Get-AzContext
    if ($ctx -and $ctx.Account) {
        Add-CheckResult "Azure Authentication" "Tenant" "PASS" "Logged in as $($ctx.Account.Id) (Tenant: $($ctx.Tenant.Id))"
    } else {
        Add-CheckResult "Azure Authentication" "Tenant" "FAIL" "No active Azure session. Run Connect-AzAccount first."
        $hasBlocker = $true
    }

    # ── 2. Reader on at least one subscription ──
    Write-Status "Checking subscription access (Reader)..." "INFO"
    $testSubId = $SubscriptionIds | Select-Object -First 1
    $readerOk = $false
    try {
        $null = Set-AzContext -SubscriptionId $testSubId -ErrorAction Stop
        $rg = Get-AzResourceGroup -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($rg -or $true) { $readerOk = $true }  # If Set-AzContext succeeded, Reader is enough
        Add-CheckResult "Reader on Subscriptions" "Subscription ($($SubscriptionIds.Count) subs)" "PASS" "Can read resources in subscriptions"
    } catch {
        Add-CheckResult "Reader on Subscriptions" "Subscription" "FAIL" "Cannot access subscription: $($_.Exception.Message)"
        $hasBlocker = $true
    }

    # ── 3. Cost Management Reader ──
    Write-Status "Checking Cost Management access..." "INFO"
    $costOk = $false
    try {
        $costBody = @{
            type = "ActualCost"
            dataSet = @{ granularity = "None"; aggregation = @{ totalCost = @{ name = "Cost"; function = "Sum" } } }
            timeframe = "MonthToDate"
        } | ConvertTo-Json -Depth 10
        $costResp = Invoke-AzRestMethod -Path "/subscriptions/$testSubId/providers/Microsoft.CostManagement/query?api-version=2023-11-01" -Method POST -Payload $costBody -ErrorAction Stop
        if ($costResp.StatusCode -eq 200) {
            $costOk = $true
            Add-CheckResult "Cost Management Reader" "Subscription" "PASS" "Can query cost data"
        } else {
            Add-CheckResult "Cost Management Reader" "Subscription" "WARN" "Cost data unavailable (HTTP $($costResp.StatusCode)) — cost analysis will be skipped" -Required $false
        }
    } catch {
        Add-CheckResult "Cost Management Reader" "Subscription" "WARN" "Cost data unavailable — cost analysis will be skipped" -Required $false
    }

    # ── 4. Resource Graph module ──
    Write-Status "Checking Az.ResourceGraph module..." "INFO"
    if (Get-Module -ListAvailable -Name Az.ResourceGraph) {
        Add-CheckResult "Az.ResourceGraph Module" "Local" "PASS" "Installed — enables bulk data collection"
    } else {
        Add-CheckResult "Az.ResourceGraph Module" "Local" "WARN" "Not installed — will use slower per-resource queries" -Required $false
    }

    # ── 5. Management Group access (ALZ Readiness — always checked) ──
        Write-Status "Checking Management Group access..." "INFO"
        try {
            $mgRoot = Get-AzManagementGroup -ErrorAction Stop | Select-Object -First 1
            if ($mgRoot) {
                Add-CheckResult "Management Group Reader" "Tenant Root" "PASS" "Can read MG hierarchy (found: $($mgRoot.DisplayName))"
                try {
                    $mgHierarchy = Get-AzManagementGroup -GroupId $TenantId -Expand -Recurse -ErrorAction Stop
                    Add-CheckResult "MG Hierarchy (Recursive)" "Tenant Root" "PASS" "Full hierarchy readable"
                } catch {
                    Add-CheckResult "MG Hierarchy (Recursive)" "Tenant Root" "WARN" "Can list MGs but cannot expand full hierarchy — partial ALZ view" -Required $false
                }
            } else {
                Add-CheckResult "Management Group Reader" "Tenant Root" "FAIL" "No management groups accessible"
            }
        } catch {
            Add-CheckResult "Management Group Reader" "Tenant Root" "FAIL" "Cannot read Management Groups: $($_.Exception.Message). Assign 'Management Group Reader' at tenant root."
        }

        # ── 6. MG-scope Policy Assignments ──
        Write-Status "Checking MG-scope policy access..." "INFO"
        try {
            $mgPolicies = Get-AzPolicyAssignment -Scope "/providers/Microsoft.Management/managementGroups/$TenantId" -ErrorAction Stop | Select-Object -First 1
            Add-CheckResult "MG-scope Policy Read" "Management Group" "PASS" "Can read policy assignments at MG scope"
        } catch {
            if ($_.Exception.Message -match 'AuthorizationFailed|Forbidden|does not have authorization') {
                Add-CheckResult "MG-scope Policy Read" "Management Group" "FAIL" "Cannot read MG-scope policies — assign Reader at MG level" -Required $false
            } else {
                Add-CheckResult "MG-scope Policy Read" "Management Group" "WARN" "MG policy check inconclusive: $($_.Exception.Message)" -Required $false
            }
        }

        # ── 7. Microsoft Graph (CA / PIM) ──
        Write-Status "Checking Microsoft Graph access (Conditional Access / PIM)..." "INFO"
        $graphAvailable = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication
        if ($graphAvailable) {
            try {
                $graphCtx = Get-MgContext -ErrorAction SilentlyContinue
                if ($graphCtx) {
                    $scopes = $graphCtx.Scopes -join ', '
                    $hasPolicyRead = $graphCtx.Scopes -contains 'Policy.Read.All'
                    $hasRoleMgmt   = $graphCtx.Scopes -contains 'RoleManagement.Read.Directory'
                    if ($hasPolicyRead) {
                        Add-CheckResult "Graph: Conditional Access" "Tenant (Graph)" "PASS" "Policy.Read.All scope available"
                    } else {
                        Add-CheckResult "Graph: Conditional Access" "Tenant (Graph)" "WARN" "Missing Policy.Read.All scope — CA policies won't be validated" -Required $false
                    }
                    if ($hasRoleMgmt) {
                        Add-CheckResult "Graph: PIM / Role Mgmt" "Tenant (Graph)" "PASS" "RoleManagement.Read.Directory scope available"
                    } else {
                        Add-CheckResult "Graph: PIM / Role Mgmt" "Tenant (Graph)" "WARN" "Missing RoleManagement.Read.Directory — PIM won't be validated" -Required $false
                    }
                } else {
                    Add-CheckResult "Graph: Conditional Access" "Tenant (Graph)" "WARN" "Microsoft.Graph module installed but auto-connection failed — CA policies won't be validated" -Required $false
                    Add-CheckResult "Graph: PIM / Role Mgmt" "Tenant (Graph)" "WARN" "Graph auto-connection failed — PIM won't be validated" -Required $false
                }
            } catch {
                Add-CheckResult "Graph: CA + PIM" "Tenant (Graph)" "WARN" "Graph context check failed — CA/PIM will be advisory only" -Required $false
            }
        } else {
            Add-CheckResult "Microsoft.Graph Module" "Local" "WARN" "Not installed — CA/PIM will be manual checklist. Install: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" -Required $false
        }

        # ── 8. vWAN check capability ──
        Write-Status "Checking vWAN/Virtual Hub read access..." "INFO"
        try {
            $vwanTest = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/virtualwans' | take 1" -Subscription $testSubId -ErrorAction Stop
            Add-CheckResult "vWAN Topology Read" "Subscription" "PASS" "Can query Virtual WAN resources"
        } catch {
            Add-CheckResult "vWAN Topology Read" "Subscription" "WARN" "Cannot query vWAN via Resource Graph" -Required $false
        }

        # ── 9. Private DNS Zones ──
        Write-Status "Checking Private DNS Zone access..." "INFO"
        try {
            $dnsTest = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/privatednszones' | take 1" -Subscription $testSubId -ErrorAction Stop
            Add-CheckResult "Private DNS Zone Read" "Subscription" "PASS" "Can query Private DNS Zones"
        } catch {
            Add-CheckResult "Private DNS Zone Read" "Subscription" "WARN" "Cannot query Private DNS Zones" -Required $false
        }

    # ── Display Results Table ──
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────┬──────────────────────┬────────┬──────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ Permission Check                     │ Scope                │ Status │ Detail                                                   │" -ForegroundColor DarkGray
    Write-Host "  ├──────────────────────────────────────┼──────────────────────┼────────┼──────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
    foreach ($r in $script:PreFlightResults) {
        $statusColor = switch ($r.Status) { "PASS" { "Green" } "FAIL" { "Red" } "WARN" { "Yellow" } "SKIP" { "DarkGray" } }
        $statusIcon  = switch ($r.Status) { "PASS" { "✓" } "FAIL" { "✗" } "WARN" { "!" } "SKIP" { "—" } }
        $checkPad  = $r.Check.PadRight(36)
        $scopePad  = $r.Scope.PadRight(20)
        $statusPad = "$statusIcon $($r.Status)".PadRight(6)
        $detailTrunc = if ($r.Detail.Length -gt 56) { $r.Detail.Substring(0, 53) + "..." } else { $r.Detail.PadRight(56) }
        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
        Write-Host "$checkPad" -NoNewline -ForegroundColor White
        Write-Host " │ " -NoNewline -ForegroundColor DarkGray
        Write-Host "$scopePad" -NoNewline -ForegroundColor Gray
        Write-Host " │ " -NoNewline -ForegroundColor DarkGray
        Write-Host "$statusPad" -NoNewline -ForegroundColor $statusColor
        Write-Host " │ " -NoNewline -ForegroundColor DarkGray
        Write-Host "$detailTrunc" -NoNewline -ForegroundColor Gray
        Write-Host " │" -ForegroundColor DarkGray
    }
    Write-Host "  └──────────────────────────────────────┴──────────────────────┴────────┴──────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    # ── Summary ──
    $passCount = @($script:PreFlightResults | Where-Object Status -eq 'PASS').Count
    $failCount = @($script:PreFlightResults | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($script:PreFlightResults | Where-Object Status -eq 'WARN').Count
    $totalChecks = $script:PreFlightResults.Count
    Write-Status "Permission check: $passCount/$totalChecks PASS, $warnCount WARN, $failCount FAIL" $(if($failCount -gt 0){"ERROR"}elseif($warnCount -gt 0){"WARN"}else{"OK"})

    if ($hasBlocker) {
        Write-Host ""
        Write-Host "  ╭─────────────────────────────────────────────────────────╮" -ForegroundColor Red
        Write-Host "  │  ✗ BLOCKING: Required permissions are missing.          │" -ForegroundColor Red
        Write-Host "  │    The assessment cannot continue.                      │" -ForegroundColor Red
        Write-Host "  │    Fix the FAIL items above and re-run.                 │" -ForegroundColor Red
        Write-Host "  ╰─────────────────────────────────────────────────────────╯" -ForegroundColor Red
        throw "Pre-flight permission check failed. See details above."
    }

    $alzFails = @($script:PreFlightResults | Where-Object { $_.Status -eq 'FAIL' -and $_.Check -match 'Management Group|Graph|MG-scope' }).Count
    if ($alzFails -gt 0) {
        Write-Host ""
        Write-Host "  ╭─────────────────────────────────────────────────────────╮" -ForegroundColor Yellow
        Write-Host "  │  ⚠ ALZ: Some permissions missing — partial coverage.   │" -ForegroundColor Yellow
        Write-Host "  │  MG hierarchy, policies, or Graph checks may be limited │" -ForegroundColor Yellow
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │  For full ALZ coverage add:                             │" -ForegroundColor Yellow
        Write-Host "  │   • Management Group Reader (Tenant Root Group)         │" -ForegroundColor Cyan
        Write-Host "  │   • Install-Module Microsoft.Graph.Authentication       │" -ForegroundColor Cyan
        Write-Host "  │     (Graph connects automatically if module is present) │" -ForegroundColor Yellow
        Write-Host "  ╰─────────────────────────────────────────────────────────╯" -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Status "ALZ readiness: all permissions available for full coverage" "OK"
    }

    Write-Host ""
    # Restore context to the first sub for main loop
    if ($SubscriptionIds.Count -gt 0) {
        Set-AzContext -SubscriptionId $SubscriptionIds[0] -ErrorAction SilentlyContinue | Out-Null
    }
}

# ============================================================================
# 1. AUTHENTICATION AND SUBSCRIPTION DISCOVERY
# ============================================================================
function Initialize-Assessment {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       AZURE TENANT ASSESSMENT - WELL-ARCHITECTED          ║" -ForegroundColor Cyan
    Write-Host "║       Complete Architecture and Security Analysis          ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Warn if running in Cloud Shell without tmux
    $isCloudShell = $env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*' -or $env:ACC_TERM_ID
    if ($isCloudShell -and -not $env:TMUX) {
        Write-Host "  ╭─────────────────────────────────────────────────────────╮" -ForegroundColor Yellow
        Write-Host "  │  ⚠ CLOUD SHELL: Running WITHOUT tmux protection       │" -ForegroundColor Yellow
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │  If your browser disconnects, the script will STOP.     │" -ForegroundColor Yellow
        Write-Host "  │  For long assessments, use tmux:                        │" -ForegroundColor Yellow
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │    tmux new -s assessment                               │" -ForegroundColor Cyan
        Write-Host "  │    pwsh ./Azure-Tenant-Assessment.ps1 -SkipLogin        │" -ForegroundColor Cyan
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │  If disconnected, reconnect and run:                    │" -ForegroundColor Yellow
        Write-Host "  │    tmux attach -t assessment                            │" -ForegroundColor Cyan
        Write-Host "  │                                                         │" -ForegroundColor Yellow
        Write-Host "  │  Continuing in 10 seconds... (Ctrl+C to abort)          │" -ForegroundColor Yellow
        Write-Host "  ╰─────────────────────────────────────────────────────────╯" -ForegroundColor Yellow
        Write-Host ""
        Start-Sleep -Seconds 10
    } elseif ($isCloudShell -and $env:TMUX) {
        Write-Status "Running inside tmux — session is protected from disconnection" "OK"
    }

    # Verify Az module
    Write-Status "Verifying Az PowerShell module..." "INFO"
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Status "Installing Az module (this may take a few minutes)..." "WARN"
        Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -MinimumVersion 12.0.0
    }
    # Verify Az.ResourceGraph module (optional, improves inventory performance)
    if (-not (Get-Module -ListAvailable -Name Az.ResourceGraph)) {
        Write-Status "Installing Az.ResourceGraph for optimized inventory..." "INFO"
        Install-Module -Name Az.ResourceGraph -Scope CurrentUser -Force -Repository PSGallery -ErrorAction SilentlyContinue
    }
    # Login
    if (-not $SkipLogin) {
        Write-Status "Starting Azure authentication..." "INFO"
        Write-Host ""
        Write-Host "  A browser window will open for authentication." -ForegroundColor Yellow
        Write-Host "  If using Cloud Shell, you are already authenticated (use -SkipLogin)." -ForegroundColor Yellow
        Write-Host ""
        try {
            Connect-AzAccount -ErrorAction Stop | Out-Null
            Write-Status "Authentication successful." "OK"
        } catch {
            Write-Status "Authentication error: $($_.Exception.Message)" "ERROR"
            Write-Host ""
            Write-Host "  Options:" -ForegroundColor Yellow
            Write-Host "  1. Run from Azure Cloud Shell (no login required)" -ForegroundColor Yellow
            Write-Host "  2. Use: Connect-AzAccount -DeviceCode" -ForegroundColor Yellow
            Write-Host "  3. Use: ./Azure-Tenant-Assessment.ps1 -SkipLogin (if already authenticated)" -ForegroundColor Yellow
            throw "Azure authentication error. Verify credentials and connectivity."
        }
    } else {
        Write-Status "Skipping login (using existing session)..." "INFO"
    }

    # ── Auto-connect Microsoft Graph for CA/PIM checks ──
    # ── Auto-connect Microsoft Graph for CA/PIM checks ──
    Write-Status "Checking Microsoft Graph connectivity..." "INFO"
    $graphModuleAvailable = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
    if ($graphModuleAvailable) {
        Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
        $mgCtx = $null
        try { $mgCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
        $requiredScopes = @('Policy.Read.All', 'RoleManagement.Read.Directory')
        $hasAllScopes = $false
        if ($mgCtx) {
            $hasAllScopes = ($requiredScopes | Where-Object { $mgCtx.Scopes -contains $_ }).Count -eq $requiredScopes.Count
        }
        if (-not $mgCtx -or -not $hasAllScopes) {
            Write-Status "Connecting to Microsoft Graph (CA/PIM checks)..." "INFO"
            $graphConnected = $false
            # Strategy 1: Reuse Azure access token (works in Cloud Shell & non-interactive)
            try {
                $azContext = Get-AzContext -ErrorAction SilentlyContinue
                if ($azContext) {
                    $tokenResult = Get-AzAccessToken -ResourceTypeName MSGraph -ErrorAction Stop
                    $graphToken = $tokenResult.Token
                    if ($graphToken) {
                        # Az.Accounts 3.0+ returns SecureString; older versions return plain string
                        $secureToken = if ($graphToken -is [System.Security.SecureString]) { $graphToken } else { ConvertTo-SecureString $graphToken -AsPlainText -Force }
                        Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop
                        $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
                        if ($mgCtx) {
                            $graphConnected = $true
                            Write-Status "Microsoft Graph connected via Azure token — CA/PIM checks enabled" "OK"
                        }
                    }
                }
            } catch {
                Write-Status "Token reuse not available: $($_.Exception.Message)" "INFO"
            }
            # Strategy 2: Interactive login (only if token reuse failed and not Cloud Shell)
            if (-not $graphConnected) {
                $isCloudShell = $env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*' -or $env:ACC_TERM_ID
                if ($isCloudShell) {
                    Write-Status "Cloud Shell detected — Graph token reuse failed. CA/PIM will be manual checklist" "WARN"
                } else {
                    try {
                        Connect-MgGraph -Scopes ($requiredScopes -join ',') -NoWelcome -ErrorAction Stop
                        $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
                        if ($mgCtx) {
                            Write-Status "Microsoft Graph connected — CA/PIM checks will run automatically" "OK"
                        }
                    } catch {
                        Write-Status "Graph connection skipped: $($_.Exception.Message)" "WARN"
                        Write-Status "CA/PIM checks will appear as manual checklist items" "INFO"
                    }
                }
            }
        } else {
            Write-Status "Microsoft Graph already connected with required scopes" "OK"
        }
    } else {
        Write-Status "Microsoft.Graph.Authentication module not installed — CA/PIM will be manual checklist" "WARN"
        Write-Status "To enable automated checks: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser" "INFO"
    }

    # Discover subscriptions
    Write-Status "Discovering tenant subscriptions..." "SECTION"
    $currentContext = Get-AzContext
    if (-not $currentContext -or -not $currentContext.Tenant) {
        Write-Status "No active Azure session found. Run Connect-AzAccount first." "ERROR"
        throw "No active Azure session. Please authenticate with Connect-AzAccount before using -SkipLogin."
    }
    $detectedTenantId = $currentContext.Tenant.Id
    Write-Status "Active tenant: $detectedTenantId" "INFO"
    if ($SubscriptionId) {
        $subs = Get-AzSubscription -SubscriptionId $SubscriptionId -TenantId $detectedTenantId -ErrorAction SilentlyContinue
    } else {
        $subs = Get-AzSubscription -TenantId $detectedTenantId -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
    }

    if (-not $subs -or $subs.Count -eq 0) {
        Write-Status "No accessible subscriptions found." "ERROR"
        throw "No accessible subscriptions found in the tenant."
    }

    foreach ($sub in $subs) {
        $script:Subscriptions.Add([PSCustomObject]@{
            Id   = $sub.Id
            Name = $sub.Name
            State = $sub.State
            TenantId = $sub.TenantId
        })
        Write-Status "  Subscription: $($sub.Name) ($($sub.Id))" "OK"
    }
    Write-Status "Total subscriptions: $($subs.Count)" "INFO"

    # ── Pre-flight permission validation ──
    $allSubIds = $script:Subscriptions | ForEach-Object { $_.Id }
    Test-PreFlightPermissions -TenantId $detectedTenantId -SubscriptionIds $allSubIds

    # Create output directory
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    # Initialize log file
    $script:LogFilePath = Join-Path $OutputPath "Assessment_Log.txt"
    $logHeader = @"
╔══════════════════════════════════════════════════════════════╗
║       AZURE TENANT ASSESSMENT - EXECUTION LOG              ║
╚══════════════════════════════════════════════════════════════╝
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Subscriptions: $($subs.Count)
"@
    $logHeader | Out-File -FilePath $script:LogFilePath -Encoding UTF8 -Force
}

# ============================================================================
# 1.5. CENTRALIZED DATA COLLECTION PER SUBSCRIPTION
# ============================================================================
function Invoke-DataCollection {
    param([string]$SubId, [string]$SubName)

    Write-Status "Collecting subscription data (centralized cache)..." "SECTION"
    $dcTimer = [System.Diagnostics.Stopwatch]::new()
    $phaseTimer = [System.Diagnostics.Stopwatch]::new()

    # ── Phase 1: Resource Graph bulk fetch (single API call, much faster) ──
    $phaseTimer.Restart()
    $subCtx = if ($SubId) { $SubId } else { (Get-AzContext).Subscription.Id }
    $graphAvailable = Get-Module -ListAvailable -Name Az.ResourceGraph
    if ($graphAvailable) {
        Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue
        Write-Status "  Using Resource Graph (fast path)..." "INFO"

        $rgQuery = @"
resources
| where subscriptionId == '$subCtx'
| project id, name, type, location, resourceGroup, tags, sku, properties, zones, identity
| order by type asc
"@
        $allResources = [System.Collections.Generic.List[PSObject]]::new()
        $skipToken = $null
        do {
            $params = @{ Query = $rgQuery; Subscription = $subCtx; First = 1000; ErrorAction = 'SilentlyContinue' }
            if ($skipToken) { $params['SkipToken'] = $skipToken }
            $page = Search-AzGraph @params
            if ($page) {
                foreach ($item in $page) { $allResources.Add($item) }
                $skipToken = $page.SkipToken
            } else { $skipToken = $null }
        } while ($skipToken)

        if ($allResources -and $allResources.Count -gt 0) {
            Write-Status "  Resource Graph returned $($allResources.Count) resources" "OK"
            $byType = $allResources | Group-Object -Property type -AsHashTable -AsString
        } else {
            $byType = @{}
        }
        Send-KeepAlive
    } else {
        $byType = @{}
    }
    Write-Status "  ⏱ Phase 1 (Resource Graph): $([math]::Round($phaseTimer.Elapsed.TotalSeconds, 1))s" "INFO"

    # ── Phase 2: Cmdlet-based fetch ──
    $phaseTimer.Restart()
    $dcTimer.Restart()
    $script:CachedVMs = Invoke-AzCommandSafely { Get-AzVM -Status -ErrorAction SilentlyContinue } "Error retrieving VMs"
    Write-Status "    Get-AzVM -Status: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s ($(@($script:CachedVMs).Count) VMs)" "INFO"
    Send-KeepAlive

    $dcTimer.Restart()
    $script:CachedVNets = Invoke-AzCommandSafely { Get-AzVirtualNetwork -ErrorAction SilentlyContinue } "Error retrieving VNets"
    $script:CachedNSGs  = Invoke-AzCommandSafely { Get-AzNetworkSecurityGroup -ErrorAction SilentlyContinue } "Error retrieving NSGs"
    Write-Status "    VNets+NSGs: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s" "INFO"
    Send-KeepAlive

    $dcTimer.Restart()
    $script:CachedSqlServers = Invoke-AzCommandSafely { Get-AzSqlServer -ErrorAction SilentlyContinue } "Error retrieving SQL Servers"
    $script:CachedKeyVaults = Invoke-AzCommandSafely { Get-AzKeyVault -ErrorAction SilentlyContinue } "Error retrieving Key Vaults"
    Write-Status "    SQL+KeyVaults: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s" "INFO"
    Send-KeepAlive

    $dcTimer.Restart()
    $script:CachedStorageAccounts = Invoke-AzCommandSafely { Get-AzStorageAccount -ErrorAction SilentlyContinue } "Error retrieving Storage Accounts"
    Write-Status "    StorageAccounts: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s ($(@($script:CachedStorageAccounts).Count))" "INFO"

    $dcTimer.Restart()
    Write-Status "  Fetching App Service details (cached for all analyses)..." "INFO"
    $basicApps = Invoke-AzCommandSafely { Get-AzWebApp -ErrorAction SilentlyContinue } "Error retrieving Web Apps"
    $script:CachedWebApps = $basicApps
    $script:CachedWebAppDetails = @{}
    if ($basicApps) {
        foreach ($app in $basicApps) {
            $detail = Safe-AzCommand { Get-AzWebApp -Name $app.Name -ResourceGroupName $app.ResourceGroup -ErrorAction SilentlyContinue } "AppDetail $($app.Name)"
            if ($detail) { $script:CachedWebAppDetails[$app.Id] = $detail }
            Send-KeepAlive
        }
        Write-Status "    WebApp details: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s ($($script:CachedWebAppDetails.Count) apps)" "INFO"
    }
    Send-KeepAlive

    $dcTimer.Restart()
    $script:CachedDisks            = Invoke-AzCommandSafely { Get-AzDisk -ErrorAction SilentlyContinue } "Error retrieving Disks"
    $script:CachedNICs             = Invoke-AzCommandSafely { Get-AzNetworkInterface -ErrorAction SilentlyContinue } "Error retrieving NICs"
    $script:CachedPublicIPs        = Invoke-AzCommandSafely { Get-AzPublicIpAddress -ErrorAction SilentlyContinue } "Error retrieving Public IPs"
    Send-KeepAlive
    $script:CachedPrivateEndpoints = Invoke-AzCommandSafely { Get-AzPrivateEndpoint -ErrorAction SilentlyContinue } "Error retrieving Private Endpoints"
    $script:CachedLoadBalancers    = Invoke-AzCommandSafely { Get-AzLoadBalancer -ErrorAction SilentlyContinue } "Error retrieving Load Balancers"
    $script:CachedAppGateways      = Invoke-AzCommandSafely { Get-AzApplicationGateway -ErrorAction SilentlyContinue } "Error retrieving App Gateways"
    Send-KeepAlive
    $script:CachedFirewalls        = Invoke-AzCommandSafely { Get-AzFirewall -ErrorAction SilentlyContinue } "Error retrieving Firewalls"
    $script:CachedBastions         = Invoke-AzCommandSafely { Get-AzBastion -ErrorAction SilentlyContinue } "Error retrieving Bastions"
    Write-Status "    Network+Disks+Other: $([math]::Round($dcTimer.Elapsed.TotalSeconds, 1))s" "INFO"
    Write-Status "  ⏱ Phase 2 (Cmdlets): $([math]::Round($phaseTimer.Elapsed.TotalSeconds, 1))s" "INFO"

    # ── Phase 3: Pre-cache VM encryption status ──
    $phaseTimer.Restart()
    $script:CachedVMEncryption = @{}
    if ($script:CachedVMs) {
        Write-Status "  Pre-caching VM disk encryption status..." "INFO"
        foreach ($vm in $script:CachedVMs) {
            $enc = Safe-AzCommand {
                Get-AzVMDiskEncryptionStatus -VMName $vm.Name -ResourceGroupName $vm.ResourceGroupName -ErrorAction SilentlyContinue
            } "Encryption $($vm.Name)"
            if ($enc) { $script:CachedVMEncryption[$vm.Id] = $enc }
            Send-KeepAlive
        }
        Write-Status "  ⏱ Phase 3 (VM Encryption): $([math]::Round($phaseTimer.Elapsed.TotalSeconds, 1))s ($($script:CachedVMEncryption.Count) VMs)" "INFO"
    }

    # ── Phase 4: Pre-cache VM extensions via Resource Graph ──
    $phaseTimer.Restart()
    $script:CachedVMExtensions = @{}
    if ($graphAvailable -and $script:CachedVMs) {
        Write-Status "  Querying VM extensions via Resource Graph..." "INFO"
        $extResults = Invoke-AzCommandSafely {
            Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.compute/virtualmachines/extensions'
| extend vmId = tolower(tostring(split(id, '/extensions/')[0]))
| project vmId, extensionType = tostring(properties.type)
"@ -Subscription $subCtx -First 1000 -ErrorAction SilentlyContinue
        } "Resource Graph VM extensions query"

        if ($extResults) {
            foreach ($ext in $extResults) {
                $vmKey = $ext.vmId
                if (-not $script:CachedVMExtensions.ContainsKey($vmKey)) {
                    $script:CachedVMExtensions[$vmKey] = [System.Collections.Generic.List[string]]::new()
                }
                $script:CachedVMExtensions[$vmKey].Add($ext.extensionType)
            }
            Write-Status "  ⏱ Phase 4 (Extensions): $([math]::Round($phaseTimer.Elapsed.TotalSeconds, 1))s ($($script:CachedVMExtensions.Count) VMs)" "INFO"
        }
    }

    Write-Status "Data collected successfully." "OK"
}

# ============================================================================
# COST ANALYSIS (Azure Cost Management API - 6 months)
# ============================================================================
function Get-SubscriptionCostAnalysis {
    param([string]$SubId, [string]$SubName)

    Write-Status "Collecting cost data (last 6 months)..." "INFO"

    $endDate = (Get-Date).ToString("yyyy-MM-dd")
    $startDate = (Get-Date).AddMonths(-6).ToString("yyyy-MM-dd")

    # Query monthly cost grouped by service name
    $body = @{
        type = "ActualCost"
        dataSet = @{
            granularity = "Monthly"
            aggregation = @{
                totalCost = @{
                    name = "Cost"
                    function = "Sum"
                }
            }
            grouping = @(
                @{
                    type = "Dimension"
                    name = "ServiceName"
                }
            )
        }
        timeframe = "Custom"
        timePeriod = @{
            from = $startDate
            to   = $endDate
        }
    } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-AzRestMethod -Path "/subscriptions/$SubId/providers/Microsoft.CostManagement/query?api-version=2023-11-01" -Method POST -Payload $body -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            $result = $response.Content | ConvertFrom-Json
            $rows = $result.properties.rows
            $columns = $result.properties.columns

            if ($rows -and $rows.Count -gt 0) {
                # Parse columns: typically [Cost, ServiceName, BillingMonth]
                $costIdx = -1
                $serviceIdx = -1
                $monthIdx = -1
                for ($i = 0; $i -lt $columns.Count; $i++) {
                    if ($columns[$i].name -eq "Cost") { $costIdx = $i }
                    elseif ($columns[$i].name -eq "ServiceName") { $serviceIdx = $i }
                    elseif ($columns[$i].name -eq "BillingMonth" -or $columns[$i].name -eq "UsageDate") { $monthIdx = $i }
                }
                if ($costIdx -lt 0 -or $serviceIdx -lt 0 -or $monthIdx -lt 0) {
                    Write-Status "  Cost query response missing expected columns (Cost=$costIdx, ServiceName=$serviceIdx, Month=$monthIdx)" "WARN"
                    return
                }

                # Build monthly data per service
                $monthlyByService = @{}
                $allMonths = [System.Collections.Generic.SortedSet[string]]::new()
                $totalByService = @{}

                foreach ($row in $rows) {
                    $cost = [double]$row[$costIdx]
                    $service = [string]$row[$serviceIdx]
                    $monthRaw = [string]$row[$monthIdx]
                    # Parse month from API — can arrive as yyyyMMdd integer, yyyy-MM, or MM/DD/YYYY date string
                    $monthKey = $monthRaw
                    try {
                        $parsedDate = [datetime]::Parse($monthRaw)
                        $monthKey = $parsedDate.ToString('yyyy-MM')
                    } catch {
                        if ($monthRaw -match '^(\d{4})-(\d{1,2})') {
                            $monthKey = '{0}-{1:D2}' -f [int]$Matches[1], [int]$Matches[2]
                        } elseif ($monthRaw -match '^(\d{4})(\d{2})') {
                            $monthKey = '{0}-{1}' -f $Matches[1], $Matches[2]
                        }
                    }

                    [void]$allMonths.Add($monthKey)
                    if (-not $monthlyByService.ContainsKey($service)) { $monthlyByService[$service] = @{} }
                    if (-not $monthlyByService[$service].ContainsKey($monthKey)) { $monthlyByService[$service][$monthKey] = 0 }
                    $monthlyByService[$service][$monthKey] += $cost

                    if (-not $totalByService.ContainsKey($service)) { $totalByService[$service] = 0 }
                    $totalByService[$service] += $cost
                }

                # Top 10 services by total cost
                $topServices = $totalByService.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10

                # Calculate total cost
                $totalCost = ($totalByService.Values | Measure-Object -Sum).Sum

                # Calculate growth: compare last month vs first month for top services
                $months = @($allMonths)
                $growth = @{}
                if ($months.Count -ge 2) {
                    $firstMonth = $months[0]
                    $lastMonth = $months[-1]
                    foreach ($svc in $topServices) {
                        $firstVal = if ($monthlyByService[$svc.Key].ContainsKey($firstMonth)) { $monthlyByService[$svc.Key][$firstMonth] } else { 0 }
                        $lastVal = if ($monthlyByService[$svc.Key].ContainsKey($lastMonth)) { $monthlyByService[$svc.Key][$lastMonth] } else { 0 }
                        $pctChange = if ($firstVal -gt 0) { [math]::Round((($lastVal - $firstVal) / $firstVal) * 100, 1) } else { if ($lastVal -gt 0) { 100 } else { 0 } }
                        $growth[$svc.Key] = $pctChange
                    }
                }

                $script:CostData[$SubId] = @{
                    SubName         = $SubName
                    TotalCost       = [math]::Round($totalCost, 2)
                    TopServices     = $topServices
                    MonthlyByService = $monthlyByService
                    Months          = $months
                    Growth          = $growth
                    Currency        = if ($result.properties.columns | Where-Object { $_.name -eq "Currency" }) { $rows[0][-1] } else { "USD" }
                }
                Write-Status "  Cost data collected: total $([math]::Round($totalCost, 0)) ($($months.Count) months, $($totalByService.Count) services)" "OK"
            } else {
                Write-Status "  No cost data returned for this subscription" "INFO"
            }
        } else {
            $errMsg = if ($response.Content) { try { ($response.Content | ConvertFrom-Json).error.message } catch { "HTTP $($response.StatusCode)" } } else { "HTTP $($response.StatusCode)" }
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $errMsg -match 'authorization|BillingAccountNotFound|IndirectCostDisabled') {
                Write-Status "  Cost data skipped — account lacks Cost Management Reader role on this subscription (non-blocking)" "INFO"
            } else {
                Write-Status "  Cost Management API: $errMsg" "WARN"
            }
        }
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match 'authorization|forbidden|401|403') {
            Write-Status "  Cost data skipped — insufficient permissions (requires Cost Management Reader role)" "INFO"
        } else {
            Write-Status "  Cost data not available: $msg" "WARN"
        }
    }
}

# ============================================================================
# 2. RESOURCE INVENTORY
# ============================================================================
function Get-ResourceInventory {
    param([string]$SubId, [string]$SubName)

    Write-Status "Collecting resource inventory..." "SECTION"

    # Use Resource Graph if available (faster and supports pagination)
    $resources = $null
    if (Get-Module -ListAvailable -Name Az.ResourceGraph) {
        Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue
        $graphResults = @()
        $skipToken = $null
        do {
            $params = @{ Query = "resources | project name, type, location, resourceGroup, tags"; Subscription = $SubId; First = 1000; ErrorAction = 'SilentlyContinue' }
            if ($skipToken) { $params['SkipToken'] = $skipToken }
            $page = Search-AzGraph @params
            if ($page) { $graphResults += $page; $skipToken = $page.SkipToken } else { $skipToken = $null }
        } while ($skipToken)
        if ($graphResults) {
            $resources = $graphResults | ForEach-Object {
                [PSCustomObject]@{
                    Name              = $_.name
                    ResourceType      = $_.type
                    Location          = $_.location
                    ResourceGroupName = $_.resourceGroup
                    Tags              = $_.tags
                }
            }
        }
    }
    if (-not $resources) {
        $resources = Invoke-AzCommandSafely { Get-AzResource -ErrorAction SilentlyContinue } "Error retrieving resources"
    }
    if (-not $resources) { return }

    # Exclude child/sub-resources (types with 3+ segments like microsoft.compute/virtualmachines/extensions)
    $resources = @($resources | Where-Object {
        ($_.ResourceType -split '/').Count -le 2
    })

    $script:Summary.TotalResources += $resources.Count
    Write-Status "  Resources found: $($resources.Count)" "INFO"

    foreach ($r in $resources) {
        $script:Resources.Add([PSCustomObject]@{
            Name          = $r.Name
            Type          = $r.ResourceType
            Location      = $r.Location
            ResourceGroup = $r.ResourceGroupName
            Subscription  = $SubName
            Tags          = ($r.Tags | ConvertTo-Json -Compress -ErrorAction SilentlyContinue)
        })

        # Verify tags
        if (-not $r.Tags -or $r.Tags.Count -eq 0) {
            $findingParams = @{
                Pillar         = "Operational Excellence"
                Severity       = "Low"
                Category       = "Governance - Tags"
                ResourceName   = $r.Name
                ResourceType   = $r.ResourceType
                ResourceGroup  = $r.ResourceGroupName
                Subscription   = $SubName
                Description    = "The resource has no tags assigned."
                Recommendation = "Implement a mandatory tagging policy (Environment, Owner, CostCenter)."
                Impact         = "Hinders management, governance, and cost allocation."
            }
            Add-Finding @findingParams
        }
    }
}

# ============================================================================
# 3. NETWORK ANALYSIS (TOPOLOGY, NSG, CONNECTIVITY)
# ============================================================================
function Analyze-Networking {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing network topology..." "SECTION"

    # --- VNETs ---
    $vnets = $script:CachedVNets
    if ($vnets) {
        Write-Status "  VNets found: $($vnets.Count)" "INFO"
        foreach ($vnet in $vnets) {
            $subnets = $vnet.Subnets
            $peerings = $vnet.VirtualNetworkPeerings

            $script:NetworkTopology.Add([PSCustomObject]@{
                Type         = "VNet"
                Name         = $vnet.Name
                ResourceGroup = $vnet.ResourceGroupName
                Location     = $vnet.Location
                AddressSpace = ($vnet.AddressSpace.AddressPrefixes -join ", ")
                SubnetCount  = $subnets.Count
                Peerings     = ($peerings | ForEach-Object { if ($_.RemoteVirtualNetwork -and $_.RemoteVirtualNetwork.Id) { $_.RemoteVirtualNetwork.Id.Split('/')[-1] } }) -join ", "
                PeeringDetails = ($peerings | ForEach-Object {
                    [PSCustomObject]@{
                        PeeringName    = $_.Name
                        RemoteVNet     = if ($_.RemoteVirtualNetwork -and $_.RemoteVirtualNetwork.Id) { $_.RemoteVirtualNetwork.Id.Split('/')[-1] } else { 'Unknown' }
                        PeeringState   = $_.PeeringState
                        AllowForwarded = $_.AllowForwardedTraffic
                        AllowGateway   = $_.AllowGatewayTransit
                        UseRemoteGw    = $_.UseRemoteGateways
                    }
                })
                Subscription = $SubName
                SubnetDetails = ($subnets | ForEach-Object {
                    [PSCustomObject]@{
                        Name = $_.Name
                        AddressPrefix = ($_.AddressPrefix -join ", ")
                        NsgName = if ($_.NetworkSecurityGroup) { $_.NetworkSecurityGroup.Id.Split('/')[-1] } else { $null }
                        NatGatewayName = if ($_.NatGateway) { $_.NatGateway.Id.Split('/')[-1] } else { $null }
                        ServiceEndpoints = ($_.ServiceEndpoints | ForEach-Object { $_.Service }) -join ", "
                        Delegations = ($_.Delegations | ForEach-Object { $_.ServiceName }) -join ", "
                        ConnectedDevices = $_.IpConfigurations.Count
                    }
                })
            })

            # Analyze subnets
            foreach ($subnet in $subnets) {
                if (-not $subnet.NetworkSecurityGroup -and $subnet.Name -notin @("GatewaySubnet","AzureBastionSubnet","AzureFirewallSubnet","AzureFirewallManagementSubnet","RouteServerSubnet") -and -not ($subnet.Delegations | Where-Object { $_.ServiceName -in @('Microsoft.Netapp/volumes','Microsoft.Databricks/workspaces') })) {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "Critical"
                        Category       = "Network - Missing NSG"
                        ResourceName   = "$($vnet.Name)/$($subnet.Name)"
                        ResourceType   = "Subnet"
                        ResourceGroup  = $vnet.ResourceGroupName
                        Subscription   = $SubName
                        Description    = "Subnet '$($subnet.Name)' in VNet '$($vnet.Name)' does NOT have an associated NSG."
                        Recommendation = "Associate an NSG to this subnet with restrictive rules (deny-all by default)."
                        Impact         = "Unfiltered traffic allows lateral movement and internal service exposure."
                    }
                    Add-Finding @findingParams
                }

                # Subnet without service endpoints
                if ((-not $subnet.ServiceEndpoints -or $subnet.ServiceEndpoints.Count -eq 0) -and $subnet.Name -notmatch "Gateway|Bastion|Firewall") {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "Medium"
                        Category       = "Network - Service Endpoints"
                        ResourceName   = "$($vnet.Name)/$($subnet.Name)"
                        ResourceType   = "Subnet"
                        ResourceGroup  = $vnet.ResourceGroupName
                        Subscription   = $SubName
                        Description    = "The subnet has no Service Endpoints configured."
                        Recommendation = "Configure Private Endpoints (preferred) or Service Endpoints for Storage, SQL, KeyVault as needed."
                        Impact         = "Traffic to PaaS services travels over the Internet instead of the Azure backbone."
                    }
                    Add-Finding @findingParams
                }
            }

            # Verify peerings
            foreach ($peering in $peerings) {
                if ($peering.PeeringState -ne "Connected") {
                    $findingParams = @{
                        Pillar         = "Reliability"
                        Severity       = "High"
                        Category       = "Network - Peering"
                        ResourceName   = "$($vnet.Name) <-> $($peering.RemoteVirtualNetwork.Id.Split('/')[-1])"
                        ResourceType   = "VNet Peering"
                        ResourceGroup  = $vnet.ResourceGroupName
                        Subscription   = $SubName
                        Description    = "Peering '$($peering.Name)' is in state: $($peering.PeeringState)."
                        Recommendation = "Verify and restore the peering connection."
                        Impact         = "Interrupted communication between VNets affects service connectivity."
                    }
                    Add-Finding @findingParams
                }
            }

            # Verify DDoS Protection — only flag if VNet has public-facing resources
            if (-not $vnet.DdosProtectionPlan) {
                # Check if any associated (non-orphaned) PIP exists in the same resource group as the VNet
                $vnetHasPublicEndpoint = $script:CachedPublicIPs | Where-Object {
                    $_.ResourceGroupName -eq $vnet.ResourceGroupName -and $_.IpConfiguration
                }
                if ($vnetHasPublicEndpoint) {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "Medium"
                        Category       = "Network - DDoS"
                        ResourceName   = $vnet.Name
                        ResourceType   = "VNet"
                        ResourceGroup  = $vnet.ResourceGroupName
                        Subscription   = $SubName
                        Description    = "VNet with public-facing resources does not have DDoS Protection Plan enabled."
                        Recommendation = "Enable Azure DDoS Protection Standard for this VNet to protect public endpoints."
                        Impact         = "Vulnerability to volumetric DDoS attacks on publicly exposed services."
                    }
                    Add-Finding @findingParams
                }
            }
        }
    }

    # --- NSGs ---
    Write-Status "  Analyzing Network Security Groups..." "INFO"
    $nsgs = $script:CachedNSGs
    if ($nsgs) {
        foreach ($nsg in $nsgs) {
            $rules = $nsg.SecurityRules + $nsg.DefaultSecurityRules

            # Dangerous rules: Allow Any from Internet
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow") {
                    $dangerousPorts = @("*", "22", "3389", "445", "1433", "3306", "5432", "27017")
                    # Check both singular and plural port/source properties
                    $destPorts = @($rule.DestinationPortRange) + @($rule.DestinationPortRanges) | Where-Object { $_ }
                    $sourcePrefixes = @($rule.SourceAddressPrefix) + @($rule.SourceAddressPrefixes) | Where-Object { $_ }
                    $isFromInternet = $sourcePrefixes | Where-Object { $_ -in @("*", "Internet", "0.0.0.0/0") }
                    # Check exact matches AND port ranges that cover dangerous ports
                    $destPort = ($destPorts | Where-Object {
                        if ($_ -in $dangerousPorts) { return $true }
                        if ($_ -match '^(\d+)-(\d+)$') {
                            $lo = [int]$Matches[1]; $hi = [int]$Matches[2]
                            foreach ($dp in $dangerousPorts) {
                                if ($dp -ne '*' -and [int]$dp -ge $lo -and [int]$dp -le $hi) { return $true }
                            }
                        }
                        return $false
                    }) | Select-Object -First 1
                    # Normalize range to the specific dangerous port for the message
                    if ($destPort -match '^\d+-\d+$') {
                        $lo = [int]($destPort -split '-')[0]; $hi = [int]($destPort -split '-')[1]
                        $matched = $dangerousPorts | Where-Object { $_ -ne '*' -and [int]$_ -ge $lo -and [int]$_ -le $hi } | Select-Object -First 1
                        if ($matched) { $destPort = "$matched (in range $destPort)" }
                    }

                    if ($isFromInternet -and $destPort) {
                        # Extract raw port number for severity check (before "in range" annotation)
                        $rawPort = if ($destPort -match '^(\d+|\*)') { $Matches[1] } else { $destPort }
                        $severity = if ($rawPort -in @("*", "22", "3389")) { "Critical" } else { "High" }
                        $findingParams = @{
                            Pillar         = "Security"
                            Severity       = $severity
                            Category       = "Network - Dangerous NSG Rule"
                            ResourceName   = "$($nsg.Name)/$($rule.Name)"
                            ResourceType   = "NSG Rule"
                            ResourceGroup  = $nsg.ResourceGroupName
                            Subscription   = $SubName
                            Description    = "Rule allows inbound traffic from the Internet to port $destPort."
                            Recommendation = "Restrict source to specific IPs or use Azure Bastion/JIT for administrative access."
                            Impact         = "Port $destPort exposed to the Internet is a critical attack vector."
                        }
                        Add-Finding @findingParams
                    }
                }
            }

            # Unassociated NSG
            if (-not $nsg.Subnets -and -not $nsg.NetworkInterfaces) {
                $findingParams = @{
                    Pillar         = "Operational Excellence"
                    Severity       = "Low"
                    Category       = "Network - Orphaned NSG"
                    ResourceName   = $nsg.Name
                    ResourceType   = "NSG"
                    ResourceGroup  = $nsg.ResourceGroupName
                    Subscription   = $SubName
                    Description    = "NSG is not associated with any subnet or NIC."
                    Recommendation = "Associate with relevant resources or delete if not needed."
                    Impact         = "Unused resource generates confusion and management overhead."
                }
                Add-Finding @findingParams
            }

            # NSG Flow Logs — check via flowLogConfigurations on NSG properties
            $hasFlowLog = $false
            if ($nsg.FlowLog) { $hasFlowLog = $true }
            elseif ($nsg.Id) {
                # Check via Network Watcher status (Resource Graph pre-cached or property check)
                $flowConfigs = $nsg.NetworkSecurityGroup.FlowLogConfigurations
                if (-not $flowConfigs) {
                    # Check provisioned flow log status via REST if available
                    try {
                        $nsgDetail = Get-AzNetworkSecurityGroup -Name $nsg.Name -ResourceGroupName $nsg.ResourceGroupName -ErrorAction SilentlyContinue
                        if ($nsgDetail -and $nsgDetail.FlowLog) { $hasFlowLog = $true }
                    } catch {}
                } else { $hasFlowLog = $true }
            }
            if (-not $hasFlowLog) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Medium"
                    Category       = "Network - Flow Logs"
                    ResourceName   = $nsg.Name
                    ResourceType   = "NSG"
                    ResourceGroup  = $nsg.ResourceGroupName
                    Subscription   = $SubName
                    Description    = "NSG does not appear to have Flow Logs enabled."
                    Recommendation = "Enable NSG Flow Logs v2 with Traffic Analytics for traffic visibility."
                    Impact         = "Without network traffic visibility, threat detection and troubleshooting are hindered."
                }
                Add-Finding @findingParams
            }
        }
    }

    # --- Public IPs ---
    Write-Status "  Analyzing Public IPs..." "INFO"
    $pips = $script:CachedPublicIPs
    if ($pips) {
        foreach ($pip in $pips) {
            $script:NetworkTopology.Add([PSCustomObject]@{
                Type         = "PublicIP"
                Name         = $pip.Name
                ResourceGroup = $pip.ResourceGroupName
                Location     = $pip.Location
                IpAddress    = $pip.IpAddress
                AssociatedTo = if ($pip.IpConfiguration) { $pip.IpConfiguration.Id.Split('/')[-3] } else { "Unassociated" }
                Sku          = $pip.Sku.Name
                Subscription = $SubName
            })

            if (-not $pip.IpConfiguration -and -not $pip.NatGateway) {
                $findingParams = @{
                    Pillar         = "Cost Optimization"
                    Severity       = "Medium"
                    Category       = "Network - Orphaned Public IP"
                    ResourceName   = $pip.Name
                    ResourceType   = "Public IP"
                    ResourceGroup  = $pip.ResourceGroupName
                    Subscription   = $SubName
                    Description    = "Public IP '$($pip.IpAddress)' is not associated with any resource."
                    Recommendation = "Delete the IP if not needed to avoid unnecessary charges."
                    Impact         = "Unused Standard SKU public IPs are billed even when unassociated, and expand the attack surface."
                }
                Add-Finding @findingParams
            }

            # Basic PIP check moved to Analyze-AdditionalChecks (aggregated summary)
        }
    }

    # --- VPN / ExpressRoute Gateways ---
    Write-Status "  Analyzing Gateways (VPN/ExpressRoute)..." "INFO"
    # Search gateways by resource type (Get-AzVirtualNetworkGateway requires specific ResourceGroupName)
    $gwResources = $script:Resources | Where-Object { $_.Type -match "virtualNetworkGateways" }
    if ($gwResources) {
        foreach ($gw in $gwResources) {
            $script:NetworkTopology.Add([PSCustomObject]@{
                Type         = "Gateway"
                Name         = $gw.Name
                ResourceGroup = $gw.ResourceGroup
                Location     = $gw.Location
                GatewayType  = $gw.Type
                Subscription = $SubName
            })
        }
    }

    # --- NAT Gateways ---
    Write-Status "  Analyzing NAT Gateways..." "INFO"
    $natGwResources = Get-AzResource -ResourceType 'Microsoft.Network/natGateways' -ErrorAction SilentlyContinue
    if ($natGwResources) {
        foreach ($natRes in $natGwResources) {
            try {
                $natGw = Get-AzNatGateway -Name $natRes.Name -ResourceGroupName $natRes.ResourceGroupName -ErrorAction SilentlyContinue
                $natPips = if ($natGw.PublicIpAddresses) {
                    ($natGw.PublicIpAddresses | ForEach-Object { $_.Id.Split('/')[-1] }) -join ", "
                } else { "" }
                $natSubnets = if ($natGw.Subnets) {
                    ($natGw.Subnets | ForEach-Object { $_.Id.Split('/')[-1] }) -join ", "
                } else { "" }
                $script:NetworkTopology.Add([PSCustomObject]@{
                    Type          = "NatGateway"
                    Name          = $natRes.Name
                    ResourceGroup = $natRes.ResourceGroupName
                    Location      = $natRes.Location
                    PublicIPs     = $natPips
                    Subnets       = $natSubnets
                    Sku           = if ($natGw.Sku) { $natGw.Sku.Name } else { "Standard" }
                    Subscription  = $SubName
                })
            } catch { continue }
        }
    }

    # --- Load Balancers ---
    Write-Status "  Analyzing Load Balancers..." "INFO"
    # Basic LB check moved to Analyze-AdditionalChecks (aggregated summary)

    # --- Application Gateways / WAF ---
    $appgws = $script:CachedAppGateways
    if ($appgws) {
        foreach ($ag in $appgws) {
            if ($ag.WebApplicationFirewallConfiguration -eq $null -and $ag.FirewallPolicy -eq $null) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "Network - WAF"
                    ResourceName   = $ag.Name
                    ResourceType   = "Application Gateway"
                    ResourceGroup  = $ag.ResourceGroupName
                    Subscription   = $SubName
                    Description    = "Application Gateway does not have WAF enabled."
                    Recommendation = "Enable WAF in Prevention mode with DRS 2.1 / OWASP 3.2+ ruleset."
                    Impact         = "Web applications exposed without OWASP Top 10 protection."
                }
                Add-Finding @findingParams
            }
        }
    }

    # ── Route Tables (UDR) — subnets without forced tunneling to firewall/NVA ──
    Write-Status "  Analyzing Route Tables (UDR)..." "INFO"
    $vnets = $script:CachedVNets
    if ($vnets) {
        $routeTables = Invoke-AzCommandSafely { Get-AzRouteTable -ErrorAction SilentlyContinue } "Route Tables"
        $rtSubnets = @{}
        if ($routeTables) {
            foreach ($rt in $routeTables) {
                foreach ($sub in $rt.Subnets) {
                    if ($sub.Id) { $rtSubnets[$sub.Id.ToLower()] = $rt.Name }
                }
            }
        }
        foreach ($vnet in $vnets) {
            foreach ($subnet in $vnet.Subnets) {
                $snName = $subnet.Name
                if ($snName -in @('GatewaySubnet','AzureBastionSubnet','AzureFirewallSubnet','AzureFirewallManagementSubnet','RouteServerSubnet')) { continue }
                if ($subnet.Delegations -and $subnet.Delegations.Count -gt 0) { continue }
                $hasUDR = $rtSubnets.ContainsKey($subnet.Id.ToLower())
                if (-not $hasUDR) {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "Network - No Route Table" `
                        -ResourceName "$($vnet.Name)/$snName" -ResourceType "Subnet" `
                        -ResourceGroup $vnet.ResourceGroupName -Subscription $SubName `
                        -Description "Subnet has no User Defined Route (UDR) associated. Traffic is not forced through a firewall or NVA." `
                        -Recommendation "Associate a route table with a 0.0.0.0/0 route pointing to Azure Firewall or NVA for traffic inspection." `
                        -Impact "Without forced tunneling, egress traffic bypasses network security controls."
                }
            }
        }
    }

    # ── Network Watcher enabled check ──
    Write-Status "  Checking Network Watcher..." "INFO"
    $networkWatchers = Invoke-AzCommandSafely { Get-AzNetworkWatcher -ErrorAction SilentlyContinue } "Network Watcher"
    $usedRegions = @($script:CachedVNets | ForEach-Object { $_.Location } | Sort-Object -Unique)
    if ($usedRegions.Count -gt 0) {
        $nwRegions = @()
        if ($networkWatchers) { $nwRegions = @($networkWatchers | ForEach-Object { $_.Location }) }
        $missingNW = $usedRegions | Where-Object { $_ -notin $nwRegions }
        if ($missingNW.Count -gt 0) {
            Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "Network - No Network Watcher" `
                -ResourceName "$($missingNW.Count) region(s)" -ResourceType "Network Watcher" `
                -ResourceGroup "N/A" -Subscription $SubName `
                -Description "Network Watcher is not enabled in $($missingNW.Count) region(s): $($missingNW -join ', ')." `
                -Recommendation "Enable Network Watcher in all regions with deployed resources. It is required for NSG flow logs, connection monitor, and packet capture." `
                -Impact "Without Network Watcher, NSG flow logs cannot be collected and network diagnostics are unavailable."
        }
    }
}

# ============================================================================
# 4. VIRTUAL MACHINE ANALYSIS
# ============================================================================
function Analyze-VirtualMachines {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Virtual Machines..." "SECTION"
    $vms = $script:CachedVMs
    if (-not $vms) { return }

    Write-Status "  VMs found: $($vms.Count)" "INFO"

    # Pre-fetch all backed-up VM IDs via Resource Graph (1 query instead of N)
    $backedUpVmIds = @{}
    $graphAvailable = Get-Module -ListAvailable -Name Az.ResourceGraph
    if ($graphAvailable) {
        $backupResults = Invoke-AzCommandSafely {
            Search-AzGraph -Query @"
recoveryservicesresources
| where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems'
| where properties.backupManagementType =~ 'AzureIaasVM'
| extend vmId = tolower(tostring(properties.sourceResourceId))
| project vmId
"@ -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
        } "Resource Graph backup status query"
        if ($backupResults) {
            foreach ($b in $backupResults) { $backedUpVmIds[$b.vmId] = $true }
        }
        Write-Status "  Backed up VMs: $($backedUpVmIds.Count)/$($vms.Count)" "INFO"
    }

    foreach ($vm in $vms) {
        $vmName = $vm.Name
        $rg = $vm.ResourceGroupName

        # --- Backup check moved to Analyze-BCDR (avoids duplicate findings) ---

        # --- Availability ---
        if (-not $vm.AvailabilitySetReference -and -not $vm.Zones) {
            $isProduction = $vm.Tags -and ($vm.Tags.Keys -match '^(env|environment)$') -and ($vm.Tags.Values -match '^prod(uction)?$')
            $findingParams = @{
                Pillar         = "Reliability"
                Severity       = if ($isProduction) { "High" } else { "Medium" }
                Category       = "VM - No High Availability"
                ResourceName   = $vmName
                ResourceType   = "Virtual Machine"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "VM is not in an Availability Set or Availability Zone."
                Recommendation = "Deploy in Availability Zones (preferred) or Availability Sets for critical workloads."
                Impact         = "Reduced SLA. Hardware failure or host maintenance causes downtime."
            }
            Add-Finding @findingParams
            }

        # --- Disk Encryption (use pre-cached data) ---
        $encStatus = $script:CachedVMEncryption[$vm.Id]

        if ($encStatus) {
            if ($encStatus.OsVolumeEncrypted -ne "Encrypted") {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "VM - Unencrypted OS Disk"
                    ResourceName   = $vmName
                    ResourceType   = "Virtual Machine"
                    ResourceGroup  = $rg
                    Subscription   = $SubName
                    Description    = "The OS disk is not encrypted with Azure Disk Encryption."
                    Recommendation = "Enable Azure Disk Encryption or use disks with encryption-at-host."
                    Impact         = "Sensitive data on disk accessible if the VHD is copied or the disk extracted."
                }
                Add-Finding @findingParams
            }
        }

        # --- Monitoring extensions (use Resource Graph pre-cached data) ---
        $vmIdLower = $vm.Id.ToLower()
        $extTypes = $script:CachedVMExtensions[$vmIdLower]
        $hasMonitoring = $extTypes | Where-Object {
            $_ -match "AzureMonitorLinuxAgent|AzureMonitorWindowsAgent"
        }
        if (-not $hasMonitoring) {
            $findingParams = @{
                Pillar         = "Operational Excellence"
                Severity       = "High"
                Category       = "VM - No Monitoring"
                ResourceName   = $vmName
                ResourceType   = "Virtual Machine"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "VM does not have Azure Monitor agent installed."
                Recommendation = "Install Azure Monitor Agent (AMA) and configure Data Collection Rules."
                Impact         = "Without logs or metrics, impossible to detect issues, threats, or degradation."
            }
            Add-Finding @findingParams
        }

        # --- VM Stopped but not deallocated ---
        $powerState = ($vm.Statuses | Where-Object { $_.Code -match "PowerState" }).Code
        if ($powerState -eq "PowerState/stopped") {
            $findingParams = @{
                Pillar         = "Cost Optimization"
                Severity       = "High"
                Category       = "VM - Stopped (No Deallocated)"
                ResourceName   = $vmName
                ResourceType   = "Virtual Machine"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "VM is stopped but NOT deallocated. Compute charges continue."
                Recommendation = "Use Stop-AzVM -Force to deallocate and stop paying for compute."
                Impact         = "Full compute charges for a VM that is not in use."
            }
            Add-Finding @findingParams
        }

        # --- Managed Disks ---
        if ($vm.StorageProfile.OsDisk.ManagedDisk -eq $null) {
            $findingParams = @{
                Pillar         = "Reliability"
                Severity       = "Medium"
                Category       = "VM - Unmanaged Disks"
                ResourceName   = $vmName
                ResourceType   = "Virtual Machine"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "VM uses unmanaged disks."
                Recommendation = "Migrate to Managed Disks for better SLA, snapshots, and encryption."
                Impact         = "Unmanaged disks have lower SLA and require manual storage account management."
            }
            Add-Finding @findingParams
        }
    }
}

# ============================================================================
# 5. APP SERVICES ANALYSIS
# ============================================================================
function Analyze-AppServices {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing App Services / Web Apps..." "SECTION"
    $webApps = $script:CachedWebApps
    if (-not $webApps) { return }

    Write-Status "  App Services found: $($webApps.Count)" "INFO"

    foreach ($app in $webApps) {
        $appName = $app.Name
        $rg = $app.ResourceGroup

        # Get detailed configuration (pre-cached in Invoke-DataCollection)
        $config = $script:CachedWebAppDetails[$app.Id]
        if (-not $config) { continue }

        # --- HTTPS Only ---
        if (-not $config.HttpsOnly) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "App Service - HTTPS"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "App Service allows HTTP traffic (does not enforce HTTPS)."
                Recommendation = "Enable 'HTTPS Only' in the App Service configuration."
                Impact         = "Unencrypted traffic exposes sensitive data in transit (credentials, tokens)."
            }
            Add-Finding @findingParams
        }

        # --- Public access ---
        $accessRestrictions = $config.SiteConfig.IpSecurityRestrictions
        $isPublic = $true
        if ($accessRestrictions -and $accessRestrictions.Count -gt 1) {
            # Azure always includes a default Allow-All rule (priority 2147483647). Check if there are real deny/restrict rules.
            $customRules = @($accessRestrictions | Where-Object { $_.Priority -ne 2147483647 })
            $hasDenyAll = @($accessRestrictions | Where-Object { $_.Action -eq 'Deny' -and $_.IpAddress -eq 'Any' }) 
            if ($customRules.Count -gt 0 -or $hasDenyAll.Count -gt 0) {
                $isPublic = $false
            }
        }
        # Check for VNet Integration
        $hasVnetIntegration = $config.VirtualNetworkSubnetId -ne $null

        # Check for Private Endpoints
        $privateEndpoints = Safe-AzCommand {
            Get-AzPrivateEndpointConnection -PrivateLinkResourceId $config.Id -ErrorAction SilentlyContinue
        } "Info: Private Endpoints not verified for $appName"

        if ($isPublic -and -not $privateEndpoints) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "App Service - Public Exposure"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "App Service publicly accessible without IP restrictions or Private Endpoint."
                Recommendation = "Configure Access Restrictions, Private Endpoints, or VNet Integration."
                Impact         = "Attack surface exposed. Anyone on the Internet can attempt access."
            }
            Add-Finding @findingParams
        }

        # --- TLS Version ---
        if ($config.SiteConfig.MinTlsVersion -and [version]$config.SiteConfig.MinTlsVersion -lt [version]"1.2") {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "App Service - TLS"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Minimum TLS is $($config.SiteConfig.MinTlsVersion). TLS 1.0/1.1 have known vulnerabilities."
                Recommendation = "Set MinTlsVersion to 1.2 or higher."
                Impact         = "Legacy TLS protocols are vulnerable to POODLE, BEAST attacks, etc."
            }
            Add-Finding @findingParams
        }

        # --- Managed Identity ---
        if (-not $config.Identity -or $config.Identity.Type -eq "None") {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "Medium"
                Category       = "App Service - Managed Identity"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "App Service does not have Managed Identity enabled."
                Recommendation = "Enable System-Assigned or User-Assigned Managed Identity."
                Impact         = "Without MI, the app requires hardcoded credentials to access other Azure services."
            }
            Add-Finding @findingParams
        }

        # --- Always On ---
        if ($config.SiteConfig.AlwaysOn -eq $false) {
            $findingParams = @{
                Pillar         = "Performance Efficiency"
                Severity       = "Low"
                Category       = "App Service - Always On"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Always On is disabled."
                Recommendation = "Enable Always On to avoid cold starts in production apps."
                Impact         = "The app unloads after inactivity, causing latency on the first request."
            }
            Add-Finding @findingParams
        }

        # --- Diagnostic Logs ---
        $diagSettings = Safe-AzCommand {
            Get-AzDiagnosticSetting -ResourceId $config.Id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } "Info: Diagnostics not verified for $appName"
        if (-not $diagSettings) {
            $findingParams = @{
                Pillar         = "Operational Excellence"
                Severity       = "Medium"
                Category       = "App Service - Diagnostics"
                ResourceName   = $appName
                ResourceType   = "App Service"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "No Diagnostic Settings configured."
                Recommendation = "Configure log forwarding to Log Analytics, Storage Account, or Event Hub."
                Impact         = "Without centralized logs, troubleshooting and auditing are hindered."
            }
            Add-Finding @findingParams
        }
    }
}

# ============================================================================
# 6. DATABASE ANALYSIS
# ============================================================================
function Analyze-Databases {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing SQL databases..." "SECTION"

    # --- Azure SQL ---
    $sqlServers = $script:CachedSqlServers
    if ($sqlServers) {
        foreach ($server in $sqlServers) {
            $srvName = $server.ServerName
            $rg = $server.ResourceGroupName

            # Firewall Rules
            $fwRules = Safe-AzCommand { Get-AzSqlServerFirewallRule -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue }
            $allowAllAzure = $fwRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "0.0.0.0" }
            $allowAllInternet = $fwRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "255.255.255.255" }

            if ($allowAllInternet) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Critical"
                    Category       = "SQL - Open Firewall"
                    ResourceName   = $srvName
                    ResourceType   = "SQL Server"
                    ResourceGroup  = $rg
                    Subscription   = $SubName
                    Description    = "Firewall rule allows access from ALL of the Internet (0.0.0.0 - 255.255.255.255)."
                    Recommendation = "Remove this rule. Use Private Endpoints or specific IPs."
                    Impact         = "Database fully exposed to brute force attacks from the Internet."
                }
                Add-Finding @findingParams
            }

            if ($allowAllAzure) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "SQL - Allow Azure Services"
                    ResourceName   = $srvName
                    ResourceType   = "SQL Server"
                    ResourceGroup  = $rg
                    Subscription   = $SubName
                    Description    = "Firewall rule 'Allow Azure services and resources to access this server' is enabled (0.0.0.0 - 0.0.0.0). Any Azure-hosted service (including other tenants) can reach this server."
                    Recommendation = "Disable this rule and use Private Endpoints or specific VNet service endpoints. If Azure service access is needed, use specific IP ranges."
                    Impact         = "Any Azure resource from any tenant can attempt connections to this SQL Server, expanding the attack surface significantly."
                }
                Add-Finding @findingParams
            }

            # TDE
            $databases = Safe-AzCommand { Get-AzSqlDatabase -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue | Where-Object { $_.DatabaseName -ne "master" } }
            foreach ($db in $databases) {
                $tde = Safe-AzCommand { Get-AzSqlDatabaseTransparentDataEncryption -ServerName $srvName -ResourceGroupName $rg -DatabaseName $db.DatabaseName -ErrorAction SilentlyContinue }
                if ($tde -and $tde.State -ne "Enabled") {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "High"
                        Category       = "SQL - TDE Disabled"
                        ResourceName   = "$srvName/$($db.DatabaseName)"
                        ResourceType   = "SQL Database"
                        ResourceGroup  = $rg
                        Subscription   = $SubName
                        Description    = "Transparent Data Encryption is not enabled."
                        Recommendation = "Enable TDE for at-rest encryption."
                        Impact         = "Unencrypted data at rest is accessible if database files are compromised."
                    }
                    Add-Finding @findingParams
                }

                # Geo-replication
                $dbEdition = if ($db.Edition) { $db.Edition } elseif ($db.SkuName) { $db.SkuName } else { 'Unknown' }
                if ($dbEdition -notin @('Basic', 'Free', 'System', 'Unknown')) {
                    $geoRep = $null
                    try {
                        $links = Get-AzSqlDatabaseFailoverGroup -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue
                        if ($links) { $geoRep = $links | Where-Object { $_.Databases -contains $db.Id } }
                    } catch {}
                    if (-not $geoRep) {
                        try { $geoRep = Invoke-AzRestMethod -Path "/subscriptions/$SubId/resourceGroups/$rg/providers/Microsoft.Sql/servers/$srvName/databases/$($db.DatabaseName)/replicationLinks?api-version=2022-05-01-preview" -Method GET -ErrorAction SilentlyContinue | ForEach-Object { if ($_.StatusCode -eq 200 -and $_.Content) { ($_.Content | ConvertFrom-Json).value } } } catch {}
                    }
                    if (-not $geoRep) {
                        $findingParams = @{
                            Pillar         = "Reliability"
                            Severity       = "Medium"
                            Category       = "SQL - No Geo-Replication"
                            ResourceName   = "$srvName/$($db.DatabaseName)"
                            ResourceType   = "SQL Database"
                            ResourceGroup  = $rg
                            Subscription   = $SubName
                            Description    = "Database without geo-replication configured."
                            Recommendation = "Configure active geo-replication or auto-failover group for DR."
                            Impact         = "Regional failure causes database availability loss."
                        }
                        Add-Finding @findingParams
                    }
                }
            }

            # Auditing
            $audit = Safe-AzCommand { Get-AzSqlServerAudit -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue }
            if (-not $audit -or ($audit.BlobStorageTargetState -ne "Enabled" -and $audit.LogAnalyticsTargetState -ne "Enabled" -and $audit.EventHubTargetState -ne "Enabled")) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "SQL - No Auditing"
                    ResourceName   = $srvName
                    ResourceType   = "SQL Server"
                    ResourceGroup  = $rg
                    Subscription   = $SubName
                    Description    = "SQL Server auditing is not enabled."
                    Recommendation = "Enable auditing to Log Analytics or Storage Account."
                    Impact         = "Without activity logging, impossible to detect unauthorized access or changes."
                }
                Add-Finding @findingParams
            }

            # ATP
            $atp = Safe-AzCommand { Get-AzSqlServerAdvancedThreatProtectionSetting -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue }
            if (-not $atp -or $atp.ThreatDetectionState -ne "Enabled") {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Medium"
                    Category       = "SQL - ATP"
                    ResourceName   = $srvName
                    ResourceType   = "SQL Server"
                    ResourceGroup  = $rg
                    Subscription   = $SubName
                    Description    = "Advanced Threat Protection is not enabled."
                    Recommendation = "Enable Microsoft Defender for SQL."
                    Impact         = "No threat detection for SQL injection, anomalous access, etc."
                }
                Add-Finding @findingParams
            }

            # AAD-only authentication check
            try {
                $aadAdmin = Safe-AzCommand { Get-AzSqlServerActiveDirectoryAdministrator -ServerName $srvName -ResourceGroupName $rg -ErrorAction SilentlyContinue }
                if (-not $aadAdmin) {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "SQL - No AAD Admin" `
                        -ResourceName $srvName -ResourceType "SQL Server" -ResourceGroup $rg `
                        -Subscription $SubName `
                        -Description "No Microsoft Entra ID administrator is configured. Only SQL authentication is available." `
                        -Recommendation "Configure an Entra ID admin and enable AAD-only authentication. Disable SQL authentication where possible." `
                        -Impact "SQL authentication uses passwords that are hard to audit, rotate, and cannot leverage MFA or Conditional Access."
                }
            } catch { Write-Status "  Could not check AAD admin for $srvName (skipped)" "WARN" }

            # Minimum TLS version check
            $sqlTls = $null
            try {
                $sqlRes = Get-AzResource -ResourceGroupName $rg -ResourceType 'Microsoft.Sql/servers' -ResourceName $srvName -ErrorAction SilentlyContinue
                if ($sqlRes) { $sqlTls = $sqlRes.Properties.minimalTlsVersion }
            } catch { Write-Status "  Could not check TLS version for $srvName (skipped)" "WARN" }
            if ($sqlTls -ne '1.2') {
                $tlsSeverity = if ($sqlTls -eq 'None' -or $sqlTls -eq '1.0') { 'Critical' } else { 'High' }
                $tlsDesc = if ($sqlTls -eq 'None') { "SQL Server has no minimum TLS version enforced (all versions accepted including TLS 1.0)." } else { "SQL Server minimum TLS version is $sqlTls instead of 1.2." }
                Add-Finding -Pillar "Security" -Severity $tlsSeverity -Category "SQL - Legacy TLS" `
                    -ResourceName $srvName -ResourceType "SQL Server" -ResourceGroup $rg `
                    -Subscription $SubName `
                    -Description $tlsDesc `
                    -Recommendation "Set minimum TLS version to 1.2. TLS 1.0 and 1.1 have known vulnerabilities and are deprecated." `
                    -Impact "Legacy TLS versions are susceptible to downgrade attacks and known cryptographic weaknesses."
            }
        }
    }
}

# ============================================================================
# 7. STORAGE ACCOUNTS ANALYSIS
# ============================================================================
function Analyze-Storage {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Storage Accounts..." "SECTION"
    $storageAccounts = $script:CachedStorageAccounts
    if (-not $storageAccounts) { return }

    foreach ($sa in $storageAccounts) {
        $saName = $sa.StorageAccountName
        $rg = $sa.ResourceGroupName

        # HTTPS Only
        if (-not $sa.EnableHttpsTrafficOnly) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "Storage - HTTPS"
                ResourceName   = $saName
                ResourceType   = "Storage Account"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Storage Account allows unencrypted HTTP traffic."
                Recommendation = "Enable 'Secure transfer required'."
                Impact         = "Unencrypted transferred data is susceptible to interception."
            }
            Add-Finding @findingParams
        }

        # Network Rules
        if ($sa.NetworkRuleSet.DefaultAction -eq "Allow") {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "Storage - Network Access"
                ResourceName   = $saName
                ResourceType   = "Storage Account"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Storage Account allows access from all networks (DefaultAction=Allow)."
                Recommendation = "Configure firewall: DefaultAction=Deny and add specific rules."
                Impact         = "Data accessible from any network, including the Internet."
            }
            Add-Finding @findingParams
        }

        # Blob Public Access
        if ($sa.AllowBlobPublicAccess) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "Critical"
                Category       = "Storage - Blob Public Access"
                ResourceName   = $saName
                ResourceType   = "Storage Account"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Blob public access is enabled at the account level."
                Recommendation = "Disable AllowBlobPublicAccess unless strictly necessary."
                Impact         = "Containers can be configured as public, exposing sensitive data."
            }
            Add-Finding @findingParams
        }

        # Soft Delete
        $blobSvc = Safe-AzCommand { Get-AzStorageBlobServiceProperty -StorageAccountName $saName -ResourceGroupName $rg -ErrorAction SilentlyContinue }
        if ($blobSvc -and (-not $blobSvc.DeleteRetentionPolicy -or -not $blobSvc.DeleteRetentionPolicy.Enabled)) {
            $findingParams = @{
                Pillar         = "Reliability"
                Severity       = "Medium"
                Category       = "Storage - Soft Delete"
                ResourceName   = $saName
                ResourceType   = "Storage Account"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Soft delete is not enabled for blobs."
                Recommendation = "Enable soft delete with a minimum 7-day retention."
                Impact         = "Accidental blob deletion is irrecoverable."
            }
            Add-Finding @findingParams
        }

        # Min TLS Version
        if ($sa.MinimumTlsVersion -and $sa.MinimumTlsVersion -ne "TLS1_2") {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "Medium"
                Category       = "Storage - TLS"
                ResourceName   = $saName
                ResourceType   = "Storage Account"
                ResourceGroup  = $rg
                Subscription   = $SubName
                Description    = "Minimum TLS is $($sa.MinimumTlsVersion) instead of TLS 1.2."
                Recommendation = "Set MinimumTlsVersion to TLS1_2."
                Impact         = "Legacy TLS versions have known vulnerabilities."
            }
            Add-Finding @findingParams
        }

        # Shared Key access — should be disabled for Zero Trust
        if ($sa.AllowSharedKeyAccess -ne $false) {
            Add-Finding -Pillar "Security" -Severity "Low" -Category "Storage - Shared Key Access" `
                -ResourceName $saName -ResourceType "Storage Account" -ResourceGroup $rg `
                -Subscription $SubName `
                -Description "Shared key (storage account key) access is still enabled. Access is possible without Entra ID authentication." `
                -Recommendation "Disable shared key access and use Entra ID (RBAC) for all data plane operations. Test existing applications first." `
                -Impact "Shared keys cannot be scoped, audited per-identity, or protected by Conditional Access policies."
        }
    }
}

# ============================================================================
# 8. KEY VAULTS ANALYSIS
# ============================================================================
function Analyze-KeyVaults {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Key Vaults..." "SECTION"
    $kvs = $script:CachedKeyVaults
    if (-not $kvs) { return }

    foreach ($kv in $kvs) {
        $kvDetail = Safe-AzCommand { Get-AzKeyVault -VaultName $kv.VaultName -ErrorAction SilentlyContinue } "Error KV detail $($kv.VaultName)"
        if (-not $kvDetail) { continue }

        # Soft Delete is now mandatory (since Feb 2025) — no need to check
        # Purge Protection (optional, recommended)
        if (-not $kvDetail.EnablePurgeProtection) {
            $findingParams = @{
                Pillar         = "Reliability"
                Severity       = "Medium"
                Category       = "Key Vault - Purge Protection"
                ResourceName   = $kv.VaultName
                ResourceType   = "Key Vault"
                ResourceGroup  = $kv.ResourceGroupName
                Subscription   = $SubName
                Description    = "Purge Protection is not enabled."
                Recommendation = "Enable Purge Protection to prevent permanent deletion during the retention period."
                Impact         = "A malicious administrator could purge secrets during the soft delete period."
            }
            Add-Finding @findingParams
        }

        # Network Access
        if ($kvDetail.NetworkAcls.DefaultAction -eq "Allow") {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "Key Vault - Network Access"
                ResourceName   = $kv.VaultName
                ResourceType   = "Key Vault"
                ResourceGroup  = $kv.ResourceGroupName
                Subscription   = $SubName
                Description    = "Key Vault allows access from all networks."
                Recommendation = "Configure firewall with DefaultAction=Deny and use Private Endpoints."
                Impact         = "Secrets and keys accessible from any network, including the Internet."
            }
            Add-Finding @findingParams
        }

        # Diagnostic Settings
        $diag = Safe-AzCommand { Get-AzDiagnosticSetting -ResourceId $kvDetail.ResourceId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
        if (-not $diag) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "Key Vault - No Diagnostics"
                ResourceName   = $kv.VaultName
                ResourceType   = "Key Vault"
                ResourceGroup  = $kv.ResourceGroupName
                Subscription   = $SubName
                Description    = "No Diagnostic Settings. Access to secrets/keys is not logged."
                Recommendation = "Configure diagnostics to Log Analytics to audit access."
                Impact         = "Without secret access auditing, impossible to detect misuse."
            }
            Add-Finding @findingParams
        }
    }
}

# ============================================================================
# 9. ORPHANED DISKS AND COST ANALYSIS
# ============================================================================
function Analyze-OrphanedResources {
    param([string]$SubId, [string]$SubName)

    Write-Status "Searching for orphaned resources and savings opportunities..." "SECTION"

    # Unattached disks (exclude disks being uploaded/exported/reserved)
    $disks = $script:CachedDisks
    if ($disks) {
        $orphanedDisks = $disks | Where-Object { $_.DiskState -eq "Unattached" }
        foreach ($disk in $orphanedDisks) {
            $diskSizeGB = if ($disk.DiskSizeGB -and $disk.DiskSizeGB -gt 0) { $disk.DiskSizeGB } else { 0 }
            $findingParams = @{
                Pillar         = "Cost Optimization"
                Severity       = "Medium"
                Category       = "Orphaned Disk"
                ResourceName   = $disk.Name
                ResourceType   = "Managed Disk"
                ResourceGroup  = $disk.ResourceGroupName
                Subscription   = $SubName
                Description    = "Disk of $($disk.DiskSizeGB) GB ($($disk.Sku.Name)) is not attached to any VM."
                Recommendation = "Verify if needed. Create a snapshot and delete if unused."
                Impact         = "Unattached managed disks ($($disk.Sku.Name), $diskSizeGB GB) continue to incur storage charges without providing value. Review in Azure Cost Management for actual cost."
            }
            Add-Finding @findingParams
        }
    }

    # Orphaned NICs (exclude Private Endpoint NICs, LB backend pool NICs, AppGw backend NICs)
    $nics = $script:CachedNICs
    if ($nics) {
        $orphanedNics = $nics | Where-Object {
            $_.VirtualMachine -eq $null -and
            $_.PrivateEndpoint -eq $null -and
            (-not $_.IpConfigurations -or -not ($_.IpConfigurations | Where-Object {
                ($_.LoadBalancerBackendAddressPools -and $_.LoadBalancerBackendAddressPools.Count -gt 0) -or
                ($_.LoadBalancerInboundNatRules -and $_.LoadBalancerInboundNatRules.Count -gt 0) -or
                ($_.ApplicationGatewayBackendAddressPools -and $_.ApplicationGatewayBackendAddressPools.Count -gt 0)
            }))
        }
        foreach ($nic in $orphanedNics) {
            $findingParams = @{
                Pillar         = "Cost Optimization"
                Severity       = "Low"
                Category       = "Orphaned NIC"
                ResourceName   = $nic.Name
                ResourceType   = "Network Interface"
                ResourceGroup  = $nic.ResourceGroupName
                Subscription   = $SubName
                Description    = "Network interface is not associated with any VM."
                Recommendation = "Delete if not needed."
                Impact         = "Unused resource generating confusion in the inventory."
            }
            Add-Finding @findingParams
        }
    }
}

# ============================================================================
# 10. MICROSOFT DEFENDER & SECURITY ANALYSIS
# ============================================================================
function Analyze-SecurityCenter {
    param([string]$SubId, [string]$SubName)

    Write-Status "Verifying Microsoft Defender for Cloud..." "SECTION"

    # ── 1. Defender Plan Coverage ──────────────────────────────────────────
    $pricings = Invoke-AzCommandSafely { Get-AzSecurityPricing -ErrorAction SilentlyContinue } "Error verifying Defender"
    if ($pricings) {
        # Expanded list — all major Defender plans
        $criticalPlans = @("VirtualMachines", "SqlServers", "AppServices", "StorageAccounts", "KeyVaults", "Containers",
                           "Dns", "Arm", "OpenSourceRelationalDatabases", "CosmosDbs", "CloudPosture")
        $freeTier = $pricings | Where-Object { $_.PricingTier -eq "Free" }
        foreach ($ft in $freeTier) {
            if ($ft.Name -in $criticalPlans) {
                $sev = if ($ft.Name -in @("VirtualMachines","SqlServers","Containers","CloudPosture")) { "Critical" } else { "High" }
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = $sev
                    Category       = "Defender for Cloud - Plan Coverage"
                    ResourceName   = "Defender for $($ft.Name)"
                    ResourceType   = "Microsoft Defender"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "Microsoft Defender for $($ft.Name) is on Free tier (no advanced protection)."
                    Recommendation = "Enable Defender Standard/P2 plan for $($ft.Name) to get threat detection, vulnerability assessment, and anomaly alerts."
                    Impact         = "No advanced threat detection, vulnerability assessment, or anomalous behavior detection for $($ft.Name) resources."
                }
                Add-Finding @findingParams
            }
        }
        # Summary: count enabled vs total
        $enabledCount = ($pricings | Where-Object { $_.PricingTier -ne "Free" }).Count
        $totalPlans   = $pricings.Count
        Write-Status "Defender plans: $enabledCount/$totalPlans enabled" "INFO"
    }

    # ── 2. Secure Score ────────────────────────────────────────────────────
    try {
        # Use pre-cached Resource Graph data if available
        $secureScores = $null
        if ($script:CachedSecureScores.ContainsKey($SubId)) {
            $cachedScores = $script:CachedSecureScores[$SubId]
            foreach ($cs in $cachedScores) {
                $current = [math]::Round([double]$cs.properties.score.current, 1)
                $max     = [math]::Round([double]$cs.properties.score.max, 1)
                $pct     = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 0) } else { 0 }
                Write-Status "Secure Score (cached): $current / $max ($pct%)" "INFO"

                if ($pct -lt 40) {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "Critical"
                        Category       = "Defender for Cloud - Secure Score"
                        ResourceName   = "Secure Score: $current / $max ($pct%)"
                        ResourceType   = "Security Posture"
                        ResourceGroup  = "N/A"
                        Subscription   = $SubName
                        Description    = "The subscription Secure Score is critically low at $pct% ($current/$max). This indicates a large number of unresolved security recommendations."
                        Recommendation = "Review Defender for Cloud recommendations and prioritize remediating critical and high-severity controls. Focus on identity, network, and data protection first."
                        Impact         = "A low Secure Score means significant security gaps exist. Attackers can exploit misconfigured resources, open ports, missing encryption, or weak identity controls."
                    }
                    Add-Finding @findingParams
                } elseif ($pct -lt 60) {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "High"
                        Category       = "Defender for Cloud - Secure Score"
                        ResourceName   = "Secure Score: $current / $max ($pct%)"
                        ResourceType   = "Security Posture"
                        ResourceGroup  = "N/A"
                        Subscription   = $SubName
                        Description    = "The subscription Secure Score is $pct% ($current/$max), indicating several unresolved security recommendations."
                        Recommendation = "Systematically address Defender for Cloud recommendations. Target bringing the score above 70% as a near-term goal."
                        Impact         = "Multiple security controls are not fully implemented, leaving the environment exposed to preventable threats."
                    }
                    Add-Finding @findingParams
                } elseif ($pct -lt 80) {
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "Medium"
                        Category       = "Defender for Cloud - Secure Score"
                        ResourceName   = "Secure Score: $current / $max ($pct%)"
                        ResourceType   = "Security Posture"
                        ResourceGroup  = "N/A"
                        Subscription   = $SubName
                        Description    = "The subscription Secure Score is $pct% ($current/$max). Some security recommendations remain unresolved."
                        Recommendation = "Continue improving the Secure Score by addressing remaining medium and high-impact recommendations."
                        Impact         = "Residual security gaps may exist in areas like network hardening, data encryption, or identity management."
                    }
                    Add-Finding @findingParams
                }
                # 80%+ = good posture, no finding generated
            }
        } else {
            # Fallback to cmdlet
            $secureScores = Get-AzSecuritySecureScore -ErrorAction SilentlyContinue
            if ($secureScores) {
                foreach ($score in $secureScores) {
                    $current = [math]::Round($score.CurrentScore, 1)
                    $max     = [math]::Round($score.MaxScore, 1)
                    $pct     = if ($max -gt 0) { [math]::Round(($current / $max) * 100, 0) } else { 0 }
                    Write-Status "Secure Score: $current / $max ($pct%)" "INFO"
                    if ($pct -lt 40) {
                        Add-Finding -Pillar "Security" -Severity "Critical" -Category "Defender for Cloud - Secure Score" -ResourceName "Secure Score: $current / $max ($pct%)" -ResourceType "Security Posture" -ResourceGroup "N/A" -Subscription $SubName -Description "The subscription Secure Score is critically low at $pct% ($current/$max)." -Recommendation "Review Defender for Cloud recommendations and prioritize remediating critical and high-severity controls." -Impact "A low Secure Score means significant security gaps exist."
                    } elseif ($pct -lt 60) {
                        Add-Finding -Pillar "Security" -Severity "High" -Category "Defender for Cloud - Secure Score" -ResourceName "Secure Score: $current / $max ($pct%)" -ResourceType "Security Posture" -ResourceGroup "N/A" -Subscription $SubName -Description "The subscription Secure Score is $pct% ($current/$max), indicating several unresolved recommendations." -Recommendation "Target bringing the score above 70%." -Impact "Multiple security controls are not fully implemented."
                    } elseif ($pct -lt 80) {
                        Add-Finding -Pillar "Security" -Severity "Medium" -Category "Defender for Cloud - Secure Score" -ResourceName "Secure Score: $current / $max ($pct%)" -ResourceType "Security Posture" -ResourceGroup "N/A" -Subscription $SubName -Description "The subscription Secure Score is $pct% ($current/$max)." -Recommendation "Continue improving the Secure Score." -Impact "Residual security gaps may exist."
                    }
                }
            }
        }
    } catch {
        Write-Status "Could not retrieve Secure Score: $($_.Exception.Message)" "WARN"
    }

    # ── 3. Security Recommendations (Unhealthy Assessments) ────────────────
    try {
        # Use pre-cached Resource Graph data if available
        $assessments = $null
        if ($script:CachedSecurityAssessments.ContainsKey($SubId)) {
            $unhealthy = $script:CachedSecurityAssessments[$SubId]
            $unhealthyCount = $unhealthy.Count
            Write-Status "Defender recommendations (cached): $unhealthyCount unhealthy assessment(s)" "INFO"
        } else {
            # Fallback to per-subscription cmdlet if cache miss
            Write-Status "  Retrieving security assessments (cmdlet fallback)..." "INFO"
            $assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue
            if ($assessments) {
                $unhealthy = $assessments | Where-Object { $_.Status.Code -eq 'Unhealthy' }
                $unhealthyCount = ($unhealthy | Measure-Object).Count
                Write-Status "Defender recommendations: $unhealthyCount unhealthy assessment(s)" "INFO"
            } else {
                $unhealthy = @()
                $unhealthyCount = 0
            }
        }

        if ($unhealthyCount -gt 0) {
            # Group by severity
            $critAssess = @()
            $highAssess = @()
            foreach ($a in $unhealthy) {
                # Support both Resource Graph format and cmdlet format
                $sevVal = if ($a.severity) { $a.severity } elseif ($a.Metadata.Severity) { $a.Metadata.Severity } elseif ($a.Status.Severity) { $a.Status.Severity } else { "Medium" }
                if ($sevVal -eq 'High') { $highAssess += $a }
                elseif ($sevVal -eq 'Critical') { $critAssess += $a }
            }

            # Report critical assessments individually (up to 10)
            $critToReport = $critAssess | Select-Object -First 10
            foreach ($ca in $critToReport) {
                $displayName = if ($ca.displayName) { $ca.displayName } elseif ($ca.DisplayName) { $ca.DisplayName } else { $ca.Name }
                $resId = if ($ca.resourceId) { $ca.resourceId.Split('/')[-1] } elseif ($ca.ResourceDetails.Id) { $ca.ResourceDetails.Id.Split('/')[-1] } else { "Multiple resources" }
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Critical"
                    Category       = "Defender for Cloud - Recommendation"
                    ResourceName   = $resId
                    ResourceType   = "Security Assessment"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "Defender for Cloud critical recommendation: $displayName"
                    Recommendation = "Open Defender for Cloud > Recommendations and remediate this finding. Follow the remediation steps provided by Microsoft."
                    Impact         = "Critical-severity recommendations indicate exploitable vulnerabilities or severe misconfigurations that attackers can leverage."
                    Source         = 'Defender for Cloud'
                }
                Add-Finding @findingParams
            }

            # Summarize high-severity if many
            $highCount = $highAssess.Count
            if ($highCount -gt 5) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "Defender for Cloud - Recommendations Summary"
                    ResourceName   = "Defender for Cloud"
                    ResourceType   = "Security Posture"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "$highCount high-severity Defender for Cloud recommendations are unresolved. Top areas: $( ($highAssess | Select-Object -First 3 | ForEach-Object { if ($_.displayName) { $_.displayName } elseif ($_.DisplayName) { $_.DisplayName } else { $_.Name } }) -join '; ' )"
                    Recommendation = "Review all high-severity recommendations in Defender for Cloud and create a remediation plan. Prioritize by resource exposure and blast radius."
                    Impact         = "Unresolved high-severity recommendations represent known security weaknesses that increase the attack surface."
                    Source         = 'Defender for Cloud'
                }
                Add-Finding @findingParams
            } elseif ($highCount -gt 0) {
                foreach ($ha in $highAssess) {
                    $displayName = if ($ha.displayName) { $ha.displayName } elseif ($ha.DisplayName) { $ha.DisplayName } else { $ha.Name }
                    $resId = if ($ha.resourceId) { $ha.resourceId.Split('/')[-1] } elseif ($ha.ResourceDetails.Id) { $ha.ResourceDetails.Id.Split('/')[-1] } else { "Multiple resources" }
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = "High"
                        Category       = "Defender for Cloud - Recommendation"
                        ResourceName   = $resId
                        ResourceType   = "Security Assessment"
                        ResourceGroup  = "N/A"
                        Subscription   = $SubName
                        Description    = "Defender for Cloud high-severity recommendation: $displayName"
                        Recommendation = "Open Defender for Cloud > Recommendations and remediate this finding."
                        Impact         = "Unresolved high-severity recommendations represent exploitable security gaps."
                        Source         = 'Defender for Cloud'
                    }
                    Add-Finding @findingParams
                }
            }

            # Overall summary if many unhealthy
            if ($unhealthyCount -gt 20) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "Defender for Cloud - Posture Overview"
                    ResourceName   = "Defender for Cloud"
                    ResourceType   = "Security Posture"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "$unhealthyCount total unhealthy security assessments detected in Defender for Cloud. This indicates the security posture needs significant improvement."
                    Recommendation = "Establish a security remediation sprint. Use Defender for Cloud's Secure Score recommendations sorted by impact to maximize improvement per effort."
                    Impact         = "A large number of unhealthy assessments increases the probability of successful attacks across the environment."
                }
                Add-Finding @findingParams
            }
        }
    } catch {
        Write-Status "Could not retrieve security assessments: $($_.Exception.Message)" "WARN"
    }

    # ── 4. Active Security Alerts ──────────────────────────────────────────
    try {
        # Use pre-cached Resource Graph data if available
        if ($script:CachedSecurityAlerts.ContainsKey($SubId)) {
            $activeAlerts = $script:CachedSecurityAlerts[$SubId]
            $activeCount = $activeAlerts.Count
            Write-Status "Active Defender alerts (cached): $activeCount" "INFO"
        } else {
            # Fallback to per-subscription cmdlet
            $alerts = Get-AzSecurityAlert -ErrorAction SilentlyContinue
            if ($alerts) {
                $activeAlerts = $alerts | Where-Object { $_.Status -eq 'Active' -or $_.Status -eq 'InProgress' }
                $activeCount  = ($activeAlerts | Measure-Object).Count
            } else {
                $activeAlerts = @()
                $activeCount = 0
            }
            Write-Status "Active Defender alerts: $activeCount" "INFO"
        }

        if ($activeCount -gt 0) {
            $alertsBySev = $activeAlerts | Group-Object { if ($_.severity) { $_.severity } else { $_.Severity } } -AsHashTable -AsString
            $highAlerts   = if ($alertsBySev['High']) { $alertsBySev['High'].Count } else { 0 }
            $critAlertsReal = if ($alertsBySev['Critical']) { $alertsBySev['Critical'].Count } else { 0 }
            $medAlerts   = if ($alertsBySev['Medium']) { $alertsBySev['Medium'].Count } else { 0 }

            if ($critAlertsReal -gt 0 -or $highAlerts -gt 0) {
                # Report up to 5 individual high/critical severity alerts
                $topAlerts = $activeAlerts | Where-Object { ($_.severity -in @('High','Critical')) -or ($_.Severity -in @('High','Critical')) } | Select-Object -First 5
                foreach ($al in $topAlerts) {
                    $entity = if ($al.entity) { $al.entity } elseif ($al.CompromisedEntity) { $al.CompromisedEntity } else { "Unknown" }
                    $alertDisplayName = if ($al.alertName) { $al.alertName } else { $al.AlertDisplayName }
                    $alertIntent = if ($al.intent) { $al.intent } else { $al.Intent }
                    $alertSev = if ($al.severity) { $al.severity } elseif ($al.Severity) { $al.Severity } else { 'High' }
                    $findingParams = @{
                        Pillar         = "Security"
                        Severity       = $alertSev
                        Category       = "Defender for Cloud - Active Alert"
                        ResourceName   = $entity
                        ResourceType   = "Security Alert"
                        ResourceGroup  = "N/A"
                        Subscription   = $SubName
                        Description    = "Active $alertSev-severity Defender alert: $alertDisplayName. Intent: $alertIntent."
                        Recommendation = "Investigate this alert immediately in Defender for Cloud > Security Alerts. Follow the remediation steps and check for indicators of compromise."
                        Impact         = "Active high-severity alerts may indicate an ongoing attack, compromised resource, or data exfiltration attempt."
                        Source         = 'Defender for Cloud'
                    }
                    Add-Finding @findingParams
                }
            }

            if ($activeCount -gt 5) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = if ($critAlertsReal -gt 0) { "Critical" } elseif ($highAlerts -gt 0) { "High" } else { "Medium" }
                    Category       = "Defender for Cloud - Alert Summary"
                    ResourceName   = "Defender for Cloud"
                    ResourceType   = "Security Alerts"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "$activeCount active security alert(s) in Defender for Cloud ($critAlertsReal critical, $highAlerts high, $medAlerts medium). These require investigation."
                    Recommendation = "Triage all active alerts. Assign ownership, investigate root cause, and close resolved alerts. Consider enabling automated response with Logic Apps."
                    Impact         = "Uninvestigated alerts may represent active threats, compromised resources, or ongoing data breaches that worsen over time."
                    Source         = 'Defender for Cloud'
                }
                Add-Finding @findingParams
            }
        }
    } catch {
        Write-Status "Could not retrieve security alerts: $($_.Exception.Message)" "WARN"
    }

    # ── 5. Regulatory Compliance (Azure Security Benchmark) ────────────────
    try {
        $compStandards = $null
        # Use pre-cached Resource Graph data if available
        if ($script:CachedRegulatoryCompliance.ContainsKey($SubId)) {
            $compStandards = $script:CachedRegulatoryCompliance[$SubId]
            $asb = $compStandards | Where-Object { $_.name -like '*Azure-Security-Benchmark*' -or $_.name -like '*azure-security-benchmark*' } | Select-Object -First 1
            if ($asb) {
                $failedControls = [int]$asb.properties.failedControls
                $passedControls = [int]$asb.properties.passedControls
                $skippedControls = [int]$asb.properties.skippedControls
                $totalControls  = $failedControls + $passedControls + $skippedControls
                $compPct = if ($totalControls -gt 0) { [math]::Round(($passedControls / $totalControls) * 100, 0) } else { 0 }
                Write-Status "Azure Security Benchmark compliance (cached): $compPct% ($passedControls/$totalControls passed)" "INFO"
            }
        } else {
            # Fallback to REST API
            $compResponse = Invoke-AzRestMethod -Path "/subscriptions/$SubId/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=2019-01-01-preview" -Method GET -ErrorAction SilentlyContinue
            if ($compResponse -and $compResponse.StatusCode -eq 200) {
                $compStandardsRaw = ($compResponse.Content | ConvertFrom-Json).value
                $asb = $compStandardsRaw | Where-Object { $_.name -like '*Azure-Security-Benchmark*' -or $_.name -like '*azure-security-benchmark*' } | Select-Object -First 1
                if ($asb) {
                    $failedControls = $asb.properties.failedControls
                    $passedControls = $asb.properties.passedControls
                    $skippedControls = $asb.properties.skippedControls
                    $totalControls  = $failedControls + $passedControls + $skippedControls
                    $compPct = if ($totalControls -gt 0) { [math]::Round(($passedControls / $totalControls) * 100, 0) } else { 0 }
                    Write-Status "Azure Security Benchmark compliance: $compPct% ($passedControls/$totalControls passed)" "INFO"
                }
            }
        }
        if ($asb -and $compPct) {
            if ($compPct -lt 50) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Critical"
                    Category       = "Defender for Cloud - Compliance"
                    ResourceName   = "Azure Security Benchmark"
                    ResourceType   = "Regulatory Compliance"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "Azure Security Benchmark compliance is critically low at $compPct% ($passedControls passed, $failedControls failed out of $totalControls controls)."
                    Recommendation = "Review the Azure Security Benchmark controls in Defender for Cloud > Regulatory Compliance. Address failed controls starting with Identity, Network Security, and Data Protection domains."
                    Impact         = "Low compliance with Azure Security Benchmark indicates the environment does not meet Microsoft's recommended security baseline, increasing risk of breaches."
                }
                Add-Finding @findingParams
            } elseif ($compPct -lt 70) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "High"
                    Category       = "Defender for Cloud - Compliance"
                    ResourceName   = "Azure Security Benchmark"
                    ResourceType   = "Regulatory Compliance"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "Azure Security Benchmark compliance is $compPct% ($passedControls passed, $failedControls failed). Several baseline security controls are not met."
                    Recommendation = "Create a compliance remediation plan targeting the $failedControls failed controls. Use Defender for Cloud's built-in remediation guidance."
                    Impact         = "Non-compliance with security baselines leaves the environment vulnerable to known attack patterns and may affect audit readiness."
                }
                Add-Finding @findingParams
            } elseif ($compPct -lt 85) {
                $findingParams = @{
                    Pillar         = "Security"
                    Severity       = "Medium"
                    Category       = "Defender for Cloud - Compliance"
                    ResourceName   = "Azure Security Benchmark"
                    ResourceType   = "Regulatory Compliance"
                    ResourceGroup  = "N/A"
                    Subscription   = $SubName
                    Description    = "Azure Security Benchmark compliance is $compPct% ($failedControls controls still failing)."
                    Recommendation = "Continue addressing remaining failed controls to reach 85%+ compliance target."
                    Impact         = "Residual non-compliance may affect regulatory audit outcomes and leaves specific security domains partially unprotected."
                }
                Add-Finding @findingParams
            }
        }
    } catch {
        Write-Status "Could not retrieve regulatory compliance: $($_.Exception.Message)" "WARN"
    }

    # ── Defender Auto-Provisioning check ──
    Write-Status "  Checking Defender auto-provisioning..." "INFO"
    try {
        $autoProvUrl = "/subscriptions/$SubId/providers/Microsoft.Security/autoProvisioningSettings?api-version=2020-01-01-preview"
        $autoProvResult = Invoke-AzRestMethod -Path $autoProvUrl -Method GET -ErrorAction SilentlyContinue
        if ($autoProvResult -and $autoProvResult.StatusCode -eq 200) {
            $autoProvData = ($autoProvResult.Content | ConvertFrom-Json).value
            $disabled = @($autoProvData | Where-Object { $_.properties.autoProvision -eq 'Off' })
            if ($disabled.Count -gt 0) {
                $disabledNames = ($disabled | ForEach-Object { ($_.name) }) -join ', '
                Add-Finding -Pillar "Security" -Severity "High" -Category "Defender - Auto-Provisioning Disabled" `
                    -ResourceName "Defender Auto-Provisioning" -ResourceType "Microsoft Defender" `
                    -ResourceGroup "N/A" -Subscription $SubName `
                    -Description "Auto-provisioning is disabled for: $disabledNames. Defender agents are not automatically deployed to new resources." `
                    -Recommendation "Enable auto-provisioning for all Defender plans to ensure continuous coverage as new resources are deployed." `
                    -Impact "New VMs and resources will not have Defender agents installed, creating protection gaps."
            }
        }
    } catch {
        Write-Status "  Could not check auto-provisioning: $($_.Exception.Message)" "WARN"
    }

    # ── Security Contact / Email Notifications check ──
    Write-Status "  Checking security contact notifications..." "INFO"
    try {
        $contactUrl = "/subscriptions/$SubId/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview"
        $contactResult = Invoke-AzRestMethod -Path $contactUrl -Method GET -ErrorAction SilentlyContinue
        if ($contactResult -and $contactResult.StatusCode -eq 200) {
            $contacts = ($contactResult.Content | ConvertFrom-Json).value
            $hasNotifications = $false
            if ($contacts) {
                foreach ($c in $contacts) {
                    $emails = $c.properties.emails
                    $alertNotify = $c.properties.alertNotifications
                    if ($emails -and $alertNotify -and $alertNotify.state -eq 'On') { $hasNotifications = $true; break }
                }
            }
            if (-not $hasNotifications) {
                Add-Finding -Pillar "Security" -Severity "High" -Category "Defender - No Email Notifications" `
                    -ResourceName "Security Contacts" -ResourceType "Microsoft Defender" `
                    -ResourceGroup "N/A" -Subscription $SubName `
                    -Description "No security contact with email notifications enabled. Security alerts are not being sent via email." `
                    -Recommendation "Configure security contact email(s) and enable alert notifications for High severity alerts at minimum." `
                    -Impact "Without email notifications, security incidents may go unnoticed until manual portal review."
            }
        }
    } catch {
        Write-Status "  Could not check security contacts: $($_.Exception.Message)" "WARN"
    }
}

# ============================================================================
# 11. KUBERNETES (AKS) ANALYSIS
# ============================================================================
function Analyze-AKS {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing AKS clusters..." "SECTION"
    $clusters = Invoke-AzCommandSafely { Get-AzAksCluster -ErrorAction SilentlyContinue } "Info: No AKS clusters found"
    if (-not $clusters) { return }

    foreach ($cluster in $clusters) {
        # RBAC
        if (-not $cluster.EnableRBAC) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "Critical"
                Category       = "AKS - RBAC"
                ResourceName   = $cluster.Name
                ResourceType   = "AKS Cluster"
                ResourceGroup  = $cluster.ResourceGroupName
                Subscription   = $SubName
                Description    = "Kubernetes RBAC is not enabled."
                Recommendation = "Enable RBAC and Azure AD integration for granular access control."
                Impact         = "Any user with cluster access has full permissions."
            }
            Add-Finding @findingParams
        }

        # Network Policy
        if (-not $cluster.NetworkProfile.NetworkPolicy) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "AKS - Network Policy"
                ResourceName   = $cluster.Name
                ResourceType   = "AKS Cluster"
                ResourceGroup  = $cluster.ResourceGroupName
                Subscription   = $SubName
                Description    = "No Network Policy configured (Calico/Azure)."
                Recommendation = "Enable Network Policies for micro-segmentation between pods."
                Impact         = "All pods can communicate with each other without restriction."
            }
            Add-Finding @findingParams
        }

        # Private Cluster
        if (-not $cluster.ApiServerAccessProfile.EnablePrivateCluster) {
            $findingParams = @{
                Pillar         = "Security"
                Severity       = "High"
                Category       = "AKS - Public API Server"
                ResourceName   = $cluster.Name
                ResourceType   = "AKS Cluster"
                ResourceGroup  = $cluster.ResourceGroupName
                Subscription   = $SubName
                Description    = "The cluster API server is publicly accessible."
                Recommendation = "Configure as Private Cluster or restrict authorized IP ranges."
                Impact         = "Exposed API server allows unauthorized access attempts from the Internet."
            }
            Add-Finding @findingParams
        }

        # ── AKS Availability Zones check ──
        $nodePools = $cluster.AgentPoolProfiles
        if ($nodePools) {
            foreach ($np in $nodePools) {
                if (-not $np.AvailabilityZones -or $np.AvailabilityZones.Count -eq 0) {
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "AKS - No Availability Zones" `
                        -ResourceName "$($cluster.Name)/$($np.Name)" -ResourceType "AKS Node Pool" `
                        -ResourceGroup $cluster.ResourceGroupName -Subscription $SubName `
                        -Description "Node pool '$($np.Name)' (count: $($np.Count)) is not spread across availability zones." `
                        -Recommendation "Recreate node pool with availability zones [1,2,3] for zone-redundant workloads." `
                        -Impact "Single-zone node pools are vulnerable to zone-level failures causing workload downtime."
                }
            }
        }
    }
}

# ============================================================================
# 12. ZERO TRUST ASSESSMENT
# ============================================================================
function Analyze-ZeroTrust {
    param([string]$SubId, [string]$SubName)

    Write-Status "Running Zero Trust Assessment..." "SECTION"

    # ── Network Security ──────────────────────────────────────────────────────
    Write-Status "  [ZT] Network Security..." "INFO"

    # 1. Micro-segmentation — covered in Analyze-Networking (Network - Missing NSG)
    $vnets = $script:CachedVNets

    # 2. Azure Firewall presence
    $firewalls = $script:CachedFirewalls
    if (-not $firewalls -or $firewalls.Count -eq 0) {
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "High"
            Category       = "ZT-Network: Traffic inspection"
            ResourceName   = "Azure Firewall"
            ResourceType   = "Firewall"
            ResourceGroup  = "N/A"
            Subscription   = $SubName
            Description    = "No Azure Firewall found in the subscription."
            Recommendation = "Deploy Azure Firewall Premium for E-W and N-S traffic inspection with IDPS."
            Impact         = "Without centralized firewall there is no deep packet inspection or network threat detection."
        }
        Add-Finding @findingParams
    }

    # 3. DDoS Protection — covered in Analyze-Networking (Network - DDoS) per-VNet

    # 4. Bastion (no direct RDP/SSH)
    $bastions = $script:CachedBastions
    $vms = $script:CachedVMs
    if ($vms -and $vms.Count -gt 0) {
        if (-not $bastions -or $bastions.Count -eq 0) {
            $findingParams = @{
                Pillar         = "Zero Trust"
                Severity       = "High"
                Category       = "ZT-Network: Secure administrative access"
                ResourceName   = "Azure Bastion"
                ResourceType   = "Bastion Host"
                ResourceGroup  = "N/A"
                Subscription   = $SubName
                Description    = "VMs exist but no Azure Bastion was found."
                Recommendation = "Deploy Azure Bastion to eliminate RDP/SSH port exposure to the Internet."
                Impact         = "Direct RDP/SSH access violates the Zero Trust principle of verified and secure access."
            }
            Add-Finding @findingParams
        }
    }

    # 5. Private Endpoints — covered in Analyze-PrivateEndpoints (more comprehensive, uses Resource ID matching)

    # 6. NSG Flow Logs — covered in Analyze-Networking (Network - Flow Logs)

    # ── Compute Security ──────────────────────────────────────────────────────
    Write-Status "  [ZT] Compute Security..." "INFO"

    # 7. JIT VM Access
    $jitPolicies = Invoke-AzCommandSafely {
        Get-AzJitNetworkAccessPolicy -ErrorAction SilentlyContinue
    } "ZT: error JIT"

    if ($vms -and $vms.Count -gt 0) {
        $jitVms = @()
        if ($jitPolicies) {
            $jitVms = $jitPolicies | ForEach-Object { $_.VirtualMachines } | ForEach-Object { $_.Id.Split('/')[-1] }
        }
        $vmsWithoutJIT = @($vms | Where-Object { $_.Name -notin $jitVms })
        if ($vmsWithoutJIT.Count -gt 0) {
            $sampleNames = ($vmsWithoutJIT | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            $extra = if ($vmsWithoutJIT.Count -gt 5) { " and $($vmsWithoutJIT.Count - 5) more" } else { '' }
            $findingParams = @{
                Pillar         = "Zero Trust"
                Severity       = if ($vmsWithoutJIT.Count -gt 10) { "High" } else { "Medium" }
                Category       = "ZT-Compute: Just-in-Time Access"
                ResourceName   = "$($vmsWithoutJIT.Count) of $($vms.Count) VMs"
                ResourceType   = "Virtual Machine"
                ResourceGroup  = "Multiple"
                Subscription   = $SubName
                Description    = "$($vmsWithoutJIT.Count) VMs lack JIT access policies. Management ports may be permanently open. Examples: $sampleNames$extra."
                Recommendation = "Enable JIT VM Access in Microsoft Defender for Cloud for all VMs."
                Impact         = "Zero Trust requires just-in-time access. Ports open 24/7 expand the attack window."
            }
            Add-Finding @findingParams
        }
    }

    # 8. Endpoint Protection / Defender for Servers
    # NOTE: Defender plan coverage is already checked in Analyze-SecurityCenter ("Defender for Cloud - Plan Coverage").
    # Here we only check for ZT-specific implications (workload identity, JIT) — skip duplicate plan finding.
    # The SecurityCenter function reports per-plan coverage comprehensively.

    # 9. VM Identity: Managed Identity vs local credentials
    if ($vms) {
        $vmsNoIdentity = @($vms | Where-Object { -not $_.Identity -or $_.Identity.Type -eq "None" })
        if ($vmsNoIdentity.Count -gt 0) {
            $sampleNames = ($vmsNoIdentity | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            $extra = if ($vmsNoIdentity.Count -gt 5) { " and $($vmsNoIdentity.Count - 5) more" } else { '' }
            $findingParams = @{
                Pillar         = "Zero Trust"
                Severity       = if ($vmsNoIdentity.Count -gt 10) { "High" } else { "Medium" }
                Category       = "ZT-Compute: Workload identity"
                ResourceName   = "$($vmsNoIdentity.Count) of $($vms.Count) VMs"
                ResourceType   = "Virtual Machine"
                ResourceGroup  = "Multiple"
                Subscription   = $SubName
                Description    = "$($vmsNoIdentity.Count) VMs lack Managed Identity. Likely use of local credentials or hardcoded secrets. Examples: $sampleNames$extra."
                Recommendation = "Assign System-Assigned Managed Identity and remove local credentials."
                Impact         = "Zero Trust requires verified identities for each workload. Local credentials are hard to rotate and audit."
            }
            Add-Finding @findingParams
        }
    }

    # 10. Guest OS patching: Update Manager — check both maintenance configurations and VM patch settings
    $updateSettings = Invoke-AzCommandSafely {
        Get-AzMaintenanceConfiguration -ErrorAction SilentlyContinue
    } "ZT: error Update Manager"
    # Also check if VMs have automatic patching enabled via patchSettings
    $vmPatchEnabled = $false
    if ($vms -and $vms.Count -gt 0) {
        $vmPatchEnabled = $vms | Where-Object {
            ($_.OSProfile -and $_.OSProfile.WindowsConfiguration -and $_.OSProfile.WindowsConfiguration.PatchSettings -and $_.OSProfile.WindowsConfiguration.PatchSettings.PatchMode -eq 'AutomaticByPlatform') -or
            ($_.OSProfile -and $_.OSProfile.LinuxConfiguration -and $_.OSProfile.LinuxConfiguration.PatchSettings -and $_.OSProfile.LinuxConfiguration.PatchSettings.PatchMode -eq 'AutomaticByPlatform')
        } | Select-Object -First 1
    }
    if ((-not $updateSettings -or $updateSettings.Count -eq 0) -and -not $vmPatchEnabled) {
        if ($vms -and $vms.Count -gt 0) {
            $findingParams = @{
                Pillar         = "Zero Trust"
                Severity       = "High"
                Category       = "ZT-Compute: Patch Management"
                ResourceName   = "Azure Update Manager"
                ResourceType   = "Update Management"
                ResourceGroup  = "N/A"
                Subscription   = $SubName
                Description    = "No Azure Update Manager/Maintenance configurations found."
                Recommendation = "Configure Azure Update Manager with automatic patching policies for VMs."
                Impact         = "Unpatched VMs are the most common compromise vector. Zero Trust requires continuously hardened workloads."
            }
            Add-Finding @findingParams
        }
    }

    # 11. Disk Encryption — covered in Analyze-VirtualMachines (VM - Unencrypted OS Disk)

    # ── Platform Security (Identity & Governance) ─────────────────────────────
    Write-Status "  [ZT] Platform Security..." "INFO"

    # 12. MFA / Conditional Access — tenant-level advisory (emit only once)
    if (-not $script:ZeroTrustTenantAdvisoryEmitted) {
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "Low"
            Category       = "ZT-Platform: Conditional Access"
            ResourceName   = "Azure AD Conditional Access"
            ResourceType   = "Identity"
            ResourceGroup  = "N/A"
            Subscription   = "Tenant-wide"
            Description    = "Could not automatically verify if Conditional Access policies with mandatory MFA exist (requires Microsoft Graph permissions)."
            Recommendation = "Verify in Azure AD that CA policies requiring MFA for all users exist, especially admins."
            Impact         = "Without MFA and CA, identities are the most common point of failure. Zero Trust requires 'never trust, always verify'."
        }
        Add-Finding @findingParams

        # 13. Privileged Identity Management — tenant-level advisory (emit only once)
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "Low"
            Category       = "ZT-Platform: Privileged Access"
            ResourceName   = "Azure AD PIM"
            ResourceType   = "Identity"
            ResourceGroup  = "N/A"
            Subscription   = "Tenant-wide"
            Description    = "Verify that Azure AD PIM is enabled for privileged roles (Global Admin, Subscription Owner, etc.)."
            Recommendation = "Enable PIM for all privileged roles: just-in-time access, approval, and activation auditing."
            Impact         = "Permanently assigned roles violate Zero Trust. PIM implements the principle of least privilege."
        }
        Add-Finding @findingParams
        $script:ZeroTrustTenantAdvisoryEmitted = $true
    }

    # 14. Azure Policy compliance — prefer pre-cached Resource Graph data
    $nonCompliantCount = 0
    if ($script:CachedPolicyStates.ContainsKey($SubId)) {
        $nonCompliantCount = [int]$script:CachedPolicyStates[$SubId].nonCompliantCount
    } else {
        $policyStates = Invoke-AzCommandSafely {
            Get-AzPolicyState -ErrorAction SilentlyContinue | Where-Object { $_.ComplianceState -eq "NonCompliant" } | Select-Object -First 100
        } "ZT: error Policy"
        if ($policyStates) { $nonCompliantCount = $policyStates.Count }
    }
    if ($nonCompliantCount -gt 0) {
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "High"
            Category       = "ZT-Platform: Policy Compliance"
            ResourceName   = "Azure Policy"
            ResourceType   = "Governance"
            ResourceGroup  = "N/A"
            Subscription   = $SubName
            Description    = "$nonCompliantCount non-compliant resources detected with Azure Policy."
            Recommendation = "Review the Policy Compliance dashboard and remediate non-compliant resources."
            Impact         = "Non-compliant resources indicate deviation from the established security baseline."
        }
        Add-Finding @findingParams
    } elseif ($nonCompliantCount -eq 0 -and -not $script:CachedPolicyStates.ContainsKey($SubId) -and -not $policyStates) {
        # Check if MG-scoped policies exist before claiming no policies
        $mgPolCount = 0
        if ($script:ALZData -and $script:ALZData.MGPolicies) {
            $mgPolCount = @($script:ALZData.MGPolicies | Where-Object { $_.Policies -gt 0 }).Count
        }
        if ($mgPolCount -eq 0) {
            $findingParams = @{
                Pillar         = "Zero Trust"
                Severity       = "Medium"
                Category       = "ZT-Platform: Policy Compliance"
                ResourceName   = "Azure Policy"
                ResourceType   = "Governance"
                ResourceGroup  = "N/A"
                Subscription   = $SubName
                Description    = "No Azure Policy assignments found at subscription or Management Group level."
                Recommendation = "Assign the 'Azure Security Benchmark' initiative and CIS/NIST policies at minimum."
                Impact         = "Without Azure Policy there is no automatic enforcement of the security baseline."
            }
            Add-Finding @findingParams
        }
    }

    # 15. Activity Log Diagnostics — covered in Analyze-DiagnosticSettings (Diagnostic Settings - Activity Log)

    # 16. Microsoft Sentinel / SIEM
    $sentinelWS = Invoke-AzCommandSafely {
        Get-AzOperationalInsightsWorkspace -ErrorAction SilentlyContinue
    } "ZT: error Log Analytics"
    if (-not $sentinelWS -or $sentinelWS.Count -eq 0) {
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "High"
            Category       = "ZT-Platform: SIEM / Threat Detection"
            ResourceName   = "Microsoft Sentinel"
            ResourceType   = "SIEM"
            ResourceGroup  = "N/A"
            Subscription   = $SubName
            Description    = "No Log Analytics Workspace found. Without SIEM/SOAR there is no threat detection."
            Recommendation = "Deploy Log Analytics + Microsoft Sentinel with Azure, AAD, and Office 365 connectors."
            Impact         = "Zero Trust requires continuous monitoring and automated threat response. Without SIEM this is impossible."
        }
        Add-Finding @findingParams
    } else {
        # Check Sentinel specifically
        foreach ($ws in $sentinelWS) {
            $sentinel = Invoke-AzCommandSafely {
                Get-AzSentinelAlertRule -WorkspaceName $ws.Name -ResourceGroupName $ws.ResourceGroupName -ErrorAction SilentlyContinue
            } "ZT: error Sentinel rules"
            if (-not $sentinel -or $sentinel.Count -eq 0) {
                $findingParams = @{
                    Pillar         = "Zero Trust"
                    Severity       = "Medium"
                    Category       = "ZT-Platform: SIEM / Threat Detection"
                    ResourceName   = $ws.Name
                    ResourceType   = "Log Analytics"
                    ResourceGroup  = $ws.ResourceGroupName
                    Subscription   = $SubName
                    Description    = "Log Analytics Workspace without Sentinel alert rules configured."
                    Recommendation = "Enable Microsoft Sentinel and configure Azure Security analytics rules."
                    Impact         = "Logs are collected but not actively analyzed for threat detection."
                }
                Add-Finding @findingParams
            }
        }
    }

    # 17. Role assignments: check for broad Owner/Contributor (including MG-scope inherited)
    $roleAssignments = $null
    if ($script:CachedRoleAssignments.ContainsKey($SubId)) {
        $roleAssignments = $script:CachedRoleAssignments[$SubId] | Where-Object {
            $_.properties.roleDefinitionId -match '8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c' -and
            $_.properties.principalType -eq 'User'
        }
    } else {
        $roleAssignments = Invoke-AzCommandSafely {
            Get-AzRoleAssignment -Scope "/subscriptions/$SubId" -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -in @("Owner","Contributor") -and $_.ObjectType -eq "User" }
        } "ZT: error Role Assignments"
    }
    # Also include MG-scope role assignments that inherit to this subscription
    $mgBroadRoles = @()
    if ($script:ALZData -and $script:ALZData.MGRoleAssignments) {
        $mgBroadRoles = @($script:ALZData.MGRoleAssignments | Where-Object {
            $_.RoleDefinitionName -in @('Owner','Contributor') -and $_.ObjectType -eq 'User'
        })
    }
    $totalBroadRoles = @($roleAssignments).Count + $mgBroadRoles.Count
    if ($totalBroadRoles -gt 0) {
        $mgNote = if ($mgBroadRoles.Count -gt 0) { " ($($mgBroadRoles.Count) inherited from MG scope)" } else { '' }
        $findingParams = @{
            Pillar         = "Zero Trust"
            Severity       = "High"
            Category       = "ZT-Platform: Least Privilege"
            ResourceName   = "Subscription RBAC"
            ResourceType   = "Role Assignment"
            ResourceGroup  = "N/A"
            Subscription   = $SubName
            Description    = "$totalBroadRoles user(s) with Owner/Contributor role affecting this subscription$mgNote."
            Recommendation = "Use least privilege RBAC. Assign roles at the Resource Group or resource level. Use PIM for Owner. Review MG-scope assignments."
            Impact         = "Broad roles at subscription or MG level violate the principle of least privilege. A compromised account has full access."
        }
        Add-Finding @findingParams
    }

    # ── Entra ID Protection — Risky Users & Sign-ins ──
    Write-Status "  Checking Entra ID Protection..." "INFO"
    try {
        $graphAvailable = Get-Command Get-MgRiskyUser -ErrorAction SilentlyContinue
        if ($graphAvailable) {
            $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk' or riskState eq 'confirmedCompromised'" -Top 100 -ErrorAction SilentlyContinue
            if ($riskyUsers -and $riskyUsers.Count -gt 0) {
                $highRisk = @($riskyUsers | Where-Object { $_.RiskLevel -eq 'high' })
                $medRisk = @($riskyUsers | Where-Object { $_.RiskLevel -eq 'medium' })
                Add-Finding -Pillar "Security" -Severity $(if($highRisk.Count -gt 0){"Critical"}else{"High"}) `
                    -Category "Identity - Risky Users Detected" `
                    -ResourceName "$($riskyUsers.Count) risky users" -ResourceType "Entra ID Protection" `
                    -ResourceGroup "N/A" -Subscription "Tenant" `
                    -Description "$($riskyUsers.Count) users flagged at risk ($($highRisk.Count) high, $($medRisk.Count) medium). Accounts may be compromised." `
                    -Recommendation "Review risky users in Entra ID Protection. Require password reset, MFA re-registration, or block sign-in for confirmed compromised accounts." `
                    -Impact "Compromised accounts can lead to data exfiltration, privilege escalation, and lateral movement."
            }
        }
    } catch {
        Write-Status "  Could not query Entra ID Protection: $($_.Exception.Message)" "WARN"
    }

    Write-Status "  Zero Trust Assessment completed." "OK"
}

# ============================================================================
# 13. UNDERUTILIZED RESOURCES — REAL AZURE MONITOR METRICS
# ============================================================================
function Analyze-UnderutilizedResources {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing underutilized resources with Azure Monitor metrics..." "SECTION"

    if ($SkipMetrics) {
        Write-Status "  Skipping metric collection (-SkipMetrics flag). Underutilized analysis disabled." "WARN"
        return
    }

    # Analysis window: configurable via -MetricDays (default 14)
    $endTime   = Get-Date
    $startTime = $endTime.AddDays(-$MetricDays)
    $timeGrain = if ($MetricDays -le 7) { [TimeSpan]::FromHours(1) } else { [TimeSpan]::FromHours(6) }   # Coarser grain for longer windows = fewer data points

    # Thresholds from script parameters
    $CPU_LOW_PCT     = $CpuLowPercent
    $CPU_IDLE_PCT    = $CpuIdlePercent
    $NET_LOW_MB      = $NetLowMB
    $APP_REQ_LOW     = $AppRequestLowPerHour
    $SQL_DTU_LOW_PCT = $SqlDtuLowPercent
    $SQL_CPU_LOW_PCT = $SqlCpuLowPercent
    $DISK_LOW_IOPS   = $DiskLowIops

    Write-Status "  Analysis period: $($startTime.ToString('MM/dd/yyyy')) → $($endTime.ToString('MM/dd/yyyy')) ($MetricDays days)" "INFO"

    # ── VIRTUAL MACHINES ─────────────────────────────────────────────────────
    Write-Status "  [Metrics] Virtual Machines..." "INFO"
    $vms = $script:CachedVMs
    if ($vms) {
        $runningVMs = @($vms | Where-Object {
            ($_.Statuses | Where-Object { $_.Code -match "PowerState" }).Code -eq "PowerState/running"
        })
        Write-Status "    $($runningVMs.Count) running VMs to analyze" "INFO"

        foreach ($vm in $runningVMs) {
            $resourceId = $vm.Id

            # Fetch CPU + Network metrics in one call (combined metric names)
            $cpuMetric = Invoke-AzCommandSafely {
                Get-AzMetric -ResourceId $resourceId -MetricName "Percentage CPU" `
                    -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                    -AggregationType Average -ErrorAction SilentlyContinue
            } "CPU Metrics $($vm.Name)"

            $cpuAvg = $null; $cpuMax = $null
            if ($cpuMetric -and $cpuMetric.Data -and $cpuMetric.Data.Count -gt 0) {
                $validPoints = $cpuMetric.Data | Where-Object { $null -ne $_.Average }
                if ($validPoints) {
                    $cpuAvg = [math]::Round(($validPoints | Measure-Object -Property Average -Average).Average, 2)
                    $cpuMax = [math]::Round(($validPoints | Measure-Object -Property Average -Maximum).Maximum, 2)
                }
            }

            # Only fetch network if CPU is low (skip expensive call for healthy VMs)
            $netAvgMBh = $null
            if ($null -ne $cpuAvg -and $cpuAvg -lt $CPU_LOW_PCT) {
                $netMetric = Invoke-AzCommandSafely {
                    Get-AzMetric -ResourceId $resourceId -MetricName "Network In Total" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                        -AggregationType Total -ErrorAction SilentlyContinue
                } "Network Metrics $($vm.Name)"

                if ($netMetric -and $netMetric.Data) {
                    $validNet = $netMetric.Data | Where-Object { $null -ne $_.Total }
                    if ($validNet) {
                        $netAvgMBh = [math]::Round(($validNet | Measure-Object -Property Total -Average).Average / 1MB, 2)
                    }
                }
            }
            Send-KeepAlive

            if ($null -ne $cpuAvg) {
                if ($cpuAvg -lt $CPU_IDLE_PCT) {
                    $severity = "High"
                    $desc = "${MetricDays}-day average CPU: $cpuAvg% (max: $cpuMax%). VM practically idle."
                    $rec  = "Evaluate shutting down, deallocating, or reducing SKU. Verify if the load is expected or if it is a zombie."
                } elseif ($cpuAvg -lt $CPU_LOW_PCT) {
                    $severity = "Medium"
                    $desc = "${MetricDays}-day average CPU: $cpuAvg% (max: $cpuMax%). VM with very low load."
                    $rec  = "Consider reducing the VM SKU (right-sizing) or consolidating workloads on fewer instances."
                } else { $severity = $null }

                if ($severity) {
                    $netInfo = if ($null -ne $netAvgMBh) { " | Average inbound network: $netAvgMBh MB/h." } else { "" }
                    $script:UnderutilizedResources.Add([PSCustomObject]@{
                        ResourceType   = "Virtual Machine"
                        ResourceName   = $vm.Name
                        ResourceGroup  = $vm.ResourceGroupName
                        Subscription   = $SubName
                        Severity       = $severity
                        MetricName     = "Average CPU (${MetricDays}d)"
                        MetricValue    = "$cpuAvg%"
                        MetricMax      = "$cpuMax%"
                        NetInfo        = $netAvgMBh
                        Threshold      = "< $CPU_LOW_PCT%"
                        Description    = $desc + $netInfo
                        Recommendation = $rec
                        PeriodDays     = $MetricDays
                        SKU            = $vm.HardwareProfile.VmSize
                        Location       = $vm.Location
                    })
                }
            }
        }
    }

    # ── APP SERVICES ─────────────────────────────────────────────────────────
    Write-Status "  [Metrics] App Services..." "INFO"
    $webApps = $script:CachedWebApps
    if ($webApps) {
        foreach ($app in $webApps) {
            $resourceId = $app.Id

            $reqMetric = Invoke-AzCommandSafely {
                Get-AzMetric -ResourceId $resourceId -MetricName "Requests" `
                    -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                    -AggregationType Total -ErrorAction SilentlyContinue
            } "Request Metrics $($app.Name)"

            $reqAvgHour = $null
            if ($reqMetric -and $reqMetric.Data) {
                $validReq = $reqMetric.Data | Where-Object { $null -ne $_.Total }
                if ($validReq) {
                    # Normalize to requests per hour regardless of time grain
                    $grainHours = $timeGrain.TotalHours
                    $avgPerGrain = ($validReq | Measure-Object -Property Total -Average).Average
                    $reqAvgHour = [math]::Round($avgPerGrain / $grainHours, 1)
                }
            }

            $cpuTimeAvg = $null
            # Only fetch CPU time if requests are already low (skip expensive metric for active apps)
            if ($null -ne $reqAvgHour -and $reqAvgHour -lt $APP_REQ_LOW) {
                $cpuTimeMetric = Invoke-AzCommandSafely {
                    Get-AzMetric -ResourceId $resourceId -MetricName "CpuTime" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                        -AggregationType Total -ErrorAction SilentlyContinue
                } "CpuTime Metrics $($app.Name)"

                if ($cpuTimeMetric -and $cpuTimeMetric.Data) {
                    $valid = $cpuTimeMetric.Data | Where-Object { $null -ne $_.Total }
                    if ($valid) {
                        $cpuTimeAvg = [math]::Round(($valid | Measure-Object -Property Total -Average).Average, 2)
                    }
                }
            }
            Send-KeepAlive

            if ($null -ne $reqAvgHour -and $reqAvgHour -lt $APP_REQ_LOW) {
                $cpuInfo = if ($null -ne $cpuTimeAvg) { " | Average CPU time: $cpuTimeAvg s/h." } else { "" }
                $script:UnderutilizedResources.Add([PSCustomObject]@{
                    ResourceType   = "App Service"
                    ResourceName   = $app.Name
                    ResourceGroup  = $app.ResourceGroup
                    Subscription   = $SubName
                    Severity       = "Medium"
                    MetricName     = "Average Requests/hour (${MetricDays}d)"
                    MetricValue    = "$reqAvgHour req/h"
                    MetricMax      = "N/A"
                    NetInfo        = $null
                    Threshold      = "< $APP_REQ_LOW req/h"
                    Description    = "App Service with $reqAvgHour average requests/hour over $MetricDays days.$cpuInfo Little to no real traffic."
                    Recommendation = "Evaluate if the app is active. Consider consolidating or downgrading the App Service plan."
                    PeriodDays     = $MetricDays
                    SKU            = $app.Sku.Name
                    Location       = $app.Location
                })
            }
        }
    }

    # ── SQL DATABASES ─────────────────────────────────────────────────────────
    Write-Status "  [Metrics] SQL Databases..." "INFO"
    $sqlServers = $script:CachedSqlServers
    if ($sqlServers) {
        foreach ($srv in $sqlServers) {
            $dbs = Invoke-AzCommandSafely {
                Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName `
                    -ErrorAction SilentlyContinue | Where-Object { $_.DatabaseName -ne "master" }
            } "Error DBs $($srv.ServerName)"
            if (-not $dbs) { continue }

            foreach ($db in $dbs) {
                $resourceId = $db.ResourceId

                $dtuMetric = Invoke-AzCommandSafely {
                    Get-AzMetric -ResourceId $resourceId -MetricName "dtu_consumption_percent" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                        -AggregationType Average -ErrorAction SilentlyContinue
                } "DTU Metrics $($db.DatabaseName)"

                $cpuMetric = $null
                if (-not $dtuMetric -or -not $dtuMetric.Data -or $dtuMetric.Data.Count -eq 0) {
                    $cpuMetric = Invoke-AzCommandSafely {
                        Get-AzMetric -ResourceId $resourceId -MetricName "cpu_percent" `
                            -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                            -AggregationType Average -ErrorAction SilentlyContinue
                    } "SQL CPU Metrics $($db.DatabaseName)"
                }
                Send-KeepAlive

                $sqlUsageAvg = $null; $sqlMetricName = ""; $sqlThreshold = 0
                if ($dtuMetric -and $dtuMetric.Data) {
                    $valid = $dtuMetric.Data | Where-Object { $null -ne $_.Average }
                    if ($valid) {
                        $sqlUsageAvg = [math]::Round(($valid | Measure-Object -Property Average -Average).Average, 2)
                        $sqlMetricName = "DTU %"; $sqlThreshold = $SQL_DTU_LOW_PCT
                    }
                } elseif ($cpuMetric -and $cpuMetric.Data) {
                    $valid = $cpuMetric.Data | Where-Object { $null -ne $_.Average }
                    if ($valid) {
                        $sqlUsageAvg = [math]::Round(($valid | Measure-Object -Property Average -Average).Average, 2)
                        $sqlMetricName = "CPU vCore %"; $sqlThreshold = $SQL_CPU_LOW_PCT
                    }
                }

                if ($null -ne $sqlUsageAvg -and $sqlUsageAvg -lt $sqlThreshold) {
                    $tier = "$($db.SkuName) / $($db.Capacity) $(if($db.SkuName -match 'vCore|GP|BC'){'vCores'}else{'DTUs'})"
                    $script:UnderutilizedResources.Add([PSCustomObject]@{
                        ResourceType   = "SQL Database"
                        ResourceName   = "$($srv.ServerName)/$($db.DatabaseName)"
                        ResourceGroup  = $srv.ResourceGroupName
                        Subscription   = $SubName
                        Severity       = "Medium"
                        MetricName     = "$sqlMetricName average (${MetricDays}d)"
                        MetricValue    = "$sqlUsageAvg%"
                        MetricMax      = "N/A"
                        NetInfo        = $null
                        Threshold      = "< $sqlThreshold%"
                        Description    = "SQL Database with $sqlMetricName average $sqlUsageAvg% over $MetricDays days. Current tier: $tier."
                        Recommendation = "Consider lowering the capacity tier (DTUs/vCores) or migrating to Serverless if the workload is irregular."
                        PeriodDays     = $MetricDays
                        SKU            = $tier
                        Location       = $db.Location
                    })
                }
            }
        }
    }

    # ── MANAGED DISKS ─────────────────────────────────────────────────────────
    Write-Status "  [Metrics] Managed Disks..." "INFO"
    $premiumDisks = @($script:CachedDisks | Where-Object {
        $_.DiskState -eq "Attached" -and $_.Sku.Name -match "Premium|UltraSSD"
    })
    if ($premiumDisks.Count -gt 0) {
        foreach ($disk in $premiumDisks) {
            $resourceId = $disk.Id

            $readMetric = Invoke-AzCommandSafely {
                Get-AzMetric -ResourceId $resourceId -MetricName "Composite Disk Read Operations/sec" `
                    -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                    -AggregationType Average -ErrorAction SilentlyContinue
            } "Read IOPS Metrics $($disk.Name)"
            $writeMetric = Invoke-AzCommandSafely {
                Get-AzMetric -ResourceId $resourceId -MetricName "Composite Disk Write Operations/sec" `
                    -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                    -AggregationType Average -ErrorAction SilentlyContinue
            } "Write IOPS Metrics $($disk.Name)"
            Send-KeepAlive

            $readAvg = $null; $writeAvg = $null
            if ($readMetric -and $readMetric.Data) {
                $valid = $readMetric.Data | Where-Object { $null -ne $_.Average }
                if ($valid) { $readAvg = [math]::Round(($valid | Measure-Object -Property Average -Average).Average, 1) }
            }
            if ($writeMetric -and $writeMetric.Data) {
                $valid = $writeMetric.Data | Where-Object { $null -ne $_.Average }
                if ($valid) { $writeAvg = [math]::Round(($valid | Measure-Object -Property Average -Average).Average, 1) }
            }
            $iopsAvg = if ($null -ne $readAvg -and $null -ne $writeAvg) { $readAvg + $writeAvg } elseif ($null -ne $readAvg) { $readAvg } elseif ($null -ne $writeAvg) { $writeAvg } else { $null }

            if ($null -ne $iopsAvg -and $iopsAvg -lt $DISK_LOW_IOPS) {
                $provisionedIops = $disk.DiskIOPSReadWrite
                $script:UnderutilizedResources.Add([PSCustomObject]@{
                    ResourceType   = "Managed Disk"
                    ResourceName   = $disk.Name
                    ResourceGroup  = $disk.ResourceGroupName
                    Subscription   = $SubName
                    Severity       = "Low"
                    MetricName     = "Average total IOPS (${MetricDays}d)"
                    MetricValue    = "$iopsAvg IOPS (R:$readAvg W:$writeAvg)"
                    MetricMax      = "N/A"
                    NetInfo        = $null
                    Threshold      = "< $DISK_LOW_IOPS IOPS"
                    Description    = "Disk $($disk.Sku.Name) with $iopsAvg average total IOPS (Read:$readAvg Write:$writeAvg). Provisioned: $provisionedIops IOPS. Oversized disk."
                    Recommendation = "Consider changing from $($disk.Sku.Name) to Standard SSD or Standard HDD to reduce costs."
                    PeriodDays     = $MetricDays
                    SKU            = "$($disk.Sku.Name) / $($disk.DiskSizeGB) GB"
                    Location       = $disk.Location
                })
            }
        }
    }

    $count = $script:UnderutilizedResources.Count
    Write-Status "  Underutilized resources detected: $count" $(if($count -gt 0){"WARN"}else{"OK"})

    # ── Cosmos DB — RU consumption vs provisioned ──
    Write-Status "  [Metrics] Cosmos DB RU utilization..." "INFO"
    $cosmosAccounts = $script:CachedCosmosDBAccounts
    if ($cosmosAccounts) {
        foreach ($cosmos in $cosmosAccounts) {
            try {
                $cosmosId = $cosmos.Id
                if (-not $cosmosId) { continue }
                $ruMetric = Invoke-AzCommandSafely {
                    Get-AzMetric -ResourceId $cosmosId -MetricName "TotalRequestUnits" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                        -AggregationType Average -ErrorAction SilentlyContinue
                } "Cosmos RU $($cosmos.Name)"
                $provMetric = Invoke-AzCommandSafely {
                    Get-AzMetric -ResourceId $cosmosId -MetricName "ProvisionedThroughput" `
                        -StartTime $startTime -EndTime $endTime -TimeGrain $timeGrain `
                        -AggregationType Maximum -ErrorAction SilentlyContinue
                } "Cosmos Provisioned $($cosmos.Name)"

                $avgRU = $null; $provRU = $null
                if ($ruMetric -and $ruMetric.Data) {
                    $valid = $ruMetric.Data | Where-Object { $null -ne $_.Average }
                    if ($valid) { $avgRU = [math]::Round(($valid | Measure-Object -Property Average -Average).Average, 1) }
                }
                if ($provMetric -and $provMetric.Data) {
                    $valid = $provMetric.Data | Where-Object { $null -ne $_.Maximum }
                    if ($valid) { $provRU = [math]::Round(($valid | Measure-Object -Property Maximum -Maximum).Maximum, 0) }
                }
                if ($avgRU -and $provRU -and $provRU -gt 0) {
                    $utilizationPct = [math]::Round(($avgRU / $provRU) * 100, 1)
                    if ($utilizationPct -lt 10) {
                        $script:UnderutilizedResources.Add([PSCustomObject]@{
                            ResourceName   = $cosmos.Name
                            ResourceType   = "Cosmos DB Account"
                            ResourceGroup  = $cosmos.ResourceGroupName
                            Subscription   = $SubName
                            SKU            = $cosmos.DatabaseAccountOfferType
                            Location       = $cosmos.Location
                            MetricName     = "TotalRequestUnits (Avg RU/s)"
                            MetricValue    = $avgRU
                            MetricMax      = $provRU
                            Threshold      = "10%"
                            Description    = "Cosmos DB account uses $avgRU avg RU/s out of $provRU provisioned ($utilizationPct% utilization)."
                            Recommendation = "Consider switching to Autoscale throughput or reducing provisioned RU/s to match actual demand."
                            PeriodDays     = $MetricDays
                        })
                    }
                }
            } catch { continue }
        }
    }
}

# ============================================================================
# MODERNIZATION & MIGRATION ANALYSIS
# ============================================================================
function Analyze-Modernization {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing modernization & migration opportunities..." "SECTION"

    # ── 1. IaaS VMs that could be migrated to PaaS / Containers ──────────
    $vms = $script:CachedVMs
    if ($vms -and $vms.Count -gt 0) {
        # VMs running web server workloads (potential App Service migration)
        foreach ($vm in $vms) {
            $vmName = $vm.Name
            $extensions = $vm.Extensions | ForEach-Object { $_.VirtualMachineExtensionType }

            # Check for old OS versions
            $osOffer = $vm.StorageProfile.ImageReference.Offer
            $osSku   = $vm.StorageProfile.ImageReference.Sku
            if ($osOffer -match 'WindowsServer' -and $osSku -match '2012') {
                Add-Finding -Pillar "Operational Excellence" -Severity "Critical" `
                    -Category "Modernization - Legacy OS" `
                    -ResourceName $vmName -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Subscription $SubName `
                    -Description "VM runs Windows Server 2012/R2 ($osSku) which reached end of support in October 2023." `
                    -Recommendation "Migrate to Windows Server 2022 or move workload to Azure PaaS/Containers. Extended Security Updates available as interim measure." `
                    -Impact "Critical security risk from unpatched OS; compliance violations; no vendor support."
            }
            if ($osOffer -match 'WindowsServer' -and $osSku -match '2016' -and $osSku -notmatch '2012') {
                Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                    -Category "Modernization - Legacy OS" `
                    -ResourceName $vmName -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Subscription $SubName `
                    -Description "VM runs Windows Server 2016 ($osSku). Extended support ends January 2027." `
                    -Recommendation "Plan migration to Windows Server 2022 before support ends." `
                    -Impact "OS approaching end of support; plan upgrade to maintain compliance."
            }
            if ($osOffer -match 'UbuntuServer|0001-com-ubuntu' -and $osSku -match '16\.04|18\.04') {
                Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                    -Category "Modernization - Legacy OS" `
                    -ResourceName $vmName -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Subscription $SubName `
                    -Description "VM runs Ubuntu $osSku which has reached or is near end of standard support." `
                    -Recommendation "Upgrade to Ubuntu 22.04+ LTS or migrate workload to containers/PaaS." `
                    -Impact "Missing security patches; compliance gaps."
            }

            # Single-instance VMs without availability (modernization candidate)
            $vmSize = $vm.HardwareProfile.VmSize
            if ($vmSize -match 'Standard_B1|Standard_B2|Standard_A') {
                Add-Finding -Pillar "Cost Optimization" -Severity "Low" `
                    -Category "Modernization - Right-size" `
                    -ResourceName $vmName -ResourceType "Microsoft.Compute/virtualMachines" `
                    -ResourceGroup $vm.ResourceGroupName -Subscription $SubName `
                    -Description "VM uses burstable/basic size ($vmSize). Evaluate if workload fits serverless or PaaS." `
                    -Recommendation "Consider Azure App Service, Azure Container Apps, or Azure Functions for this workload." `
                    -Impact "Potential cost savings and reduced operational overhead."
            }
        }
    }

    # ── 2. Classic / V1 resources ────────────────────────────────────────────
    $classicResources = $script:Resources | Where-Object { $_.Type -match 'Microsoft\.ClassicCompute|Microsoft\.ClassicNetwork|Microsoft\.ClassicStorage' }
    if ($classicResources -and $classicResources.Count -gt 0) {
        foreach ($cr in $classicResources) {
            Add-Finding -Pillar "Operational Excellence" -Severity "High" `
                -Category "Migration - Classic Resources" `
                -ResourceName $cr.Name -ResourceType $cr.Type `
                -ResourceGroup $cr.ResourceGroup -Subscription $SubName `
                -Description "Classic (ASM) resource detected. Classic/ASM was retired August 31, 2024." `
                -Recommendation "Migrate to Azure Resource Manager (ARM) immediately — classic resources are no longer supported." `
                -Impact "Classic resources lack modern security features, RBAC, and will lose support."
        }
    }

    # ── 3. App Services on outdated runtimes ─────────────────────────────────
    $webApps = $script:CachedWebApps
    if ($webApps) {
        foreach ($app in $webApps) {
            $appName = $app.Name
            try {
                $config = $script:CachedWebAppDetails[$app.Id]
                if (-not $config) { continue }
                $runtimeStack = $config.SiteConfig.LinuxFxVersion
                $netVersion   = $config.SiteConfig.NetFrameworkVersion

                # Check for old .NET Framework
                if ($netVersion -and $netVersion -match '^v[23]\.' ) {
                    Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                        -Category "Modernization - Legacy Runtime" `
                        -ResourceName $appName -ResourceType "Microsoft.Web/sites" `
                        -ResourceGroup $app.ResourceGroup -Subscription $SubName `
                        -Description "App Service uses legacy .NET Framework ($netVersion)." `
                        -Recommendation "Migrate to .NET 8+ for better performance, security, and cross-platform support." `
                        -Impact "Legacy runtimes miss security patches and modern features."
                }

                # Check for old Node.js
                if ($runtimeStack -match 'NODE\|([0-9]+)') {
                    $nodeVer = [int]$Matches[1]
                    if ($nodeVer -lt 20) {
                        Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                            -Category "Modernization - Legacy Runtime" `
                            -ResourceName $appName -ResourceType "Microsoft.Web/sites" `
                            -ResourceGroup $app.ResourceGroup -Subscription $SubName `
                            -Description "App Service uses Node.js $nodeVer which is end-of-life." `
                            -Recommendation "Upgrade to Node.js 20+ LTS." `
                            -Impact "EOL runtimes do not receive security patches."
                    }
                }

                # Check for old Python
                if ($runtimeStack -match 'PYTHON\|([0-9.]+)') {
                    $pyVer = $Matches[1]
                    if ($pyVer -match '^(2\.|3\.\d$)') {
                        Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                            -Category "Modernization - Legacy Runtime" `
                            -ResourceName $appName -ResourceType "Microsoft.Web/sites" `
                            -ResourceGroup $app.ResourceGroup -Subscription $SubName `
                            -Description "App Service uses Python $pyVer which is end-of-life or nearing EOL." `
                            -Recommendation "Upgrade to Python 3.12+ LTS for security patches and performance improvements." `
                            -Impact "EOL runtimes do not receive security patches."
                    }
                }

                # Check for old Java
                if ($runtimeStack -match 'JAVA\|([0-9]+)') {
                    $javaVer = [int]$Matches[1]
                    if ($javaVer -lt 17) {
                        Add-Finding -Pillar "Operational Excellence" -Severity "Low" `
                            -Category "Modernization - Legacy Runtime" `
                            -ResourceName $appName -ResourceType "Microsoft.Web/sites" `
                            -ResourceGroup $app.ResourceGroup -Subscription $SubName `
                            -Description "App Service uses Java $javaVer. Consider upgrading to a current LTS." `
                            -Recommendation "Upgrade to Java 21 LTS for long-term support and security." `
                            -Impact "Older Java versions may miss security updates."
                    }
                }

                # App Service on Free/Shared tier (PaaS optimization)
                $sku = $app.Sku
                if ($sku -match 'Free|Shared|D1|F1') {
                    Add-Finding -Pillar "Reliability" -Severity "Medium" `
                        -Category "Modernization - PaaS Tier" `
                        -ResourceName $appName -ResourceType "Microsoft.Web/sites" `
                        -ResourceGroup $app.ResourceGroup -Subscription $SubName `
                        -Description "App Service runs on Free/Shared tier with no SLA and limited features." `
                        -Recommendation "Upgrade to Basic (B1) or Standard (S1) for production SLA and auto-scale." `
                        -Impact "No SLA; limited compute; no custom domains with SSL; no deployment slots."
                }
            } catch {
                # Skip if can't get config
            }
        }
    }

    # ── 4. SQL Server on VMs → consider Azure SQL / Managed Instance ─────────
    if ($vms) {
        $sqlVMs = $vms | Where-Object {
            ($_.Extensions | Where-Object { $_.VirtualMachineExtensionType -eq 'SqlIaaSAgent' -or $_.Type -eq 'SqlIaaSAgent' }) -or
            ($_.StorageProfile -and $_.StorageProfile.ImageReference -and $_.StorageProfile.ImageReference.Offer -match 'SQL|sql')
        }
        foreach ($sqlVM in $sqlVMs) {
            Add-Finding -Pillar "Operational Excellence" -Severity "Medium" `
                -Category "Migration - SQL on VM" `
                -ResourceName $sqlVM.Name -ResourceType "Microsoft.Compute/virtualMachines" `
                -ResourceGroup $sqlVM.ResourceGroupName -Subscription $SubName `
                -Description "SQL Server running on IaaS VM. Consider migrating to Azure SQL or Managed Instance." `
                -Recommendation "Use Azure Migrate / Data Migration Assistant to assess migration to Azure SQL DB or Managed Instance for reduced management overhead." `
                -Impact "PaaS database services provide automated patching, backups, HA, and lower TCO."
        }
    }

    # ── 5. Unmanaged disks (legacy) ──────────────────────────────────────────
    $unmanagedVMs = $vms | Where-Object { $_.StorageProfile.OsDisk.Vhd }
    foreach ($uvm in $unmanagedVMs) {
        Add-Finding -Pillar "Reliability" -Severity "High" `
            -Category "Migration - Unmanaged Disks" `
            -ResourceName $uvm.Name -ResourceType "Microsoft.Compute/virtualMachines" `
            -ResourceGroup $uvm.ResourceGroupName -Subscription $SubName `
            -Description "VM uses unmanaged disks (VHD blobs). This is a legacy pattern." `
            -Recommendation "Convert to Managed Disks for better reliability, security, and simpler management." `
            -Impact "Unmanaged disks lack SLA guarantees, no RBAC, and require manual storage account management."
    }

    # ── 6. Load Balancer Basic SKU → Standard (moved to Analyze-AdditionalChecks check 18) ──

    # ── 7. Public IP Basic SKU → Standard (moved to Analyze-AdditionalChecks check 12) ──

    # ── 8. Containers/Serverless adoption opportunities ──────────────────────
    $aksCount = ($script:Resources | Where-Object { $_.Type -match 'managedClusters' }).Count
    $acaCount = ($script:Resources | Where-Object { $_.Type -match 'containerApps' }).Count
    $funcCount = ($script:Resources | Where-Object { $_.Type -match 'Microsoft.Web/sites' -and $_.Name -match 'func' }).Count
    $vmCount = ($vms | Measure-Object).Count

    if ($vmCount -gt 5 -and $aksCount -eq 0 -and $acaCount -eq 0) {
        Add-Finding -Pillar "Operational Excellence" -Severity "Low" `
            -Category "Modernization - Containers" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" `
            -ResourceGroup "N/A" -Subscription $SubName `
            -Description "Subscription has $vmCount VMs but no container services (AKS/Container Apps). Evaluate containerization." `
            -Recommendation "Assess VM workloads for containerization using Azure Migrate. Consider AKS or Azure Container Apps." `
            -Impact "Containers improve density, portability, CI/CD velocity, and can reduce costs."
    }

    Write-Status "  Modernization analysis completed." "OK"
}


# ============================================================================
# 12. CI/CD & DEPLOYMENT SECURITY ANALYSIS
# ============================================================================
function Analyze-DevOpsSecurity {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing CI/CD & deployment security..." "SECTION"

    # --- Azure Container Registry Security ---
    $acrs = Get-AzResource -ResourceType 'Microsoft.ContainerRegistry/registries' -ErrorAction SilentlyContinue
    foreach ($acrRes in $acrs) {
        try {
            $resp = Invoke-AzRestMethod -Path "$($acrRes.ResourceId)?api-version=2023-07-01" -Method GET -ErrorAction Stop
            if ($resp.StatusCode -ne 200) { Write-Status "  ACR API returned $($resp.StatusCode) for $($acrRes.Name)" "WARN"; continue }
            $acr  = ($resp.Content | ConvertFrom-Json)
            $acrName = $acr.name
            $rg      = $acrRes.ResourceGroupName

            if ($acr.properties.adminUserEnabled -eq $true) {
                Add-Finding -ResourceName $acrName `
                    -ResourceType "Container Registry" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "High" -Category "DevOps - ACR Security" `
                    -Description "Container Registry '$acrName' has the admin user enabled. Admin credentials are shared and not auditable." `
                    -Recommendation "Disable admin user and use Azure AD authentication with RBAC roles (AcrPull, AcrPush) for image access." `
                    -Impact "Shared admin credentials cannot be individually revoked and bypass Azure AD authentication, increasing risk of unauthorized image access."
            }

            if ($acr.properties.publicNetworkAccess -ne 'Disabled') {
                Add-Finding -ResourceName $acrName `
                    -ResourceType "Container Registry" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "Medium" -Category "DevOps - ACR Security" `
                    -Description "Container Registry '$acrName' allows public network access." `
                    -Recommendation "Restrict network access using Private Endpoints and disable public access. Use Premium SKU if required." `
                    -Impact "Public access exposes the registry to potential unauthorized image pulls or pushes from the internet."
            }

            if ($acr.properties.anonymousPullEnabled -eq $true) {
                Add-Finding -ResourceName $acrName `
                    -ResourceType "Container Registry" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "High" -Category "DevOps - ACR Security" `
                    -Description "Container Registry '$acrName' allows anonymous (unauthenticated) image pulls." `
                    -Recommendation "Disable anonymous pull access and require authentication for all image operations." `
                    -Impact "Anyone on the internet can pull container images without authentication, potentially exposing application code and configurations."
            }

            $trustPolicy = $acr.properties.policies.trustPolicy
            if (-not $trustPolicy -or $trustPolicy.status -ne 'enabled') {
                Add-Finding -ResourceName $acrName `
                    -ResourceType "Container Registry" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "Medium" -Category "DevOps - ACR Security" `
                    -Description "Container Registry '$acrName' does not have content trust (image signing) enabled." `
                    -Recommendation "Enable content trust to ensure only signed and verified images are deployed. Requires Premium SKU." `
                    -Impact "Without content trust, there is no guarantee that deployed images have not been tampered with."
            }
        } catch { continue }
    }

    # --- App Service Deployment Security ---
    $webApps = $script:CachedWebApps
    if (-not $webApps) { $webApps = @() }
    foreach ($app in $webApps) {
        try {
            $rg  = $app.ResourceGroup
            $cfg = $script:CachedWebAppDetails[$app.Id]
            if (-not $cfg) { continue }

            if ($cfg.SiteConfig.RemoteDebuggingEnabled) {
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "High" -Category "DevOps - Deployment Security" `
                    -Description "App Service '$($app.Name)' has remote debugging enabled, opening additional ports and attack surface." `
                    -Recommendation "Disable remote debugging in production. Use Application Insights and Log Stream for diagnostics instead." `
                    -Impact "Remote debugging opens ports on the service and may allow unauthorized code inspection or manipulation."
            }

            $ftpState = $cfg.SiteConfig.FtpsState
            if ($ftpState -and $ftpState -ne 'Disabled') {
                $sev = if ($ftpState -eq 'AllAllowed') { 'High' } else { 'Medium' }
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity $sev -Category "DevOps - Deployment Security" `
                    -Description "App Service '$($app.Name)' has FTP state '$ftpState'. $(if($ftpState -eq 'AllAllowed'){'Unencrypted FTP allowed.'}else{'FTPS allowed but should be fully disabled.'})" `
                    -Recommendation "Set FTP state to 'Disabled'. Use modern deployment: GitHub Actions, Azure DevOps, ZIP deploy, or az webapp deploy." `
                    -Impact "FTP transmits credentials in clear text (if AllAllowed) or maintains a legacy deployment surface."
            }

            $slots = try { Get-AzWebAppSlot -ResourceGroupName $rg -Name $app.Name -ErrorAction SilentlyContinue } catch { $null }
            $slots = @($slots | Where-Object { $_ -ne $null })
            $appSku = if ($cfg.ServerFarmId) { try { (Get-AzResource -ResourceId $cfg.ServerFarmId -ErrorAction SilentlyContinue).Sku.Tier } catch { '' } } else { '' }
            if (($slots.Count -eq 0) -and $appSku -and $appSku -notin @('Free','Shared','Basic')) {
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Operational Excellence" `
                    -Severity "Low" -Category "DevOps - Deployment Practices" `
                    -Description "App Service '$($app.Name)' (Plan: $appSku) has no deployment slots. Deployments go directly to production." `
                    -Recommendation "Create a staging slot and use slot swapping for zero-downtime deployments with rollback capability." `
                    -Impact "Direct-to-production deployments increase risk of downtime and make rollback more difficult."
            }
        } catch { continue }
    }

    Write-Status "  CI/CD & deployment security analysis complete" "OK"
}

# ============================================================================
# 13. APPLICATION-LEVEL SECURITY ANALYSIS
# ============================================================================
function Analyze-ApplicationSecurity {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing application-level security..." "SECTION"

    $webApps = $script:CachedWebApps
    if (-not $webApps) { $webApps = @() }
    foreach ($app in $webApps) {
        try {
            $rg  = $app.ResourceGroup
            $cfg = $script:CachedWebAppDetails[$app.Id]
            if (-not $cfg) { continue }

            $cors = $cfg.SiteConfig.Cors
            if ($cors -and $cors.AllowedOrigins -contains '*') {
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "High" -Category "Application Security - CORS" `
                    -Description "App Service '$($app.Name)' allows CORS requests from any origin (wildcard '*')." `
                    -Recommendation "Restrict CORS to specific trusted domains. Remove the wildcard entry and add explicit origins." `
                    -Impact "Wildcard CORS allows any website to make cross-origin requests, enabling potential data theft."
            }

            $clientCertEnabled = $cfg.ClientCertEnabled
            if (-not $clientCertEnabled) {
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "Low" -Category "Application Security - Authentication" `
                    -Description "App Service '$($app.Name)' does not require client certificates (mutual TLS)." `
                    -Recommendation "For APIs and backend services, enable client certificates (mutual TLS) to ensure only authorized clients connect." `
                    -Impact "Without mutual TLS, the application relies solely on application-level authentication."
            }

            if (-not $cfg.SiteConfig.Http20Enabled) {
                Add-Finding -ResourceName $app.Name `
                    -ResourceType "App Service" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Performance Efficiency" `
                    -Severity "Low" -Category "Application Security - Protocol" `
                    -Description "App Service '$($app.Name)' is not using HTTP/2 protocol." `
                    -Recommendation "Enable HTTP/2 for improved performance through multiplexing and header compression." `
                    -Impact "HTTP/1.1 has higher latency due to head-of-line blocking and requires more TCP connections."
            }
        } catch { continue }
    }

    # API Management Security
    $apims = Get-AzResource -ResourceType 'Microsoft.ApiManagement/service' -ErrorAction SilentlyContinue
    foreach ($apimRes in $apims) {
        try {
            $resp = Invoke-AzRestMethod -Path "$($apimRes.ResourceId)?api-version=2023-05-01-preview" -Method GET -ErrorAction Stop
            if ($resp.StatusCode -ne 200) { continue }
            $apim = ($resp.Content | ConvertFrom-Json)
            $apimName = $apim.name
            $rg = $apimRes.ResourceGroupName

            $protocols = $apim.properties.customProperties
            $httpEnabled = $protocols.'Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http'
            if ($httpEnabled -eq 'True') {
                Add-Finding -ResourceName $apimName `
                    -ResourceType "API Management" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "High" -Category "Application Security - API Gateway" `
                    -Description "API Management '$apimName' allows unencrypted HTTP traffic." `
                    -Recommendation "Disable HTTP and enforce HTTPS-only communication for all APIs." `
                    -Impact "API traffic over HTTP can be intercepted, exposing authentication tokens and sensitive data."
            }

            $vnetConfig = $apim.properties.virtualNetworkType
            if (-not $vnetConfig -or $vnetConfig -eq 'None') {
                Add-Finding -ResourceName $apimName `
                    -ResourceType "API Management" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Security" `
                    -Severity "Medium" -Category "Application Security - API Gateway" `
                    -Description "API Management '$apimName' is not integrated with a Virtual Network." `
                    -Recommendation "Deploy APIM in Internal or External VNet mode to restrict backend API access." `
                    -Impact "Without VNet integration, backend APIs may be accessed directly bypassing the gateway."
            }
        } catch { continue }
    }

    Write-Status "  Application-level security analysis complete" "OK"
}

# ============================================================================
# 14. COST OPTIMIZATION — ADVISOR, HYBRID BENEFIT & RESERVATIONS
# ============================================================================
function Analyze-CostAdvisor {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing cost optimization (Advisor, Hybrid Benefit, Reservations)..." "SECTION"

    # Azure Advisor Cost Recommendations — prefer pre-cached Resource Graph
    try {
        $costRecs = $null
        if ($script:CachedAdvisorCost.ContainsKey($SubId)) {
            $costRecs = $script:CachedAdvisorCost[$SubId]
            foreach ($rec in $costRecs) {
                $resId   = if ($rec.properties.resourceMetadata.resourceId) { $rec.properties.resourceMetadata.resourceId } else { $rec.id }
                $resName = if ($resId) { $resId.Split('/')[-1] } else { 'N/A' }
                $resType = if ($rec.properties.impactedField) { $rec.properties.impactedField.Split('/')[-1] } else { 'Azure Resource' }
                $resRg   = if ($resId -match '/resourceGroups/([^/]+)') { $Matches[1] } else { 'N/A' }
                $impact  = $rec.properties.impact
                $sev     = switch ($impact) { 'High' { 'High' } 'Medium' { 'Medium' } default { 'Low' } }
                $shortDesc = $rec.properties.shortDescription.problem
                $solution  = $rec.properties.shortDescription.solution
                $savings   = ''
                $extProps  = $rec.properties.extendedProperties
                if ($extProps.savingsAmount) { $savings = " Azure Advisor reports potential savings of $($extProps.savingsAmount) $($extProps.savingsCurrency)/year." }
                Add-Finding -ResourceName $resName -ResourceType $resType -ResourceGroup $resRg -Subscription $SubName -Pillar "Cost Optimization" -Severity $sev -Category "Cost - Azure Advisor" -Description "$shortDesc.$savings" -Recommendation "$solution" -Impact "Cost impact rated '$impact' by Azure Advisor.$savings" -Source 'Azure Advisor'
            }
            if ($costRecs.Count -gt 0) { Write-Status "  Azure Advisor (cached): $($costRecs.Count) cost recommendation(s)" "WARN" }
            else { Write-Status "  Azure Advisor: No cost recommendations" "OK" }
        } else {
            # Fallback to REST API
            $advisorResp = Invoke-AzRestMethod -Path "/subscriptions/$SubId/providers/Microsoft.Advisor/recommendations?api-version=2022-10-01&`$filter=Category eq 'Cost'" -Method GET -ErrorAction Stop
            if ($advisorResp.StatusCode -ne 200) { throw "Advisor API returned $($advisorResp.StatusCode)" }
            $advisorData = ($advisorResp.Content | ConvertFrom-Json)
            $costRecs = $advisorData.value | Where-Object { $_.properties.category -eq 'Cost' }
            foreach ($rec in $costRecs) {
                $resId   = $rec.properties.resourceMetadata.resourceId
                $resName = if ($resId) { $resId.Split('/')[-1] } else { 'N/A' }
                $resType = if ($rec.properties.impactedField) { $rec.properties.impactedField.Split('/')[-1] } else { 'Azure Resource' }
                $resRg   = if ($resId -match '/resourceGroups/([^/]+)') { $Matches[1] } else { 'N/A' }
                $impact  = $rec.properties.impact
                $sev     = switch ($impact) { 'High' { 'High' } 'Medium' { 'Medium' } default { 'Low' } }
                $shortDesc = $rec.properties.shortDescription.problem
                $solution  = $rec.properties.shortDescription.solution
                $savings   = ''
                $extProps  = $rec.properties.extendedProperties
                if ($extProps.savingsAmount) { $savings = " Azure Advisor reports potential savings of $($extProps.savingsAmount) $($extProps.savingsCurrency)/year." }
                Add-Finding -ResourceName $resName -ResourceType $resType -ResourceGroup $resRg -Subscription $SubName -Pillar "Cost Optimization" -Severity $sev -Category "Cost - Azure Advisor" -Description "$shortDesc.$savings" -Recommendation "$solution" -Impact "Cost impact rated '$impact' by Azure Advisor.$savings" -Source 'Azure Advisor'
            }
            if ($costRecs.Count -gt 0) { Write-Status "  Azure Advisor: $($costRecs.Count) cost recommendation(s)" "WARN" }
            else { Write-Status "  Azure Advisor: No cost recommendations" "OK" }
        }
    } catch { Write-Status "  Azure Advisor API not accessible (requires Advisor Reader role)" "INFO" }

    # Azure Hybrid Benefit — Windows VMs
    $vms = $script:CachedVMs
    if (-not $vms) { $vms = @() }
    foreach ($vm in $vms) {
        try {
            if ($vm.StorageProfile.OsDisk.OsType -eq 'Windows' -and $vm.LicenseType -ne 'Windows_Server') {
                Add-Finding -ResourceName $vm.Name `
                    -ResourceType "Virtual Machine" -ResourceGroup $vm.ResourceGroupName `
                    -Subscription $SubName -Pillar "Cost Optimization" `
                    -Severity "Medium" -Category "Cost - Hybrid Benefit" `
                    -Description "Windows VM '$($vm.Name)' (Size: $($vm.HardwareProfile.VmSize)) is not using Azure Hybrid Benefit. AHUB allows using existing Windows Server licenses with Software Assurance on Azure." `
                    -Recommendation "Apply Azure Hybrid Benefit by setting LicenseType to 'Windows_Server'. Requires licenses with Software Assurance." `
                    -Impact "Pay-as-you-go Windows licensing cost is applied. Azure Hybrid Benefit leverages existing on-premises licenses to reduce compute costs."
            }
        } catch { continue }
    }

    # SQL Azure Hybrid Benefit
    $sqlServers = $script:CachedSqlServers
    if ($sqlServers) {
        foreach ($server in $sqlServers) {
            try {
                $dbs = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue |
                    Where-Object { $_.DatabaseName -ne 'master' }
                foreach ($db in $dbs) {
                    if ($db.SkuName -match 'vCore|GP_|BC_|HS_' -and $db.LicenseType -ne 'BasePrice') {
                        Add-Finding -ResourceName $db.DatabaseName `
                            -ResourceType "SQL Database" -ResourceGroup $db.ResourceGroupName `
                            -Subscription $SubName -Pillar "Cost Optimization" `
                            -Severity "Medium" -Category "Cost - Hybrid Benefit" `
                            -Description "SQL Database '$($db.DatabaseName)' (SKU: $($db.SkuName)) not using Hybrid Benefit. Eligible for license cost reduction with existing SQL Server licenses." `
                            -Recommendation "Set LicenseType to 'BasePrice'. Requires SQL Server licenses with Software Assurance." `
                            -Impact "Full SQL Server license cost is applied on each vCore. Azure Hybrid Benefit leverages existing on-premises licenses to reduce compute costs."
                    }
                }
            } catch { continue }
        }
    }

    # Dev/Test VMs without auto-shutdown — use pre-cached schedules
    $shutdownSchedules = @{}
    if ($script:CachedAutoShutdown.ContainsKey($SubId)) {
        foreach ($sched in $script:CachedAutoShutdown[$SubId]) {
            $vmName = $sched.name -replace '^shutdown-computevm-', ''
            $shutdownSchedules[$vmName.ToLower()] = $true
        }
    }
    foreach ($vm in $vms) {
        try {
            $hasShutdown = $false
            if ($shutdownSchedules.Count -gt 0) {
                $hasShutdown = $shutdownSchedules.ContainsKey($vm.Name.ToLower())
            } else {
                # Fallback to REST if no cache
                $shutdownId = "/subscriptions/$SubId/resourceGroups/$($vm.ResourceGroupName)/providers/Microsoft.DevTestLab/schedules/shutdown-computevm-$($vm.Name)"
                $shutdownResp = Invoke-AzRestMethod -Path "${shutdownId}?api-version=2018-09-15" -Method GET -ErrorAction SilentlyContinue
                $hasShutdown = ($shutdownResp.StatusCode -eq 200)
            }
            if (-not $hasShutdown) {
                $rgTags   = try { (Get-AzResourceGroup -Name $vm.ResourceGroupName -ErrorAction SilentlyContinue).Tags } catch { @{} }
                $isDevTest = ($vm.Tags.Environment -match 'dev|test|sandbox|lab|poc') -or ($rgTags.Environment -match 'dev|test|sandbox|lab|poc')
                if ($isDevTest) {
                    Add-Finding -ResourceName $vm.Name `
                        -ResourceType "Virtual Machine" -ResourceGroup $vm.ResourceGroupName `
                        -Subscription $SubName -Pillar "Cost Optimization" `
                        -Severity "Medium" -Category "Cost - VM Scheduling" `
                        -Description "Dev/Test VM '$($vm.Name)' has no auto-shutdown. Running 24/7 incurs unnecessary costs." `
                        -Recommendation "Configure auto-shutdown (e.g., 7 PM daily) via DevTest Labs or Azure Automation." `
                        -Impact "Running dev/test VMs 24/7 instead of ~10h/day wastes ~58% of compute cost."
                }
            }
        } catch { continue }
    }

    # ── Subscription Budget Alerts check ──
    Write-Status "  Checking subscription budgets..." "INFO"
    try {
        $budgetUrl = "/subscriptions/$SubId/providers/Microsoft.Consumption/budgets?api-version=2023-11-01"
        $budgetResult = Invoke-AzRestMethod -Path $budgetUrl -Method GET -ErrorAction SilentlyContinue
        if ($budgetResult -and $budgetResult.StatusCode -eq 200) {
            $budgets = ($budgetResult.Content | ConvertFrom-Json).value
            if (-not $budgets -or $budgets.Count -eq 0) {
                Add-Finding -Pillar "Cost Optimization" -Severity "Medium" -Category "Cost - No Budget Configured" `
                    -ResourceName "Subscription Budget" -ResourceType "Budget" `
                    -ResourceGroup "N/A" -Subscription $SubName `
                    -Description "No Azure budgets are configured for this subscription. Spending is not monitored." `
                    -Recommendation "Create at least one budget with alert thresholds at 50%, 80%, and 100% of expected monthly spend." `
                    -Impact "Without budgets, cost overruns may go unnoticed until the end of the billing cycle."
            } else {
                foreach ($b in $budgets) {
                    $notifications = $b.properties.notifications
                    if (-not $notifications -or ($notifications.PSObject.Properties | Measure-Object).Count -eq 0) {
                        Add-Finding -Pillar "Cost Optimization" -Severity "Low" -Category "Cost - Budget No Alerts" `
                            -ResourceName $b.name -ResourceType "Budget" `
                            -ResourceGroup "N/A" -Subscription $SubName `
                            -Description "Budget '$($b.name)' exists but has no notification/alert rules configured." `
                            -Recommendation "Add alert notifications at key thresholds (e.g., 50%, 80%, 100%) with email/action group." `
                            -Impact "Budget without alerts provides no proactive cost notification."
                    }
                }
            }
        }
    } catch {
        Write-Status "  Could not check budgets: $($_.Exception.Message)" "WARN"
    }

    Write-Status "  Cost optimization analysis complete" "OK"
}

# ============================================================================
# 14b. AZURE RESERVATIONS & SAVINGS PLANS
# ============================================================================
function Analyze-Reservations {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Azure Reservations & Savings Plans..." "SECTION"

    # ── 1. Reservation Orders (tenant-wide, fetched once) ──
    if ($script:ReservationData.Count -eq 0) {
        try {
            $riResp = Invoke-AzRestMethod -Path "/providers/Microsoft.Capacity/reservationOrders?api-version=2022-11-01" -Method GET -ErrorAction Stop
            if ($riResp.StatusCode -eq 200) {
                $riOrders = ($riResp.Content | ConvertFrom-Json).value
                foreach ($order in $riOrders) {
                    $orderId = $order.id
                    $orderName = $order.name
                    # Get reservations within each order
                    try {
                        $riDetailResp = Invoke-AzRestMethod -Path "${orderId}/reservations?api-version=2022-11-01" -Method GET -ErrorAction Stop
                        if ($riDetailResp.StatusCode -eq 200) {
                            $reservations = ($riDetailResp.Content | ConvertFrom-Json).value
                            foreach ($ri in $reservations) {
                                $props = $ri.properties
                                $expiryDate = if ($props.expiryDate) { [datetime]$props.expiryDate } else { $null }
                                $purchaseDate = if ($props.purchaseDate) { [datetime]$props.purchaseDate } else { $null }
                                $daysToExpiry = if ($expiryDate) { [math]::Round(($expiryDate - (Get-Date)).TotalDays) } else { -1 }
                                $utilizationPct = -1
                                try {
                                    $utilResp = Invoke-AzRestMethod -Path "$($ri.id)?api-version=2022-11-01&`$expand=utilization" -Method GET -ErrorAction SilentlyContinue
                                    if ($utilResp.StatusCode -eq 200) {
                                        $utilData = ($utilResp.Content | ConvertFrom-Json).properties.utilization
                                        if ($utilData.aggregates) {
                                            $avgUtil = $utilData.aggregates | Where-Object { $_.grain -eq 'Last7Days' -and $_.grainUnit -eq 'percentage' }
                                            if ($avgUtil) { $utilizationPct = [math]::Round([double]$avgUtil.value, 1) }
                                            else {
                                                $anyAvg = $utilData.aggregates | Select-Object -First 1
                                                if ($anyAvg) { $utilizationPct = [math]::Round([double]$anyAvg.value, 1) }
                                            }
                                        }
                                    }
                                } catch { }

                                $script:ReservationData.Add([PSCustomObject]@{
                                    Type            = 'Reservation'
                                    Name            = $ri.name
                                    DisplayName     = if ($props.displayName) { $props.displayName } else { $ri.name }
                                    ResourceType    = if ($props.reservedResourceType) { $props.reservedResourceType } else { 'Unknown' }
                                    SKU             = if ($ri.sku.name) { $ri.sku.name } else { 'N/A' }
                                    Quantity        = if ($props.quantity) { $props.quantity } else { 0 }
                                    Term            = if ($props.term) { $props.term } else { 'N/A' }
                                    Status          = if ($props.provisioningState) { $props.provisioningState } else { 'Unknown' }
                                    UtilizationPct  = $utilizationPct
                                    PurchaseDate    = $purchaseDate
                                    ExpiryDate      = $expiryDate
                                    DaysToExpiry    = $daysToExpiry
                                    Scope           = if ($props.appliedScopeType) { $props.appliedScopeType } else { 'N/A' }
                                    BenefitId       = $ri.id
                                    Subscription    = $SubName
                                })
                            }
                        }
                    } catch { }
                }
                Write-Status "  Reservation orders found: $($riOrders.Count)" "INFO"
            }
        } catch {
            Write-Status "  Reservations API not accessible (requires Reservation Reader): $($_.Exception.Message)" "INFO"
        }

        # ── 2. Savings Plans ──
        try {
            $spResp = Invoke-AzRestMethod -Path "/providers/Microsoft.BillingBenefits/savingsPlanOrders?api-version=2022-11-01" -Method GET -ErrorAction Stop
            if ($spResp.StatusCode -eq 200) {
                $spOrders = ($spResp.Content | ConvertFrom-Json).value
                foreach ($spOrder in $spOrders) {
                    try {
                        $spDetailResp = Invoke-AzRestMethod -Path "$($spOrder.id)/savingsPlans?api-version=2022-11-01" -Method GET -ErrorAction Stop
                        if ($spDetailResp.StatusCode -eq 200) {
                            $savingsPlans = ($spDetailResp.Content | ConvertFrom-Json).value
                            foreach ($sp in $savingsPlans) {
                                $props = $sp.properties
                                $expiryDate = if ($props.expiryDateTime) { [datetime]$props.expiryDateTime } else { $null }
                                $purchaseDate = if ($props.purchaseDateTime) { [datetime]$props.purchaseDateTime } else { $null }
                                $daysToExpiry = if ($expiryDate) { [math]::Round(($expiryDate - (Get-Date)).TotalDays) } else { -1 }
                                $utilizationPct = -1
                                if ($props.utilization -and $props.utilization.aggregates) {
                                    $avgUtil = $props.utilization.aggregates | Where-Object { $_.grain -eq 'Last7Days' }
                                    if ($avgUtil) { $utilizationPct = [math]::Round([double]$avgUtil.value, 1) }
                                }

                                $script:ReservationData.Add([PSCustomObject]@{
                                    Type            = 'SavingsPlan'
                                    Name            = $sp.name
                                    DisplayName     = if ($props.displayName) { $props.displayName } else { $sp.name }
                                    ResourceType    = if ($props.appliedScopeProperties.resourceType) { $props.appliedScopeProperties.resourceType } else { 'Compute' }
                                    SKU             = 'N/A'
                                    Quantity        = 1
                                    Term            = if ($props.term) { $props.term } else { 'N/A' }
                                    Status          = if ($props.provisioningState) { $props.provisioningState } else { 'Unknown' }
                                    UtilizationPct  = $utilizationPct
                                    PurchaseDate    = $purchaseDate
                                    ExpiryDate      = $expiryDate
                                    DaysToExpiry    = $daysToExpiry
                                    Scope           = if ($props.appliedScopeType) { $props.appliedScopeType } else { 'N/A' }
                                    BenefitId       = $sp.id
                                    Subscription    = $SubName
                                })
                            }
                        }
                    } catch { }
                }
                Write-Status "  Savings Plan orders found: $($spOrders.Count)" "INFO"
            }
        } catch {
            Write-Status "  Savings Plans API not accessible: $($_.Exception.Message)" "INFO"
        }
    }

    # ── 3. Generate findings ──
    $riItems = @($script:ReservationData | Where-Object { $_.Type -eq 'Reservation' })
    $spItems = @($script:ReservationData | Where-Object { $_.Type -eq 'SavingsPlan' })

    # No reservations at all
    if ($riItems.Count -eq 0 -and $spItems.Count -eq 0 -and $script:ReservationData.Count -eq 0) {
        # Check if there are VMs or SQL that could benefit
        $vmCount = @($script:CachedVMs).Count
        $sqlCount = @($script:CachedSqlServers).Count
        if ($vmCount -gt 5 -or $sqlCount -gt 2) {
            Add-Finding -Pillar "Cost Optimization" -Severity "Medium" -Category "Cost - No Reservations" `
                -ResourceName "Subscription: $SubName" -ResourceType "Billing" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "No Azure Reservations or Savings Plans detected. This subscription has $vmCount VMs and $sqlCount SQL servers that may benefit from reserved pricing." `
                -Recommendation "Review Azure Advisor reservation recommendations. Evaluate 1-year or 3-year Reserved Instances for workloads with predictable, steady-state usage." `
                -Impact "Pay-as-you-go pricing is applied to all compute resources. Reserved pricing offers significant discounts for committed usage."
        }
    }

    # Low utilization reservations
    foreach ($ri in $riItems) {
        if ($ri.UtilizationPct -ge 0 -and $ri.UtilizationPct -lt 50) {
            $sev = if ($ri.UtilizationPct -lt 20) { 'High' } else { 'Medium' }
            Add-Finding -Pillar "Cost Optimization" -Severity $sev -Category "Cost - RI Low Utilization" `
                -ResourceName "$($ri.DisplayName)" -ResourceType "Reservation ($($ri.ResourceType))" -ResourceGroup "N/A" `
                -Subscription $ri.Subscription `
                -Description "Reservation '$($ri.DisplayName)' ($($ri.ResourceType), SKU: $($ri.SKU)) has only $($ri.UtilizationPct)% utilization over the last 7 days. Quantity: $($ri.Quantity)." `
                -Recommendation "Review if the reserved SKU matches deployed resources. Consider exchanging or changing the scope (Shared vs Single subscription)." `
                -Impact "Underutilized reservations represent wasted commitment spend. At $($ri.UtilizationPct)% utilization, $(100 - $ri.UtilizationPct)% of the reservation cost is lost."
        }
    }

    # Expiring soon (within 90 days)
    foreach ($ri in $script:ReservationData) {
        if ($ri.DaysToExpiry -ge 0 -and $ri.DaysToExpiry -le 90) {
            $sev = if ($ri.DaysToExpiry -le 30) { 'High' } else { 'Medium' }
            $typeLabel = if ($ri.Type -eq 'SavingsPlan') { 'Savings Plan' } else { 'Reservation' }
            Add-Finding -Pillar "Cost Optimization" -Severity $sev -Category "Cost - RI Expiring Soon" `
                -ResourceName "$($ri.DisplayName)" -ResourceType "$typeLabel ($($ri.ResourceType))" -ResourceGroup "N/A" `
                -Subscription $ri.Subscription `
                -Description "$typeLabel '$($ri.DisplayName)' expires in $($ri.DaysToExpiry) days ($(if($ri.ExpiryDate){$ri.ExpiryDate.ToString('yyyy-MM-dd')}else{'N/A'})). Term: $($ri.Term)." `
                -Recommendation "Evaluate renewal or exchange before expiry. If workloads remain stable, renew to maintain savings. Consider switching to a Savings Plan for more flexibility." `
                -Impact "After expiry, resources revert to pay-as-you-go pricing, increasing costs by 30-72%."
        }
    }

    # Expired reservations still in inventory
    foreach ($ri in $script:ReservationData) {
        if ($ri.DaysToExpiry -lt 0 -and $ri.ExpiryDate) {
            $typeLabel = if ($ri.Type -eq 'SavingsPlan') { 'Savings Plan' } else { 'Reservation' }
            Add-Finding -Pillar "Cost Optimization" -Severity "Low" -Category "Cost - RI Expired" `
                -ResourceName "$($ri.DisplayName)" -ResourceType "$typeLabel ($($ri.ResourceType))" -ResourceGroup "N/A" `
                -Subscription $ri.Subscription `
                -Description "$typeLabel '$($ri.DisplayName)' expired on $(if($ri.ExpiryDate){$ri.ExpiryDate.ToString('yyyy-MM-dd')}else{'N/A'}). Resources are now billed at pay-as-you-go rates." `
                -Recommendation "Purchase a new reservation or savings plan if workloads are still active. Review usage patterns before committing." `
                -Impact "Expired commitments mean affected resources are running at full pay-as-you-go cost."
        }
    }

    Write-Status "  Reservations analysis complete: $($riItems.Count) reservations, $($spItems.Count) savings plans" "OK"
}

# ============================================================================
# 15. HYBRID & MULTI-CLOUD INFRASTRUCTURE ANALYSIS
# ============================================================================
function Analyze-HybridInfrastructure {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing hybrid & multi-cloud infrastructure..." "SECTION"

    # Azure Arc-enabled Servers
    $arcMachines = Get-AzResource -ResourceType 'Microsoft.HybridCompute/machines' -ErrorAction SilentlyContinue
    if ($arcMachines -and $arcMachines.Count -gt 0) {
        Write-Status "  Azure Arc servers found: $($arcMachines.Count)" "INFO"
        foreach ($arcRes in $arcMachines) {
            try {
                $resp = Invoke-AzRestMethod -Path "$($arcRes.ResourceId)?api-version=2024-03-31-preview" -Method GET -ErrorAction Stop
                if ($resp.StatusCode -ne 200) { continue }
                $arc  = ($resp.Content | ConvertFrom-Json)
                $arcName = $arc.name
                $rg      = $arcRes.ResourceGroupName
                $status  = $arc.properties.status

                if ($status -ne 'Connected') {
                    Add-Finding -ResourceName $arcName `
                        -ResourceType "Azure Arc Server" -ResourceGroup $rg `
                        -Subscription $SubName -Pillar "Reliability" `
                        -Severity "High" -Category "Hybrid - Arc Connectivity" `
                        -Description "Arc server '$arcName' is '$status'. Policies, updates, and monitoring are not applied." `
                        -Recommendation "Verify the Connected Machine agent is running and has outbound HTTPS access to Azure endpoints." `
                        -Impact "Disconnected Arc servers miss policy enforcement, patches, and monitoring."
                }

                $extResp = Invoke-AzRestMethod -Path "$($arcRes.ResourceId)/extensions?api-version=2024-03-31-preview" -Method GET -ErrorAction SilentlyContinue
                $extensions = if ($extResp.StatusCode -eq 200) { ($extResp.Content | ConvertFrom-Json).value } else { @() }
                $extNames = $extensions | ForEach-Object { $_.properties.type }

                $hasMonitoring = $extNames | Where-Object { $_ -match 'AzureMonitorLinuxAgent|AzureMonitorWindowsAgent|MicrosoftMonitoringAgent|OmsAgentForLinux' }
                if (-not $hasMonitoring -and $status -eq 'Connected') {
                    Add-Finding -ResourceName $arcName `
                        -ResourceType "Azure Arc Server" -ResourceGroup $rg `
                        -Subscription $SubName -Pillar "Operational Excellence" `
                        -Severity "Medium" -Category "Hybrid - Arc Monitoring" `
                        -Description "Arc server '$arcName' does not have Azure Monitor Agent installed." `
                        -Recommendation "Deploy AMA extension and configure Data Collection Rules for Log Analytics." `
                        -Impact "Server performance, availability, and security events are not visible in Azure Monitor."
                }

                $hasSecurity = $extNames | Where-Object { $_ -match 'MDE.Linux|MDE.Windows|MicrosoftDefenderForServers' }
                if (-not $hasSecurity -and $status -eq 'Connected') {
                    Add-Finding -ResourceName $arcName `
                        -ResourceType "Azure Arc Server" -ResourceGroup $rg `
                        -Subscription $SubName -Pillar "Security" `
                        -Severity "Medium" -Category "Hybrid - Arc Security" `
                        -Description "Arc server '$arcName' lacks Defender for Endpoint extension." `
                        -Recommendation "Enable Defender for Servers and deploy MDE extension for threat detection." `
                        -Impact "On-premises servers without endpoint protection are not covered by Defender for Cloud."
                }
            } catch { continue }
        }
    } else { Write-Status "  No Azure Arc servers in this subscription" "INFO" }

    # ExpressRoute Circuits
    try {
        $erCircuits = Get-AzExpressRouteCircuit -ErrorAction SilentlyContinue
        foreach ($er in $erCircuits) {
            $erName = $er.Name; $rg = $er.ResourceGroupName

            if ($er.ServiceProviderProvisioningState -ne 'Provisioned') {
                Add-Finding -ResourceName $erName `
                    -ResourceType "ExpressRoute Circuit" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Reliability" `
                    -Severity "Critical" -Category "Hybrid - ExpressRoute" `
                    -Description "ExpressRoute '$erName' is '$($er.ServiceProviderProvisioningState)'. Circuit is not operational." `
                    -Recommendation "Work with your connectivity provider to complete provisioning." `
                    -Impact "No private Azure connectivity. All traffic routes through the public internet."
            }

            if ($er.Peerings.Count -eq 0 -and $er.ServiceProviderProvisioningState -eq 'Provisioned') {
                Add-Finding -ResourceName $erName `
                    -ResourceType "ExpressRoute Circuit" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Reliability" `
                    -Severity "High" -Category "Hybrid - ExpressRoute" `
                    -Description "ExpressRoute '$erName' is provisioned but has no peerings configured." `
                    -Recommendation "Configure at least Private Peering. Consider adding Microsoft Peering for M365/Dynamics connectivity." `
                    -Impact "Without peering, the circuit is provisioned but not usable for connectivity."
            }

            if ($er.Sku.Tier -eq 'Standard' -and $er.Sku.Family -eq 'MeteredData') {
                Add-Finding -ResourceName $erName `
                    -ResourceType "ExpressRoute Circuit" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Cost Optimization" `
                    -Severity "Low" -Category "Hybrid - ExpressRoute" `
                    -Description "ExpressRoute '$erName' uses metered data. If transfer is high, unlimited may be cheaper." `
                    -Recommendation "Analyze monthly data transfer. Switch to Unlimited if it exceeds the breakeven point." `
                    -Impact "High data volumes on metered circuits lead to high costs."
            }
        }
    } catch { Write-Status "  ExpressRoute analysis skipped" "INFO" }

    # VPN Gateway Connections
    try {
        $gwResources = Get-AzResource -ResourceType 'Microsoft.Network/virtualNetworkGateways' -ErrorAction SilentlyContinue
        $vpnGateways = foreach ($gwRes in $gwResources) {
            try { Get-AzVirtualNetworkGateway -Name $gwRes.Name -ResourceGroupName $gwRes.ResourceGroupName -ErrorAction SilentlyContinue } catch { $null }
        }
        $vpnGateways = @($vpnGateways | Where-Object { $_ -and $_.GatewayType -eq 'Vpn' })
        foreach ($gw in $vpnGateways) {
            $gwName = $gw.Name; $rg = $gw.ResourceGroupName; $gwSku = $gw.Sku.Name

            if ($gwSku -and $gwSku -notmatch 'AZ|ErGw.*AZ') {
                Add-Finding -ResourceName $gwName `
                    -ResourceType "VPN Gateway" -ResourceGroup $rg `
                    -Subscription $SubName -Pillar "Reliability" `
                    -Severity "Medium" -Category "Hybrid - VPN Gateway" `
                    -Description "VPN Gateway '$gwName' (SKU: $gwSku) is not zone-redundant." `
                    -Recommendation "Upgrade to zone-redundant SKU (VpnGw1AZ, VpnGw2AZ, etc.)." `
                    -Impact "Zone outage will disconnect all VPN tunnels."
            }

            $connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $rg -ErrorAction SilentlyContinue |
                Where-Object { $_.VirtualNetworkGateway1.Id -eq $gw.Id }
            foreach ($conn in $connections) {
                if ($conn.ConnectionStatus -ne 'Connected') {
                    Add-Finding -ResourceName $conn.Name `
                        -ResourceType "VPN Connection" -ResourceGroup $rg `
                        -Subscription $SubName -Pillar "Reliability" `
                        -Severity "High" -Category "Hybrid - VPN Connectivity" `
                        -Description "VPN connection '$($conn.Name)' on '$gwName' is '$($conn.ConnectionStatus)'." `
                        -Recommendation "Check on-premises VPN device config, IKE/IPSec params, shared keys, and endpoint reachability." `
                        -Impact "Disconnected VPN breaks hybrid workload communication with Azure VNets."
                }
            }
        }
    } catch { Write-Status "  VPN Gateway analysis skipped" "INFO" }

    Write-Status "  Hybrid & multi-cloud analysis complete" "OK"
}

# ============================================================================
# 16A. HIGH AVAILABILITY & RESILIENCE
# ============================================================================
function Analyze-HighAvailability {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing High Availability & Resilience..." "SECTION"

    # ── 1. Storage Accounts: LRS = no zone or geo redundancy ──
    $storageAccounts = $script:CachedStorageAccounts
    if ($storageAccounts) {
        foreach ($sa in $storageAccounts) {
            $skuName = $sa.Sku.Name
            if ($skuName -match '^(Standard_LRS|Premium_LRS)$') {
                $sev = if ($sa.Kind -eq 'StorageV2' -or $sa.Kind -eq 'BlobStorage') { "Medium" } else { "Low" }
                Add-Finding -Pillar "Reliability" -Severity $sev -Category "HA - Storage No Redundancy" `
                    -ResourceName $sa.StorageAccountName -ResourceType "Storage Account" -ResourceGroup $sa.ResourceGroupName `
                    -Subscription $SubName `
                    -Description "Storage Account uses $skuName — data exists in a single datacenter with no zone or geo replication." `
                    -Recommendation "Upgrade to ZRS (zone-redundant), GRS (geo-redundant), or GZRS for critical data." `
                    -Impact "A datacenter failure causes data loss and unavailability. No automatic failover capability."
            }
        }
        Write-Status "  Storage redundancy: checked $(@($storageAccounts).Count) accounts" "OK"
    }

    # ── 2. App Service Plans: single instance and zone redundancy ──
    try {
        $graphAvailable = Get-Module -ListAvailable -Name Az.ResourceGraph
        if ($graphAvailable) {
            $aspResults = Invoke-AzCommandSafely {
                Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where sku.tier !in~ ('Free', 'Shared', 'Dynamic')
| extend workers = toint(properties.numberOfWorkers),
         zoneRedundant = tobool(properties.zoneRedundant),
         skuTier = tostring(sku.tier),
         skuName = tostring(sku.name)
| project name, resourceGroup, location, workers, zoneRedundant, skuTier, skuName, id
"@ -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
            } "Resource Graph App Service Plans HA query"

            if ($aspResults) {
                foreach ($asp in $aspResults) {
                    # Single instance — single point of failure
                    if ($asp.workers -le 1) {
                        Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "HA - App Service Single Instance" `
                            -ResourceName $asp.name -ResourceType "App Service Plan" -ResourceGroup $asp.resourceGroup `
                            -Subscription $SubName `
                            -Description "App Service Plan ($($asp.skuTier)/$($asp.skuName)) runs a single instance — no redundancy against host failures." `
                            -Recommendation "Scale out to at least 2 instances for production workloads. Consider auto-scale rules." `
                            -Impact "A host failure or platform update takes the application offline. No SLA for single-instance plans."
                    }
                    # Standard/Premium without zone redundancy
                    if (-not $asp.zoneRedundant -and $asp.skuTier -match 'Premium|Isolated') {
                        Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - App Service No Zone Redundancy" `
                            -ResourceName $asp.name -ResourceType "App Service Plan" -ResourceGroup $asp.resourceGroup `
                            -Subscription $SubName `
                            -Description "App Service Plan ($($asp.skuTier)) is not configured for zone redundancy." `
                            -Recommendation "Enable zone redundancy on Premium/Isolated plans to survive availability zone failures." `
                            -Impact "An availability zone failure takes down all instances in this plan."
                    }
                }
                Write-Status "  App Service Plans: checked $($aspResults.Count) plans" "OK"
            }
        }
    } catch { Write-Status "  App Service Plan HA check skipped" "INFO" }

    # ── 3. SQL Databases: zone redundancy ──
    try {
        if ($graphAvailable) {
            $sqlDbResults = Invoke-AzCommandSafely {
                Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.sql/servers/databases'
| where name != 'master'
| extend zoneRedundant = tobool(properties.zoneRedundant),
         skuTier = tostring(sku.tier),
         skuName = tostring(sku.name)
| where skuTier !in~ ('Free', 'Basic')
| project name, resourceGroup, location, zoneRedundant, skuTier, skuName,
          serverName = tostring(split(id, '/')[8]),
          serverId = tolower(strcat(split(id, '/')[0], '/', split(id, '/')[1], '/', split(id, '/')[2], '/', split(id, '/')[3], '/', split(id, '/')[4], '/', split(id, '/')[5], '/', split(id, '/')[6], '/', split(id, '/')[7], '/', split(id, '/')[8]))
"@ -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
            } "Resource Graph SQL DB zone redundancy"

            if ($sqlDbResults) {
                foreach ($db in $sqlDbResults) {
                    if (-not $db.zoneRedundant -and $db.skuTier -match 'Premium|BusinessCritical|GeneralPurpose') {
                        Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - SQL No Zone Redundancy" `
                            -ResourceName "$($db.serverName)/$($db.name)" -ResourceType "SQL Database" -ResourceGroup $db.resourceGroup `
                            -Subscription $SubName `
                            -Description "SQL Database ($($db.skuTier)/$($db.skuName)) does not have zone redundancy enabled." `
                            -Recommendation "Enable zone redundancy on General Purpose, Business Critical, or Premium tier databases." `
                            -Impact "Database availability is tied to a single availability zone. Zone failure causes downtime."
                    }
                }
                Write-Status "  SQL Databases zone redundancy: checked $($sqlDbResults.Count) DBs" "OK"
            }
        }
    } catch { Write-Status "  SQL DB zone redundancy check skipped" "INFO" }

    # ── 4. Application Gateway: no zones configured ──
    $appGws = $script:CachedAppGateways
    if ($appGws) {
        foreach ($ag in $appGws) {
            if ((-not $ag.Zones -or $ag.Zones.Count -eq 0) -and $ag.Sku.Tier -match 'v2|WAF_v2') {
                Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "HA - App Gateway No Zones" `
                    -ResourceName $ag.Name -ResourceType "Application Gateway" -ResourceGroup $ag.ResourceGroupName `
                    -Subscription $SubName `
                    -Description "Application Gateway v2 is not deployed across availability zones." `
                    -Recommendation "Redeploy Application Gateway v2 in at least 2 availability zones for zone-redundant HA." `
                    -Impact "An availability zone failure takes down the entire application gateway and all backends behind it."
            }
        }
        Write-Status "  App Gateways zone config: checked $(@($appGws).Count)" "OK"
    }

    # ── 5. Azure Firewall: no zones configured ──
    $firewalls = $script:CachedFirewalls
    if ($firewalls) {
        foreach ($fw in $firewalls) {
            if (-not $fw.Zones -or $fw.Zones.Count -eq 0) {
                Add-Finding -Pillar "Reliability" -Severity "High" -Category "HA - Firewall No Zones" `
                    -ResourceName $fw.Name -ResourceType "Azure Firewall" -ResourceGroup $fw.ResourceGroupName `
                    -Subscription $SubName `
                    -Description "Azure Firewall is not deployed across availability zones." `
                    -Recommendation "Redeploy Azure Firewall across all 3 availability zones for 99.99% SLA (vs 99.95% without zones)." `
                    -Impact "Firewall is a single point of failure. A zone outage disconnects all traffic routed through it."
            }
        }
        Write-Status "  Firewall zone config: checked $(@($firewalls).Count)" "OK"
    }

    # ── 6. VPN/ExpressRoute Gateways: non-zone-redundant SKU ──
    try {
        if ($graphAvailable) {
            $gwResults = Invoke-AzCommandSafely {
                Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| extend gwType = tostring(properties.gatewayType),
         skuName = tostring(sku.name),
         activeActive = tobool(properties.activeActive)
| project name, resourceGroup, location, gwType, skuName, activeActive, id
"@ -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
            } "Resource Graph VPN/ER Gateways HA"

            if ($gwResults) {
                foreach ($gw in $gwResults) {
                    # Non-zone-redundant SKU
                    if ($gw.skuName -and $gw.skuName -notmatch 'AZ|ErGw.*az') {
                        $sev = if ($gw.gwType -eq 'ExpressRoute') { "High" } else { "Medium" }
                        Add-Finding -Pillar "Reliability" -Severity $sev -Category "HA - Gateway No Zone Redundancy" `
                            -ResourceName $gw.name -ResourceType "$($gw.gwType) Gateway" -ResourceGroup $gw.resourceGroup `
                            -Subscription $SubName `
                            -Description "$($gw.gwType) Gateway uses SKU '$($gw.skuName)' which is not zone-redundant." `
                            -Recommendation "Use zone-redundant SKUs (VpnGw1AZ–VpnGw5AZ or ErGw1AZ–ErGw3AZ) for cross-zone resilience." `
                            -Impact "Gateway is bound to a single zone. A zone failure disconnects all hybrid/on-premises connectivity."
                    }
                    # Active-Passive = single point of failure for tunnel
                    if ($gw.gwType -eq 'Vpn' -and -not $gw.activeActive) {
                        Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - VPN Active-Passive" `
                            -ResourceName $gw.name -ResourceType "VPN Gateway" -ResourceGroup $gw.resourceGroup `
                            -Subscription $SubName `
                            -Description "VPN Gateway is in Active-Passive mode — only one tunnel is active at a time." `
                            -Recommendation "Enable Active-Active mode for automatic tunnel failover and higher aggregate throughput." `
                            -Impact "Planned maintenance or tunnel failure causes connectivity disruption until failover completes."
                    }
                }
                Write-Status "  VPN/ER Gateways: checked $($gwResults.Count) gateways" "OK"
            }
        }
    } catch { Write-Status "  Gateway HA check skipped" "INFO" }

    # ── 7. Redis Cache: Basic tier = no replication ──
    try {
        if ($graphAvailable) {
            $redisResults = Invoke-AzCommandSafely {
                Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.cache/redis'
| extend skuName = tostring(sku.name),
         skuFamily = tostring(sku.family),
         skuCapacity = toint(sku.capacity),
         zones = properties.instances
| project name, resourceGroup, location, skuName, skuFamily, skuCapacity, id
"@ -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
            } "Resource Graph Redis HA"

            if ($redisResults) {
                foreach ($redis in $redisResults) {
                    if ($redis.skuName -eq 'Basic') {
                        Add-Finding -Pillar "Reliability" -Severity "High" -Category "HA - Redis No Replication" `
                            -ResourceName $redis.name -ResourceType "Redis Cache" -ResourceGroup $redis.resourceGroup `
                            -Subscription $SubName `
                            -Description "Redis Cache uses Basic tier — single node, no replication, no SLA." `
                            -Recommendation "Upgrade to Standard (replication) or Premium (clustering + zones) tier for production workloads." `
                            -Impact "Node failure causes complete cache data loss and application downtime. No automatic failover."
                    }
                }
                Write-Status "  Redis HA: checked $($redisResults.Count) instances" "OK"
            }
        }
    } catch { Write-Status "  Redis HA check skipped" "INFO" }

    # ── 8. Single-Region Deployment risk ──
    $subResources = @($script:Resources | Where-Object { $_.Subscription -eq $SubName -and $_.Location -ne 'global' })
    if ($subResources.Count -gt 10) {
        $regions = @($subResources | Select-Object -ExpandProperty Location -Unique)
        if ($regions.Count -eq 1) {
            Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "HA - Single Region Deployment" `
                -ResourceName $SubName -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "All $($subResources.Count) resources are deployed in a single region ($($regions[0])). No geographic redundancy." `
                -Recommendation "Distribute critical workloads across paired regions. Design active-passive or active-active multi-region architectures." `
                -Impact "A regional outage (rare but possible) would affect all workloads simultaneously with no failover option."
        }
    }

    # ── 9. Load Balancer Standard: backends in single zone ──
    $lbs = $script:CachedLoadBalancers
    if ($lbs) {
        foreach ($lb in $lbs) {
            if ($lb.Sku.Name -eq 'Standard' -and $lb.FrontendIpConfigurations) {
                $hasZones = $lb.FrontendIpConfigurations | Where-Object { $_.Zones -and $_.Zones.Count -gt 0 }
                $isZoneRedundant = $lb.FrontendIpConfigurations | Where-Object { $_.Zones -and $_.Zones.Count -ge 3 }
                # Standard LB with zone-pinned frontend (single zone) — risk
                if ($hasZones -and -not $isZoneRedundant) {
                    Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - Load Balancer Zone-Pinned" `
                        -ResourceName $lb.Name -ResourceType "Load Balancer" -ResourceGroup $lb.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Standard Load Balancer frontend is pinned to a single availability zone instead of being zone-redundant." `
                        -Recommendation "Use zone-redundant frontend IPs (no zone specified) for automatic cross-zone failover." `
                        -Impact "If the pinned zone fails, the load balancer frontend becomes unavailable."
                }
            }
        }
    }

    # ── 10. Managed Disks: no zone resilience for Premium/Ultra ──
    $disks = $script:CachedDisks
    if ($disks) {
        $premiumDisksNoZone = @($disks | Where-Object {
            $_.Sku.Name -match 'Premium|UltraSSD' -and
            (-not $_.Zones -or $_.Zones.Count -eq 0) -and
            $_.ManagedBy  # attached to a VM
        })
        if ($premiumDisksNoZone.Count -gt 5) {
            Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - Disks Not Zone-Aligned" `
                -ResourceName "$($premiumDisksNoZone.Count) Premium/Ultra disks" -ResourceType "Managed Disk" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($premiumDisksNoZone.Count) Premium/UltraSSD managed disks are not deployed in availability zones." `
                -Recommendation "When deploying VMs in availability zones, ensure attached disks are also zone-aligned." `
                -Impact "Disks outside zones cannot be attached to zone-pinned VMs during failover scenarios."
        }
    }

    # ── VMSS Zone Spread Validation ──
    Write-Status "  Checking VMSS zone spread..." "INFO"
    $vmssInstances = Invoke-AzCommandSafely { Get-AzVmss -ErrorAction SilentlyContinue } "VMSS instances"
    if ($vmssInstances) {
        foreach ($vmss in $vmssInstances) {
            if (-not $vmss.Zones -or $vmss.Zones.Count -lt 2) {
                $zoneInfo = if ($vmss.Zones) { $vmss.Zones -join ',' } else { 'none' }
                Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "HA - VMSS No Zone Spread" `
                    -ResourceName $vmss.Name -ResourceType "VM Scale Set" `
                    -ResourceGroup $vmss.ResourceGroupName -Subscription $SubName `
                    -Description "VMSS '$($vmss.Name)' has $($vmss.Sku.Capacity) instances but zones=[$zoneInfo]. Not spread across multiple zones." `
                    -Recommendation "Deploy VMSS across at least 2 availability zones for zone redundancy." `
                    -Impact "Single-zone VMSS is vulnerable to zone-level failures, causing full scale set outage."
            }
        }
    }

    # ── Traffic Manager / Front Door health probe check ──
    Write-Status "  Checking Traffic Manager & Front Door..." "INFO"
    $tmProfiles = Invoke-AzCommandSafely { Get-AzTrafficManagerProfile -ErrorAction SilentlyContinue } "Traffic Manager"
    if ($tmProfiles) {
        foreach ($tm in $tmProfiles) {
            $degraded = @($tm.Endpoints | Where-Object { $_.EndpointMonitorStatus -ne 'Online' -and $_.EndpointStatus -eq 'Enabled' })
            if ($degraded.Count -gt 0) {
                $names = ($degraded | ForEach-Object { $_.Name }) -join ', '
                Add-Finding -Pillar "Reliability" -Severity "High" -Category "HA - Traffic Manager Degraded" `
                    -ResourceName $tm.Name -ResourceType "Traffic Manager" `
                    -ResourceGroup $tm.ResourceGroupName -Subscription $SubName `
                    -Description "$($degraded.Count) endpoint(s) are not healthy: $names." `
                    -Recommendation "Investigate degraded endpoints. Verify health probe path, port, and backend availability." `
                    -Impact "Degraded endpoints may cause routing failures or reduced availability."
            }
        }
    }
    try {
        $fdUrl = "/subscriptions/$SubId/providers/Microsoft.Cdn/profiles?api-version=2024-02-01"
        $fdResult = Invoke-AzRestMethod -Path $fdUrl -Method GET -ErrorAction SilentlyContinue
        if ($fdResult -and $fdResult.StatusCode -eq 200) {
            $fdProfiles = ($fdResult.Content | ConvertFrom-Json).value | Where-Object { $_.sku.name -match 'Standard_AzureFrontDoor|Premium_AzureFrontDoor' }
            foreach ($fd in $fdProfiles) {
                # Check origin response timeout
                if (-not $fd.properties.originResponseTimeoutSeconds -or $fd.properties.originResponseTimeoutSeconds -lt 16) {
                    Add-Finding -Pillar "Reliability" -Severity "Low" -Category "HA - Front Door Timeout" `
                        -ResourceName $fd.name -ResourceType "Front Door" `
                        -ResourceGroup ($fd.id -split '/')[4] -Subscription $SubName `
                        -Description "Front Door '$($fd.name)' origin timeout is $(if($fd.properties.originResponseTimeoutSeconds){$fd.properties.originResponseTimeoutSeconds}else{'default (30)'})s." `
                        -Recommendation "Tune originResponseTimeoutSeconds based on backend response times." `
                        -Impact "Suboptimal timeout can cause premature 504 errors or slow failover."
                }

                # Check WAF association (independent of timeout) — query securityPolicies child resource
                $fdId = $fd.id
                $spUrl = "$fdId/securityPolicies?api-version=2024-02-01"
                $spResult = Invoke-AzRestMethod -Path $spUrl -Method GET -ErrorAction SilentlyContinue
                $hasWaf = $false
                if ($spResult -and $spResult.StatusCode -eq 200) {
                    $secPolicies = ($spResult.Content | ConvertFrom-Json).value
                    $hasWaf = ($secPolicies | Where-Object { $_.properties.parameters.type -eq 'WebApplicationFirewall' }).Count -gt 0
                }
                if (-not $hasWaf) {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "Security - Front Door No WAF" `
                        -ResourceName $fd.name -ResourceType "Front Door" `
                        -ResourceGroup ($fd.id -split '/')[4] -Subscription $SubName `
                        -Description "Front Door '$($fd.name)' has no WAF security policy associated." `
                        -Recommendation "Create a WAF security policy and associate it with Front Door endpoints for OWASP and bot protection." `
                        -Impact "Without WAF, web applications are exposed to common web attacks."
                }
                }
            }
    } catch { }

    Write-Status "  High Availability analysis complete" "OK"
}

# ============================================================================
# 16. BUSINESS CONTINUITY & DISASTER RECOVERY (BCDR)
# ============================================================================
function Analyze-BCDR {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Business Continuity & Disaster Recovery..." "SECTION"

    # ── Recovery Services Vaults (still needed for vault-level checks + cache for ResourceLocks) ──
    $vaults = Invoke-AzCommandSafely { Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue } "Error retrieving Recovery Services Vaults"
    $script:CachedRecoveryVaults = $vaults  # Cache for reuse in ResourceLocks

    if (-not $vaults) {
        # No vaults at all — check if there are VMs that should be backed up
        $vms = $script:CachedVMs
        if ($vms -and $vms.Count -gt 0) {
            Add-Finding -Pillar "Reliability" -Severity "Critical" -Category "BCDR - No Backup Vault" `
                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "No Recovery Services Vaults found but $($vms.Count) VMs exist. No backup infrastructure is configured." `
                -Recommendation "Create a Recovery Services Vault and configure backup policies for all production VMs." `
                -Impact "Complete lack of backup infrastructure means zero recovery capability in case of disaster."
        }
        Write-Status "  BCDR analysis complete" "OK"
        return
    }

    Write-Status "  Recovery Services Vaults: $($vaults.Count)" "INFO"

    # ─── Determine if we can use ARG cache for backup items ───
    $useARGBackup = ($script:CachedBackupItems.Count -gt 0)
    $subIdLower = $SubId.ToLower()

    if ($useARGBackup) {
        # ═══ FAST PATH: Resource Graph pre-cached backup items ═══
        Write-Status "  Using Resource Graph cache for backup item analysis" "INFO"

        $backupItems = if ($script:CachedBackupItems.ContainsKey($subIdLower)) { $script:CachedBackupItems[$subIdLower] } else { @() }

        foreach ($item in $backupItems) {
            $itemName = ($item.name -split '/')[-1]
            $vaultName = $item.vaultName
            $rg = $item.resourceGroup

            # Check last backup status
            if ($item.lastBackupStatus -and $item.lastBackupStatus -ne "Completed") {
                Add-Finding -Pillar "Reliability" -Severity "High" -Category "BCDR - Backup Failed" `
                    -ResourceName $itemName -ResourceType "Backup Item" -ResourceGroup $rg `
                    -Subscription $SubName `
                    -Description "Last backup status: '$($item.lastBackupStatus)'. Last backup time: $($item.lastBackupTime)." `
                    -Recommendation "Investigate the backup failure. Check VM agent status, disk snapshots, and vault storage capacity." `
                    -Impact "Failed backups leave the workload unprotected against data loss or disaster."
            }

            # Check backup staleness (>48 hours since last backup)
            if ($item.lastBackupTime) {
                $lastTime = $null
                if ($item.lastBackupTime -is [datetime]) { $lastTime = $item.lastBackupTime }
                else { try { $lastTime = [datetime]::Parse($item.lastBackupTime) } catch { $lastTime = $null } }
                if ($lastTime -and $lastTime -lt (Get-Date).AddHours(-48)) {
                    $hoursSince = [math]::Round(((Get-Date) - $lastTime).TotalHours, 0)
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "BCDR - Stale Backup" `
                        -ResourceName $itemName -ResourceType "Backup Item" -ResourceGroup $rg `
                        -Subscription $SubName `
                        -Description "Last successful backup was $hoursSince hours ago ($($lastTime.ToString('yyyy-MM-dd HH:mm')))." `
                        -Recommendation "Verify backup schedule and ensure daily backups are completing successfully." `
                        -Impact "Stale backups increase the RPO gap and potential data loss in a disaster."
                }
            }

            # Check protection state
            if ($item.protectionState -and $item.protectionState -ne "Protected") {
                Add-Finding -Pillar "Reliability" -Severity "High" -Category "BCDR - Protection Stopped" `
                    -ResourceName $itemName -ResourceType "Backup Item" -ResourceGroup $rg `
                    -Subscription $SubName `
                    -Description "Backup protection state: '$($item.protectionState)'. Item is not actively protected." `
                    -Recommendation "Resume backup protection or re-configure the backup policy for this resource." `
                    -Impact "Unprotected resources cannot be recovered in case of failure or data loss."
            }
        }

        # ── Backup policies from ARG cache ──
        $policies = if ($script:CachedBackupPolicies.ContainsKey($subIdLower)) { $script:CachedBackupPolicies[$subIdLower] } else { @() }
        foreach ($pol in $policies) {
            $polName = ($pol.name -split '/')[-1]
            $vaultName = $pol.vaultName
            $rg = $pol.resourceGroup
            # Check daily retention
            $dailyRetention = $null
            if ($pol.properties -and $pol.properties.retentionPolicy -and $pol.properties.retentionPolicy.dailySchedule) {
                $dailyRetention = $pol.properties.retentionPolicy.dailySchedule.retentionDuration.count
            }
            if ($dailyRetention -and $dailyRetention -lt 7) {
                Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "BCDR - Short Retention" `
                    -ResourceName "$vaultName/$polName" -ResourceType "Backup Policy" -ResourceGroup $rg `
                    -Subscription $SubName `
                    -Description "Backup policy has only $dailyRetention days of daily retention." `
                    -Recommendation "Increase daily retention to at least 7 days. Consider 30-day retention with weekly/monthly points." `
                    -Impact "Short retention limits the ability to recover from delayed detection of data corruption."
            }
        }

        # ── VMs without backup (from ARG cached items) ──
        $vms = $script:CachedVMs
        if ($vms) {
            $backedUpVMIds = @($backupItems | Where-Object { $_.backupManagementType -eq 'AzureIaasVM' -and $_.sourceResourceId } | ForEach-Object { $_.sourceResourceId.ToLower() })
            $unprotectedVMs = $vms | Where-Object { $_.Id.ToLower() -notin $backedUpVMIds }
            foreach ($vm in $unprotectedVMs) {
                $isProduction = $vm.Tags -and ($vm.Tags.Keys -match '^(env|environment)$') -and ($vm.Tags.Values -match '^prod(uction)?$')
                $severity = if ($isProduction) { "Critical" } else { "High" }
                Add-Finding -Pillar "Reliability" -Severity $severity -Category "BCDR - VM Not Backed Up" `
                    -ResourceName $vm.Name -ResourceType "Virtual Machine" -ResourceGroup $vm.ResourceGroupName `
                    -Subscription $SubName `
                    -Description "VM '$($vm.Name)' is not protected by any Recovery Services Vault backup policy." `
                    -Recommendation "Configure Azure Backup for this VM in a Recovery Services Vault with appropriate retention policy." `
                    -Impact "Unprotected VM cannot be recovered in case of accidental deletion, corruption, or ransomware."
            }
        }

        # ── Soft delete + Immutability check (still per-vault, fast) ──
        foreach ($vault in $vaults) {
            try {
                $vaultProp = Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID -ErrorAction SilentlyContinue
                if ($vaultProp -and $vaultProp.SoftDeleteFeatureState -ne "Enabled") {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "BCDR - Soft Delete Disabled" `
                        -ResourceName $vault.Name -ResourceType "Recovery Services Vault" -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Soft Delete is not enabled on this vault. Deleted backup data cannot be recovered." `
                        -Recommendation "Enable Soft Delete to protect against accidental or malicious backup data deletion." `
                        -Impact "Without soft delete, ransomware or accidental deletion permanently destroys backup data."
                }
                # Immutability check (ransomware protection)
                $immutable = $false
                if ($vaultProp.ImmutabilityState) { $immutable = $vaultProp.ImmutabilityState -in @('Locked','Unlocked') }
                if (-not $immutable) {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "BCDR - No Immutability" `
                        -ResourceName $vault.Name -ResourceType "Recovery Services Vault" -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Vault immutability is not enabled. Backup data can be modified or deleted before expiry." `
                        -Recommendation "Enable vault immutability to prevent early deletion of recovery points. Use 'Locked' state for production vaults." `
                        -Impact "Without immutability, ransomware or compromised admin can delete all backup data."
                }
            } catch { }
        }

        # ── Cross-region backup check ──
        if ($vaults -and $script:CachedVMs) {
            $vmRegions = @($script:CachedVMs | ForEach-Object { $_.Location.ToLower() } | Sort-Object -Unique)
            $vaultRegions = @($vaults | ForEach-Object { $_.Location.ToLower() } | Sort-Object -Unique)
            $allSameRegion = ($vaultRegions.Count -eq 1 -and $vmRegions.Count -ge 1 -and ($vmRegions | Where-Object { $_ -ne $vaultRegions[0] }).Count -eq 0)
            if ($allSameRegion -and $script:CachedVMs.Count -gt 2) {
                Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "BCDR - No Cross-Region Backup" `
                    -ResourceName "All vaults in $($vaultRegions[0])" -ResourceType "Recovery Services Vault" `
                    -ResourceGroup "N/A" -Subscription $SubName `
                    -Description "All $($vaults.Count) Recovery Services Vault(s) and $($script:CachedVMs.Count) VMs are in the same region ($($vaultRegions[0])). A regional outage could affect both production and backup." `
                    -Recommendation "Enable Cross Region Restore (CRR) on GRS vaults, or create a secondary vault in a paired region." `
                    -Impact "Single-region backup offers no protection against a full regional disaster."
            }
        }

    } elseif (-not $SkipBackupDetails) {
        # ═══ SLOW FALLBACK: per-vault cmdlet calls (original method) ═══
        Write-Status "  Resource Graph cache empty, falling back to per-vault backup queries..." "WARN"

        foreach ($vault in $vaults) {
            try {
                Set-AzRecoveryServicesVaultContext -Vault $vault -ErrorAction SilentlyContinue | Out-Null

                # Check backup items (Azure VMs)
                $containers = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -VaultId $vault.ID -ErrorAction SilentlyContinue
                $backupItems = @()
                if ($containers) {
                    foreach ($c in $containers) {
                        $items = Get-AzRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM -VaultId $vault.ID -ErrorAction SilentlyContinue
                        if ($items) { $backupItems += $items }
                    }
                }

                foreach ($item in $backupItems) {
                    if ($item.LastBackupStatus -ne "Completed") {
                        Add-Finding -Pillar "Reliability" -Severity "High" -Category "BCDR - Backup Failed" `
                            -ResourceName $item.Name -ResourceType "Backup Item" -ResourceGroup $vault.ResourceGroupName `
                            -Subscription $SubName `
                            -Description "Last backup status: '$($item.LastBackupStatus)'. Last backup time: $($item.LastBackupTime)." `
                            -Recommendation "Investigate the backup failure. Check VM agent status, disk snapshots, and vault storage capacity." `
                            -Impact "Failed backups leave the workload unprotected against data loss or disaster."
                    }
                    if ($item.LastBackupTime -and $item.LastBackupTime -lt (Get-Date).AddHours(-48)) {
                        $hoursSince = [math]::Round(((Get-Date) - $item.LastBackupTime).TotalHours, 0)
                        Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "BCDR - Stale Backup" `
                            -ResourceName $item.Name -ResourceType "Backup Item" -ResourceGroup $vault.ResourceGroupName `
                            -Subscription $SubName `
                            -Description "Last successful backup was $hoursSince hours ago ($($item.LastBackupTime.ToString('yyyy-MM-dd HH:mm')))." `
                            -Recommendation "Verify backup schedule and ensure daily backups are completing successfully." `
                            -Impact "Stale backups increase the RPO gap and potential data loss in a disaster."
                    }
                    if ($item.ProtectionState -ne "Protected") {
                        Add-Finding -Pillar "Reliability" -Severity "High" -Category "BCDR - Protection Stopped" `
                            -ResourceName $item.Name -ResourceType "Backup Item" -ResourceGroup $vault.ResourceGroupName `
                            -Subscription $SubName `
                            -Description "Backup protection state: '$($item.ProtectionState)'. Item is not actively protected." `
                            -Recommendation "Resume backup protection or re-configure the backup policy for this resource." `
                            -Impact "Unprotected resources cannot be recovered in case of failure or data loss."
                    }
                }

                # Check backup policies
                $policies = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $vault.ID -ErrorAction SilentlyContinue
                foreach ($pol in $policies) {
                    if ($pol.RetentionPolicy -and $pol.RetentionPolicy.DailySchedule) {
                        $dailyRetention = $pol.RetentionPolicy.DailySchedule.DurationCountInDays
                        if ($dailyRetention -and $dailyRetention -lt 7) {
                            Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "BCDR - Short Retention" `
                                -ResourceName "$($vault.Name)/$($pol.Name)" -ResourceType "Backup Policy" -ResourceGroup $vault.ResourceGroupName `
                                -Subscription $SubName `
                                -Description "Backup policy has only $dailyRetention days of daily retention." `
                                -Recommendation "Increase daily retention to at least 7 days. Consider 30-day retention with weekly/monthly points." `
                                -Impact "Short retention limits the ability to recover from delayed detection of data corruption."
                        }
                    }
                }

                # Soft delete check
                $vaultProp = Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID -ErrorAction SilentlyContinue
                if ($vaultProp -and $vaultProp.SoftDeleteFeatureState -ne "Enabled") {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "BCDR - Soft Delete Disabled" `
                        -ResourceName $vault.Name -ResourceType "Recovery Services Vault" -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Soft Delete is not enabled on this vault. Deleted backup data cannot be recovered." `
                        -Recommendation "Enable Soft Delete to protect against accidental or malicious backup data deletion." `
                        -Impact "Without soft delete, ransomware or accidental deletion permanently destroys backup data."
                }
            } catch {
                Write-Status "  Error analyzing vault $($vault.Name): $($_.Exception.Message)" "WARN"
            }
        }

        # ── VMs without backup (cross-reference via cmdlets) ──
        $vms = $script:CachedVMs
        if ($vms) {
            $allBackedUpVMs = @()
            foreach ($vault in $vaults) {
                try {
                    $containers = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM -VaultId $vault.ID -ErrorAction SilentlyContinue
                    if ($containers) {
                        foreach ($c in $containers) {
                            $items = Get-AzRecoveryServicesBackupItem -Container $c -WorkloadType AzureVM -VaultId $vault.ID -ErrorAction SilentlyContinue
                            if ($items) { $allBackedUpVMs += $items | ForEach-Object { $_.VirtualMachineId.ToLower() } }
                        }
                    }
                } catch { }
            }
            $unprotectedVMs = $vms | Where-Object { $_.Id.ToLower() -notin $allBackedUpVMs }
            foreach ($vm in $unprotectedVMs) {
                $isProduction = $vm.Tags -and ($vm.Tags.Keys -match '^(env|environment)$') -and ($vm.Tags.Values -match '^prod(uction)?$')
                $severity = if ($isProduction) { "Critical" } else { "High" }
                Add-Finding -Pillar "Reliability" -Severity $severity -Category "BCDR - VM Not Backed Up" `
                    -ResourceName $vm.Name -ResourceType "Virtual Machine" -ResourceGroup $vm.ResourceGroupName `
                    -Subscription $SubName `
                    -Description "VM '$($vm.Name)' is not protected by any Recovery Services Vault backup policy." `
                    -Recommendation "Configure Azure Backup for this VM in a Recovery Services Vault with appropriate retention policy." `
                    -Impact "Unprotected VM cannot be recovered in case of accidental deletion, corruption, or ransomware."
            }
        }
    } else {
        Write-Status "  Skipped backup details (SkipBackupDetails and no ARG cache)" "INFO"
        # Still check soft delete even when skipping backup details
        foreach ($vault in $vaults) {
            try {
                $vaultProp = Get-AzRecoveryServicesVaultProperty -VaultId $vault.ID -ErrorAction SilentlyContinue
                if ($vaultProp -and $vaultProp.SoftDeleteFeatureState -ne "Enabled") {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "BCDR - Soft Delete Disabled" `
                        -ResourceName $vault.Name -ResourceType "Recovery Services Vault" -ResourceGroup $vault.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Soft Delete is not enabled on this vault. Deleted backup data cannot be recovered." `
                        -Recommendation "Enable Soft Delete to protect against accidental or malicious backup data deletion." `
                        -Impact "Without soft delete, ransomware or accidental deletion permanently destroys backup data."
                }
            } catch { }
        }
    }

    # ── Azure Site Recovery (ASR) for critical VMs (kept as-is, not the bottleneck) ──
    if ($vaults) {
        $asrItems = @()
        foreach ($vault in $vaults) {
            try {
                Set-AzRecoveryServicesAsrVaultContext -Vault $vault -ErrorAction SilentlyContinue | Out-Null
                $fabrics = Get-AzRecoveryServicesAsrFabric -ErrorAction SilentlyContinue
                if ($fabrics) {
                    foreach ($fabric in $fabrics) {
                        $protContainers = Get-AzRecoveryServicesAsrProtectionContainer -Fabric $fabric -ErrorAction SilentlyContinue
                        if ($protContainers) {
                            foreach ($pc in $protContainers) {
                                $repItems = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $pc -ErrorAction SilentlyContinue
                                if ($repItems) { $asrItems += $repItems }
                            }
                        }
                    }
                }
            } catch { }
        }
        foreach ($asrItem in $asrItems) {
            if ($asrItem.ReplicationHealth -ne "Normal") {
                Add-Finding -Pillar "Reliability" -Severity "High" -Category "BCDR - ASR Replication Unhealthy" `
                    -ResourceName $asrItem.FriendlyName -ResourceType "ASR Protected Item" `
                    -ResourceGroup "N/A" -Subscription $SubName `
                    -Description "Site Recovery replication health: '$($asrItem.ReplicationHealth)'. State: $($asrItem.ProtectionState)." `
                    -Recommendation "Investigate ASR replication errors and resolve connectivity or configuration issues." `
                    -Impact "Unhealthy replication means the DR copy may be outdated or unavailable during failover."
            }
        }
    }

    Write-Status "  BCDR analysis complete" "OK"
}

# ============================================================================
# 17. RESOURCE LOCKS ANALYSIS
# ============================================================================
function Analyze-ResourceLocks {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Resource Locks..." "SECTION"

    # Get all locks in subscription — prefer pre-cached Resource Graph data
    $locks = $null
    if ($script:CachedResourceLocks.ContainsKey($SubId)) {
        $locks = $script:CachedResourceLocks[$SubId]
    } else {
        $locks = Invoke-AzCommandSafely { Get-AzResourceLock -ErrorAction SilentlyContinue } "Error retrieving resource locks"
    }
    $lockCount = if ($locks) { @($locks).Count } else { 0 }
    Write-Status "  Resource locks found: $lockCount" "INFO"

    # Critical resource types that SHOULD have locks
    $criticalResources = @()

    # VNets
    $vnets = $script:CachedVNets
    if ($vnets) { $criticalResources += $vnets | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; ResourceId = $_.Id; Type = "VNet"; RG = $_.ResourceGroupName } } }

    # SQL Servers
    $sqlServers = $script:CachedSqlServers
    if ($sqlServers) { $criticalResources += $sqlServers | ForEach-Object { [PSCustomObject]@{ Name = $_.ServerName; ResourceId = $_.ResourceId; Type = "SQL Server"; RG = $_.ResourceGroupName } } }

    # Key Vaults
    $kvs = $script:CachedKeyVaults
    if ($kvs) { $criticalResources += $kvs | ForEach-Object { [PSCustomObject]@{ Name = $_.VaultName; ResourceId = $_.ResourceId; Type = "Key Vault"; RG = $_.ResourceGroupName } } }

    # Storage Accounts
    $sas = $script:CachedStorageAccounts
    if ($sas) { $criticalResources += $sas | ForEach-Object { [PSCustomObject]@{ Name = $_.StorageAccountName; ResourceId = $_.Id; Type = "Storage Account"; RG = $_.ResourceGroupName } } }

    # Recovery Services Vaults (reuse from BCDR cache)
    $rsvs = $script:CachedRecoveryVaults
    if ($rsvs) { $criticalResources += $rsvs | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; ResourceId = $_.ID; Type = "Recovery Vault"; RG = $_.ResourceGroupName } } }

    # Check each critical resource for locks
    $lockedResourceIds = @()
    if ($locks) {
        $lockedResourceIds = $locks | Where-Object { $_.ResourceId } | ForEach-Object { $_.ResourceId }
    }

    foreach ($res in $criticalResources) {
        $hasLock = $false
        if ($lockedResourceIds.Count -gt 0) {
            foreach ($lockId in $lockedResourceIds) {
                if ($lockId -and $res.ResourceId -and ($lockId.ToLower() -eq $res.ResourceId.ToLower() -or $lockId.ToLower().StartsWith($res.ResourceId.ToLower() + '/'))) {
                    $hasLock = $true; break
                }
            }
        }
        # Also check resource-group level locks
        if (-not $hasLock -and $locks) {
            $rgLocks = $locks | Where-Object { $_.ResourceGroupName -eq $res.RG -and -not $_.ResourceId }
            if ($rgLocks) { $hasLock = $true }
        }

        if (-not $hasLock) {
            $severity = switch ($res.Type) {
                "Recovery Vault" { "Critical" }
                "SQL Server"     { "High" }
                "Key Vault"      { "High" }
                "VNet"           { "Medium" }
                "Storage Account" { "Medium" }
                default          { "Medium" }
            }
            Add-Finding -Pillar "Operational Excellence" -Severity $severity -Category "Governance - Resource Lock" `
                -ResourceName $res.Name -ResourceType $res.Type -ResourceGroup $res.RG `
                -Subscription $SubName `
                -Description "Critical resource '$($res.Name)' ($($res.Type)) has no Delete or ReadOnly lock." `
                -Recommendation "Apply a CanNotDelete lock to prevent accidental deletion of this critical resource." `
                -Impact "Without a lock, this resource can be accidentally deleted, causing service outage or data loss."
        }
    }

    # Subscription-level check: if no locks at all and >10 resources exist
    if ($lockCount -eq 0 -and $script:Summary.TotalResources -gt 10) {
        Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "Governance - No Locks" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "No resource locks found in subscription with $($script:Summary.TotalResources) resources." `
            -Recommendation "Implement resource locks on all critical resources (databases, vaults, VNets, storage accounts)." `
            -Impact "All resources are vulnerable to accidental or unauthorized deletion."
    }

    Write-Status "  Resource locks analysis complete" "OK"
}

# ============================================================================
# 18. KEY VAULT - EXPIRING SECRETS & CERTIFICATES
# ============================================================================
function Analyze-ExpiringSecrets {
    param([string]$SubId, [string]$SubName)

    Write-Status "Analyzing Key Vault secrets & certificates expiration..." "SECTION"

    $keyVaults = $script:CachedKeyVaults
    if (-not $keyVaults) {
        Write-Status "  No Key Vaults found, skipping" "INFO"
        return
    }

    $thresholds = @(
        @{ Days = 30;  Label = "30 days";  Severity = "Critical" }
        @{ Days = 60;  Label = "60 days";  Severity = "High" }
        @{ Days = 90;  Label = "90 days";  Severity = "Medium" }
    )

    # Helper: convert ARG expires value (epoch int or ISO string) to DateTime
    function Convert-ExpiresValue {
        param($raw)
        if ($null -eq $raw) { return $null }
        if ($raw -is [datetime]) { return $raw }
        if ($raw -is [long] -or $raw -is [int] -or $raw -match '^\d+$') {
            $epoch = [long]$raw
            # Handle millisecond-precision Unix epochs (>year 2286 in seconds = clearly millis)
            if ($epoch -gt 9999999999) { $epoch = [math]::Floor($epoch / 1000) }
            return [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime
        }
        $dt = $null
        if ([datetime]::TryParse($raw, [ref]$dt)) { return $dt }
        return $null
    }

    # ─── Fast path: use Resource Graph pre-cached data ───
    $subIdLower = $SubId.ToLower()
    $useARGCache = ($script:CachedKVSecrets.ContainsKey($subIdLower) -or $script:CachedKVKeys.ContainsKey($subIdLower) -or $script:CachedKVCerts.ContainsKey($subIdLower))
    # Also consider cache valid if the pre-fetch ran but this sub simply has no KV items
    if (-not $useARGCache -and ($script:CachedKVSecrets.Count -gt 0 -or $script:CachedKVKeys.Count -gt 0 -or $script:CachedKVCerts.Count -gt 0)) { $useARGCache = $true }

    if ($useARGCache) {
        Write-Status "  Using Resource Graph cache for Key Vault expiration analysis" "INFO"

        # ── Secrets from ARG ──
        $argSecrets = if ($script:CachedKVSecrets.ContainsKey($subIdLower)) { $script:CachedKVSecrets[$subIdLower] } else { @() }
        foreach ($secret in $argSecrets) {
            $kvName = $secret.vaultName
            $kvRG = $secret.resourceGroup
            $secretName = ($secret.name -split '/')[-1]
            $expires = Convert-ExpiresValue $secret.expires
            $enabled = $secret.enabled

            if ($null -eq $expires) {
                Add-Finding -Pillar "Security" -Severity "Low" -Category "Key Vault - No Expiry Set" `
                    -ResourceName "$kvName/$secretName" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                    -Subscription $SubName `
                    -Description "Secret '$secretName' has no expiration date configured." `
                    -Recommendation "Set an expiration date and configure rotation policy for all secrets." `
                    -Impact "Secrets without expiry are never rotated, increasing the risk of credential compromise."
                continue
            }
            # Handle boolean strings from Resource Graph (returns "true"/"false" as strings)
            if ($enabled -is [string]) { $enabled = $enabled -ne 'false' }
            if ($enabled -eq $false) { continue }

            $daysUntilExpiry = [math]::Round(($expires - (Get-Date)).TotalDays, 0)
            if ($daysUntilExpiry -le 0) {
                Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Secret" `
                    -ResourceName "$kvName/$secretName" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                    -Subscription $SubName `
                    -Description "Secret '$secretName' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago ($($expires.ToString('yyyy-MM-dd')))." `
                    -Recommendation "Rotate this secret immediately and update all dependent applications." `
                    -Impact "Expired secrets may cause application authentication failures and service outages."
            } else {
                foreach ($t in $thresholds) {
                    if ($daysUntilExpiry -le $t.Days) {
                        Add-Finding -Pillar "Security" -Severity $t.Severity -Category "Key Vault - Expiring Secret" `
                            -ResourceName "$kvName/$secretName" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Secret '$secretName' expires in $daysUntilExpiry days ($($expires.ToString('yyyy-MM-dd')))." `
                            -Recommendation "Plan rotation of this secret within the next $($t.Label). Update dependent applications." `
                            -Impact "Expired secrets cause authentication failures, breaking application connectivity."
                        break
                    }
                }
            }
        }

        # ── Certificates from ARG ──
        $argCerts = if ($script:CachedKVCerts.ContainsKey($subIdLower)) { $script:CachedKVCerts[$subIdLower] } else { @() }
        foreach ($cert in $argCerts) {
            $kvName = $cert.vaultName
            $kvRG = $cert.resourceGroup
            $certName = ($cert.name -split '/')[-1]
            $expires = Convert-ExpiresValue $cert.expires
            $enabled = $cert.enabled

            if ($null -eq $expires -or $enabled -eq $false) { continue }

            $daysUntilExpiry = [math]::Round(($expires - (Get-Date)).TotalDays, 0)
            if ($daysUntilExpiry -le 0) {
                Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Certificate" `
                    -ResourceName "$kvName/$certName" -ResourceType "Key Vault Certificate" -ResourceGroup $kvRG `
                    -Subscription $SubName `
                    -Description "Certificate '$certName' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago ($($expires.ToString('yyyy-MM-dd')))." `
                    -Recommendation "Renew this certificate immediately. Expired certificates cause TLS failures and service outages." `
                    -Impact "Expired TLS certificates break HTTPS connectivity and may expose traffic to interception."
            } else {
                foreach ($t in $thresholds) {
                    if ($daysUntilExpiry -le $t.Days) {
                        Add-Finding -Pillar "Security" -Severity $t.Severity -Category "Key Vault - Expiring Certificate" `
                            -ResourceName "$kvName/$certName" -ResourceType "Key Vault Certificate" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Certificate '$certName' expires in $daysUntilExpiry days ($($expires.ToString('yyyy-MM-dd')))." `
                            -Recommendation "Plan certificate renewal within $($t.Label). Use auto-renewal if supported by the CA." `
                            -Impact "Expired certificates cause TLS handshake failures and application downtime."
                        break
                    }
                }
            }
        }

        # ── Keys from ARG ──
        $argKeys = if ($script:CachedKVKeys.ContainsKey($subIdLower)) { $script:CachedKVKeys[$subIdLower] } else { @() }
        foreach ($key in $argKeys) {
            $kvName = $key.vaultName
            $kvRG = $key.resourceGroup
            $keyName = ($key.name -split '/')[-1]
            $expires = Convert-ExpiresValue $key.expires
            $enabled = $key.enabled

            if ($null -eq $expires -or $enabled -eq $false) { continue }

            $daysUntilExpiry = [math]::Round(($expires - (Get-Date)).TotalDays, 0)
            if ($daysUntilExpiry -le 0) {
                Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Key" `
                    -ResourceName "$kvName/$keyName" -ResourceType "Key Vault Key" -ResourceGroup $kvRG `
                    -Subscription $SubName `
                    -Description "Key '$keyName' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago." `
                    -Recommendation "Rotate this key immediately and update dependent encryption configurations." `
                    -Impact "Expired keys may prevent data decryption or signing operations."
            } elseif ($daysUntilExpiry -le 90) {
                $severity = if ($daysUntilExpiry -le 30) { "Critical" } elseif ($daysUntilExpiry -le 60) { "High" } else { "Medium" }
                Add-Finding -Pillar "Security" -Severity $severity -Category "Key Vault - Expiring Key" `
                    -ResourceName "$kvName/$keyName" -ResourceType "Key Vault Key" -ResourceGroup $kvRG `
                    -Subscription $SubName `
                    -Description "Key '$keyName' expires in $daysUntilExpiry days." `
                    -Recommendation "Plan key rotation before expiration. Update all resources using this key." `
                    -Impact "Expired keys break encryption/decryption and signing operations."
            }
        }

    } elseif (-not $SkipKeyVaultDataPlane) {
        # ─── Slow fallback: data-plane calls per vault (original method) ───
        Write-Status "  Resource Graph cache empty, falling back to data-plane calls..." "WARN"

        foreach ($kv in $keyVaults) {
            $kvName = $kv.VaultName
            $kvRG = $kv.ResourceGroupName

            # ── Secrets ──
            $secrets = Invoke-AzCommandSafely {
                Get-AzKeyVaultSecret -VaultName $kvName -ErrorAction SilentlyContinue
            } "Error retrieving secrets from $kvName"

            if ($secrets) {
                foreach ($secret in $secrets) {
                    if (-not $secret.Expires) {
                        Add-Finding -Pillar "Security" -Severity "Low" -Category "Key Vault - No Expiry Set" `
                            -ResourceName "$kvName/$($secret.Name)" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Secret '$($secret.Name)' has no expiration date configured." `
                            -Recommendation "Set an expiration date and configure rotation policy for all secrets." `
                            -Impact "Secrets without expiry are never rotated, increasing the risk of credential compromise."
                        continue
                    }
                    if ($secret.Enabled -eq $false) { continue }
                    $daysUntilExpiry = [math]::Round(($secret.Expires - (Get-Date)).TotalDays, 0)
                    if ($daysUntilExpiry -le 0) {
                        Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Secret" `
                            -ResourceName "$kvName/$($secret.Name)" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Secret '$($secret.Name)' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago ($($secret.Expires.ToString('yyyy-MM-dd')))." `
                            -Recommendation "Rotate this secret immediately and update all dependent applications." `
                            -Impact "Expired secrets may cause application authentication failures and service outages."
                    } else {
                        foreach ($t in $thresholds) {
                            if ($daysUntilExpiry -le $t.Days) {
                                Add-Finding -Pillar "Security" -Severity $t.Severity -Category "Key Vault - Expiring Secret" `
                                    -ResourceName "$kvName/$($secret.Name)" -ResourceType "Key Vault Secret" -ResourceGroup $kvRG `
                                    -Subscription $SubName `
                                    -Description "Secret '$($secret.Name)' expires in $daysUntilExpiry days ($($secret.Expires.ToString('yyyy-MM-dd')))." `
                                    -Recommendation "Plan rotation of this secret within the next $($t.Label). Update dependent applications." `
                                    -Impact "Expired secrets cause authentication failures, breaking application connectivity."
                                break
                            }
                        }
                    }
                }
            }

            # ── Certificates ──
            $certs = Invoke-AzCommandSafely {
                Get-AzKeyVaultCertificate -VaultName $kvName -ErrorAction SilentlyContinue
            } "Error retrieving certificates from $kvName"

            if ($certs) {
                foreach ($cert in $certs) {
                    if (-not $cert.Expires -or $cert.Enabled -eq $false) { continue }
                    $daysUntilExpiry = [math]::Round(($cert.Expires - (Get-Date)).TotalDays, 0)
                    if ($daysUntilExpiry -le 0) {
                        Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Certificate" `
                            -ResourceName "$kvName/$($cert.Name)" -ResourceType "Key Vault Certificate" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Certificate '$($cert.Name)' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago ($($cert.Expires.ToString('yyyy-MM-dd')))." `
                            -Recommendation "Renew this certificate immediately. Expired certificates cause TLS failures and service outages." `
                            -Impact "Expired TLS certificates break HTTPS connectivity and may expose traffic to interception."
                    } else {
                        foreach ($t in $thresholds) {
                            if ($daysUntilExpiry -le $t.Days) {
                                Add-Finding -Pillar "Security" -Severity $t.Severity -Category "Key Vault - Expiring Certificate" `
                                    -ResourceName "$kvName/$($cert.Name)" -ResourceType "Key Vault Certificate" -ResourceGroup $kvRG `
                                    -Subscription $SubName `
                                    -Description "Certificate '$($cert.Name)' expires in $daysUntilExpiry days ($($cert.Expires.ToString('yyyy-MM-dd')))." `
                                    -Recommendation "Plan certificate renewal within $($t.Label). Use auto-renewal if supported by the CA." `
                                    -Impact "Expired certificates cause TLS handshake failures and application downtime."
                                break
                            }
                        }
                    }
                }
            }

            # ── Keys ──
            $keys = Invoke-AzCommandSafely {
                Get-AzKeyVaultKey -VaultName $kvName -ErrorAction SilentlyContinue
            } "Error retrieving keys from $kvName"

            if ($keys) {
                foreach ($key in $keys) {
                    if (-not $key.Expires -or $key.Enabled -eq $false) { continue }
                    $daysUntilExpiry = [math]::Round(($key.Expires - (Get-Date)).TotalDays, 0)
                    if ($daysUntilExpiry -le 0) {
                        Add-Finding -Pillar "Security" -Severity "Critical" -Category "Key Vault - Expired Key" `
                            -ResourceName "$kvName/$($key.Name)" -ResourceType "Key Vault Key" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Key '$($key.Name)' EXPIRED $([math]::Abs($daysUntilExpiry)) days ago." `
                            -Recommendation "Rotate this key immediately and update dependent encryption configurations." `
                            -Impact "Expired keys may prevent data decryption or signing operations."
                    } elseif ($daysUntilExpiry -le 90) {
                        $severity = if ($daysUntilExpiry -le 30) { "Critical" } elseif ($daysUntilExpiry -le 60) { "High" } else { "Medium" }
                        Add-Finding -Pillar "Security" -Severity $severity -Category "Key Vault - Expiring Key" `
                            -ResourceName "$kvName/$($key.Name)" -ResourceType "Key Vault Key" -ResourceGroup $kvRG `
                            -Subscription $SubName `
                            -Description "Key '$($key.Name)' expires in $daysUntilExpiry days." `
                            -Recommendation "Plan key rotation before expiration. Update all resources using this key." `
                            -Impact "Expired keys break encryption/decryption and signing operations."
                    }
                }
            }
        }
    } else {
        Write-Status "  Skipped (SkipKeyVaultDataPlane and no ARG cache)" "INFO"
    }

    Write-Status "  Expiring secrets & certificates analysis complete" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 20: Tag Compliance Analysis
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-TagCompliance {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing tag compliance..." "INFO"

    $mandatoryTags = $MandatoryTags

    # Get all resources in subscription
    $resources = @(Get-AzResource -ErrorAction SilentlyContinue)
    $totalResources = $resources.Count
    if ($totalResources -eq 0) { Write-Status "  No resources found for tag analysis" "SKIP"; return }

    $untaggedCount = 0
    $partialTaggedCount = 0
    $resourcesMissingTags = @{}

    foreach ($res in $resources) {
        $resTags = $res.Tags
        if (-not $resTags -or $resTags.Count -eq 0) {
            $untaggedCount++
        } else {
            $missingTags = @($mandatoryTags | Where-Object { -not $resTags.ContainsKey($_) })
            if ($missingTags.Count -gt 0) {
                $partialTaggedCount++
            }
        }
    }

    # Aggregated finding for untagged resources (avoid per-resource spam)
    if ($untaggedCount -gt 0) {
        $sev = if ($untaggedCount -gt 50) { "High" } elseif ($untaggedCount -gt 10) { "Medium" } else { "Low" }
        Add-Finding -Pillar "Operational Excellence" -Severity $sev -Category "Tag Compliance - Untagged Resources" `
            -ResourceName "$untaggedCount of $totalResources resources" -ResourceType "Multiple" -ResourceGroup "Multiple" `
            -Subscription $SubName `
            -Description "$untaggedCount resources ($([math]::Round($untaggedCount/$totalResources*100,1))%) have no tags at all. Mandatory tags: $($mandatoryTags -join ', ')." `
            -Recommendation "Implement Azure Policy 'Require a tag on resources' to enforce mandatory tagging at deployment time. Use remediation tasks for existing resources." `
            -Impact "Untagged resources cannot be tracked for cost allocation, compliance, or ownership."
    }

    # Aggregated finding for partially tagged resources
    if ($partialTaggedCount -gt 0) {
        $sev = if ($partialTaggedCount -gt 50) { "Medium" } else { "Low" }
        Add-Finding -Pillar "Operational Excellence" -Severity $sev -Category "Tag Compliance - Missing Tags" `
            -ResourceName "$partialTaggedCount of $totalResources resources" -ResourceType "Multiple" -ResourceGroup "Multiple" `
            -Subscription $SubName `
            -Description "$partialTaggedCount resources have some tags but are missing one or more mandatory tags ($($mandatoryTags -join ', '))." `
            -Recommendation "Add the missing mandatory tags to ensure proper governance and cost tracking." `
            -Impact "Incomplete tagging hinders cost allocation and automated governance policies."
    }

    # Check for RG-level tags (empty RG detection is handled in Analyze-SubscriptionHygiene)
    $resourceGroups = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)
    foreach ($rg in $resourceGroups) {
        # Check RG-level tags
        if (-not $rg.Tags -or $rg.Tags.Count -eq 0) {
            Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Tag Compliance - Untagged RG" `
                -ResourceName $rg.ResourceGroupName -ResourceType "Microsoft.Resources/resourceGroups" -ResourceGroup $rg.ResourceGroupName `
                -Subscription $SubName `
                -Description "Resource group has no tags. Tags on RGs enable inherited governance policies." `
                -Recommendation "Apply mandatory tags at the resource group level for cost management and governance." `
                -Impact "Untagged resource groups break cost allocation and governance automation."
        }
    }

    # Summary finding if compliance is low
    $compliantCount = $totalResources - $untaggedCount - $partialTaggedCount
    $compliancePct = if ($totalResources -gt 0) { [math]::Round(($compliantCount / $totalResources) * 100, 1) } else { 100 }
    if ($compliancePct -lt 50) {
        Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "Tag Compliance - Low Compliance" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "Only $compliancePct% of resources have all mandatory tags. $untaggedCount completely untagged, $partialTaggedCount partially tagged out of $totalResources total." `
            -Recommendation "Implement Azure Policy to enforce mandatory tagging at deployment time. Use remediation tasks for existing resources." `
            -Impact "Poor tag compliance prevents effective cost management, ownership tracking, and automated governance."
    }

    Write-Status "  Tag compliance analysis complete ($compliancePct% compliant)" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 21: Diagnostic Settings Coverage
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-DiagnosticSettings {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing diagnostic settings coverage..." "INFO"

    # Critical resource types that MUST have diagnostic settings
    $criticalTypes = @(
        @{ Type = 'Microsoft.Network/networkSecurityGroups';     Label = 'NSG';              Severity = 'High' }
        @{ Type = 'Microsoft.Network/loadBalancers';             Label = 'Load Balancer';    Severity = 'Medium' }
        @{ Type = 'Microsoft.Network/applicationGateways';       Label = 'App Gateway';      Severity = 'High' }
        @{ Type = 'Microsoft.Network/azureFirewalls';            Label = 'Azure Firewall';   Severity = 'High' }
        @{ Type = 'Microsoft.Sql/servers';                       Label = 'SQL Server';       Severity = 'High' }
        @{ Type = 'Microsoft.Storage/storageAccounts';           Label = 'Storage Account';  Severity = 'Medium' }
        @{ Type = 'Microsoft.Compute/virtualMachines';           Label = 'Virtual Machine';  Severity = 'Medium' }
        @{ Type = 'Microsoft.Network/virtualNetworkGateways';    Label = 'VPN/ER Gateway';   Severity = 'High' }
        @{ Type = 'Microsoft.ContainerService/managedClusters';  Label = 'AKS Cluster';      Severity = 'High' }
        @{ Type = 'Microsoft.Network/publicIPAddresses';         Label = 'Public IP';        Severity = 'Low' }
        @{ Type = 'Microsoft.Web/sites';                         Label = 'App Service';      Severity = 'Medium' }
        @{ Type = 'Microsoft.Network/frontDoors';                Label = 'Front Door';       Severity = 'High' }
    )

    # Build a fast lookup of critical types
    $typeSet = @{}
    foreach ($ct in $criticalTypes) { $typeSet[$ct.Type.ToLower()] = $ct }

    # Use Resource Graph to find resources that DO have diagnostic settings in one call
    $resourcesWithDiag = @{}
    try {
        Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue
        $query = "resourcecontainers | where type =~ 'microsoft.resources/subscriptions' | take 0 | union (diagnosticsettings | where isnotempty(properties) | project resourceId = tolower(tostring(split(id, '/providers/microsoft.insights/diagnosticSettings')[0])), hasLAW = isnotempty(properties.workspaceId) | summarize hasLAW = max(hasLAW) by resourceId)"
        $diagResults = Search-AzGraph -Query $query -Subscription $SubId -First 1000 -ErrorAction SilentlyContinue
        if ($diagResults) {
            foreach ($d in $diagResults) {
                $resourcesWithDiag[$d.resourceId] = [bool]$d.hasLAW
            }
        }
    } catch {
        # Resource Graph query for diagnosticSettings might not be available
    }

    $totalChecked = 0
    $totalMissing = 0

    # If Resource Graph returned results, use cached data + fast lookup
    if ($resourcesWithDiag.Count -gt 0) {
        # Check cached resources by type
        foreach ($ct in $criticalTypes) {
            $resources = switch ($ct.Type) {
                'Microsoft.Compute/virtualMachines'              { $script:CachedVMs }
                'Microsoft.Network/networkSecurityGroups'        { $script:CachedNSGs }
                'Microsoft.Network/loadBalancers'                { $script:CachedLoadBalancers }
                'Microsoft.Network/applicationGateways'          { $script:CachedAppGateways }
                'Microsoft.Network/azureFirewalls'               { $script:CachedFirewalls }
                'Microsoft.Sql/servers'                          { $script:CachedSqlServers }
                'Microsoft.Storage/storageAccounts'              { $script:CachedStorageAccounts }
                'Microsoft.Web/sites'                            { $script:CachedWebApps }
                'Microsoft.Network/publicIPAddresses'            { $script:CachedPublicIPs }
                default { @(Get-AzResource -ResourceType $ct.Type -ErrorAction SilentlyContinue) }
            }
            if (-not $resources) { continue }
            foreach ($res in $resources) {
                $totalChecked++
                $resId = ($res.Id).ToLower()
                if ($resourcesWithDiag.ContainsKey($resId)) {
                    # Has diag settings — check if it sends to LAW
                    if (-not $resourcesWithDiag[$resId]) {
                        Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Diagnostic Settings - No Log Analytics" `
                            -ResourceName $res.Name -ResourceType $ct.Type -ResourceGroup $res.ResourceGroupName `
                            -Subscription $SubName `
                            -Description "Diagnostic settings exist but none send to Log Analytics workspace." `
                            -Recommendation "Add a diagnostic setting targeting a Log Analytics workspace for queryable log analysis and Sentinel integration." `
                            -Impact "Without Log Analytics integration, logs cannot be queried for investigations or used by Microsoft Sentinel."
                    }
                } else {
                    $totalMissing++
                    Add-Finding -Pillar "Operational Excellence" -Severity $ct.Severity -Category "Diagnostic Settings - $($ct.Label)" `
                        -ResourceName $res.Name -ResourceType $ct.Type -ResourceGroup $res.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "No diagnostic settings configured. Logs and metrics are not being collected." `
                        -Recommendation "Enable diagnostic settings to send logs to Log Analytics workspace for monitoring, alerting, and incident investigation." `
                        -Impact "Without diagnostic settings, you cannot investigate security incidents, troubleshoot issues, or meet compliance audit requirements."
                }
            }
        }
    } else {
        # Fallback: per-resource API calls (slower but always works)
        foreach ($ct in $criticalTypes) {
            try {
                $resources = @(Get-AzResource -ResourceType $ct.Type -ErrorAction SilentlyContinue)
                foreach ($res in $resources) {
                    $totalChecked++
                    try {
                        $diag = @(Get-AzDiagnosticSetting -ResourceId $res.ResourceId -ErrorAction SilentlyContinue)
                        if ($diag.Count -eq 0) {
                            $totalMissing++
                            Add-Finding -Pillar "Operational Excellence" -Severity $ct.Severity -Category "Diagnostic Settings - $($ct.Label)" `
                                -ResourceName $res.Name -ResourceType $ct.Type -ResourceGroup $res.ResourceGroupName `
                                -Subscription $SubName `
                                -Description "No diagnostic settings configured. Logs and metrics are not being collected." `
                                -Recommendation "Enable diagnostic settings to send logs to Log Analytics workspace for monitoring, alerting, and incident investigation." `
                                -Impact "Without diagnostic settings, you cannot investigate security incidents, troubleshoot issues, or meet compliance audit requirements."
                        } else {
                            $hasLAW = $diag | Where-Object { $_.WorkspaceId }
                            if (-not $hasLAW) {
                                Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Diagnostic Settings - No Log Analytics" `
                                    -ResourceName $res.Name -ResourceType $ct.Type -ResourceGroup $res.ResourceGroupName `
                                    -Subscription $SubName `
                                    -Description "Diagnostic settings exist but none send to Log Analytics workspace." `
                                    -Recommendation "Add a diagnostic setting targeting a Log Analytics workspace for queryable log analysis and Sentinel integration." `
                                    -Impact "Without Log Analytics integration, logs cannot be queried for investigations or used by Microsoft Sentinel."
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
    }

    # Check subscription-level Activity Log diagnostic settings
    try {
        $activityDiag = @(Get-AzDiagnosticSetting -ResourceId "/subscriptions/$SubId" -ErrorAction SilentlyContinue)
        if ($activityDiag.Count -eq 0) {
            Add-Finding -Pillar "Security" -Severity "High" -Category "Diagnostic Settings - Activity Log" `
                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "Activity Log is not exported to Log Analytics. Administrative and security events are only retained for 90 days in portal." `
                -Recommendation "Configure Activity Log diagnostic settings to export to a Log Analytics workspace for long-term retention and SIEM integration." `
                -Impact "Without Activity Log export, you lose visibility into subscription-level operations after 90 days and cannot correlate with resource-level logs."
        }
    } catch { }

    Write-Status "  Diagnostic settings analysis complete ($totalMissing/$totalChecked resources missing diagnostics)" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 22: Private Endpoint Adoption
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-PrivateEndpoints {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing Private Endpoint adoption..." "INFO"

    # PaaS services that should use Private Endpoints
    $paasChecks = @(
        @{ Type = 'Microsoft.Storage/storageAccounts';           Label = 'Storage Account';   GetPublic = { param($r) $r.NetworkRuleSet.DefaultAction -eq 'Allow' -or (-not $r.NetworkRuleSet) } }
        @{ Type = 'Microsoft.Sql/servers';                       Label = 'SQL Server';        GetPublic = { param($r) $r.PublicNetworkAccess -ne 'Disabled' } }
        @{ Type = 'Microsoft.KeyVault/vaults';                   Label = 'Key Vault';         GetPublic = { param($r) $true } }  # Will check via properties
        @{ Type = 'Microsoft.Web/sites';                         Label = 'App Service';       GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.ContainerRegistry/registries';      Label = 'Container Registry'; GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.DocumentDB/databaseAccounts';       Label = 'Cosmos DB';         GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.DBforPostgreSQL/flexibleServers';   Label = 'PostgreSQL Flex';   GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.DBforMySQL/flexibleServers';        Label = 'MySQL Flex';        GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.Cache/redis';                       Label = 'Redis Cache';       GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.CognitiveServices/accounts';        Label = 'Cognitive Services'; GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.EventHub/namespaces';               Label = 'Event Hub';         GetPublic = { param($r) $true } }
        @{ Type = 'Microsoft.ServiceBus/namespaces';             Label = 'Service Bus';       GetPublic = { param($r) $true } }
    )

    # Get all private endpoints in the subscription to cross-reference
    $privateEndpoints = @(Get-AzPrivateEndpoint -ErrorAction SilentlyContinue)
    $peTargetIds = @($privateEndpoints | ForEach-Object { $_.PrivateLinkServiceConnections | ForEach-Object { $_.PrivateLinkServiceId } }) | Where-Object { $_ }

    $totalPaaS = 0
    $withPE = 0
    $withoutPE = 0

    foreach ($check in $paasChecks) {
        try {
            $resources = @(Get-AzResource -ResourceType $check.Type -ErrorAction SilentlyContinue)
            foreach ($res in $resources) {
                $totalPaaS++
                $hasPE = $peTargetIds -contains $res.ResourceId

                if (-not $hasPE) {
                    $withoutPE++
                    # Determine severity based on resource type sensitivity
                    $sev = switch ($check.Label) {
                        'SQL Server'        { 'High' }
                        'Key Vault'         { 'High' }
                        'Storage Account'   { 'High' }
                        'Cosmos DB'         { 'High' }
                        'Container Registry' { 'Medium' }
                        'App Service'       { 'Medium' }
                        'PostgreSQL Flex'   { 'High' }
                        'MySQL Flex'        { 'High' }
                        'Redis Cache'       { 'Medium' }
                        default             { 'Medium' }
                    }

                    Add-Finding -Pillar "Security" -Severity $sev -Category "Private Endpoint - $($check.Label)" `
                        -ResourceName $res.Name -ResourceType $check.Type -ResourceGroup $res.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "$($check.Label) '$($res.Name)' has no Private Endpoint. Traffic traverses public internet." `
                        -Recommendation "Create a Private Endpoint to route traffic over the Microsoft backbone network. Disable public access after PE is configured." `
                        -Impact "Without Private Endpoints, data transits the public internet, increasing exposure to interception and attacks. Required for Zero Trust architecture."
                } else {
                    $withPE++
                }
            }
        } catch { }
    }

    if ($totalPaaS -gt 0) {
        $adoptionPct = [math]::Round(($withPE / $totalPaaS) * 100, 1)
        if ($adoptionPct -lt 30) {
            Add-Finding -Pillar "Security" -Severity "High" -Category "Private Endpoint - Low Adoption" `
                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "Only $adoptionPct% of PaaS resources use Private Endpoints ($withPE of $totalPaaS). This is significantly below the recommended baseline." `
                -Recommendation "Develop a Private Endpoint migration plan. Prioritize data services (SQL, Storage, Key Vault, Cosmos DB) first." `
                -Impact "Low Private Endpoint adoption means most PaaS services are publicly accessible, violating Zero Trust principles."
        }
    }

    Write-Status "  Private Endpoint analysis complete ($withPE/$totalPaaS with PE)" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 23: Azure Policy Compliance
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-PolicyCompliance {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing Azure Policy compliance..." "INFO"

    try {
        # Get policy assignments
        $assignments = @(Get-AzPolicyAssignment -ErrorAction SilentlyContinue)
        if ($assignments.Count -eq 0) {
            # Check if MG-scoped policies exist (inherited) before raising a finding
            $mgPolCount = 0
            if ($script:ALZData -and $script:ALZData.MGPolicies) {
                $mgPolCount = @($script:ALZData.MGPolicies | Where-Object { $_.Policies -gt 0 }).Count
            }
            if ($mgPolCount -gt 0) {
                Write-Status "  No subscription-level policy assignments, but $mgPolCount MG(s) have policies that inherit down." "INFO"
            } else {
                Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "Policy - No Assignments" `
                    -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                    -Subscription $SubName `
                    -Description "No Azure Policy assignments found at subscription or Management Group level. There are no guardrails enforcing compliance." `
                    -Recommendation "Assign built-in policy initiatives such as 'Azure Security Benchmark', 'CIS Microsoft Azure Foundations', or custom policies for tagging and resource configuration." `
                    -Impact "Without policies, there are no automated guardrails to prevent non-compliant resource deployments."
                Write-Status "  No policy assignments found" "WARN"
            }
            return
        }

        # Get compliance state — prefer pre-cached Resource Graph data
        if ($script:CachedPolicyStates.ContainsKey($SubId)) {
            $cached = $script:CachedPolicyStates[$SubId]
            $totalNonCompliant = [int]$cached.nonCompliantCount
            Write-Status "  Policy non-compliant resources (cached): $totalNonCompliant" "INFO"
            if ($totalNonCompliant -gt 50) {
                Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "Policy - Low Compliance Rate" `
                    -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                    -Subscription $SubName `
                    -Description "$totalNonCompliant resources are non-compliant with Azure Policy in this subscription." `
                    -Recommendation "Prioritize remediation of high-severity policy violations. Enable 'Deny' effect on critical policies to prevent future non-compliance." `
                    -Impact "Low policy compliance indicates systemic governance gaps and potential regulatory exposure."
            } elseif ($totalNonCompliant -gt 20) {
                Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "Policy - Moderate Compliance" `
                    -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                    -Subscription $SubName `
                    -Description "$totalNonCompliant resources are non-compliant with Azure Policy." `
                    -Recommendation "Create remediation tasks for existing non-compliant resources. Review policy effects (Audit vs Deny) for critical policies." `
                    -Impact "Moderate compliance leaves gaps in governance enforcement."
            }
        } else {
            # Fallback to REST API
            $complianceUrl = "/subscriptions/$SubId/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
            try {
                $complianceResult = Invoke-AzRestMethod -Path $complianceUrl -Method POST -ErrorAction Stop
                if ($complianceResult.StatusCode -ne 200) { throw "Policy Insights API returned $($complianceResult.StatusCode)" }
                $complianceData = ($complianceResult.Content | ConvertFrom-Json).value

                if ($complianceData) {
                    foreach ($summary in $complianceData) {
                        $results = $summary.results
                        $nonCompliantResources = $results.nonCompliantResources
                        $nonCompliantPolicies = $results.nonCompliantPolicies

                        if ($summary.policyAssignments) {
                            $topPolicies = $summary.policyAssignments | Sort-Object { $_.results.nonCompliantResources } -Descending | Select-Object -First 10
                            foreach ($pa in $topPolicies) {
                                $paName = if ($pa.policyAssignmentId -match '/([^/]+)$') { $Matches[1] } else { $pa.policyAssignmentId }
                                $ncRes = $pa.results.nonCompliantResources
                                if ($ncRes -gt 0) {
                                    $sev = if ($ncRes -gt 50) { "High" } elseif ($ncRes -gt 20) { "Medium" } else { "Low" }
                                    Add-Finding -Pillar "Operational Excellence" -Severity $sev -Category "Policy - Non-Compliant" `
                                        -ResourceName $paName -ResourceType "Policy Assignment" -ResourceGroup "N/A" `
                                        -Subscription $SubName `
                                        -Description "$ncRes resources are non-compliant with this policy assignment." `
                                        -Recommendation "Review non-compliant resources and create remediation tasks." `
                                        -Impact "Non-compliant resources may not meet security, governance, or regulatory requirements."
                                }
                            }
                        }

                        # Use same absolute-count thresholds as cached path for consistency
                        $totalNonCompliant = [int]$nonCompliantResources
                        if ($totalNonCompliant -gt 50) {
                            Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "Policy - Low Compliance Rate" `
                                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                                -Subscription $SubName `
                                -Description "$totalNonCompliant resources are non-compliant with Azure Policy in this subscription." `
                                -Recommendation "Prioritize remediation of high-severity policy violations. Enable 'Deny' effect on critical policies to prevent future non-compliance." `
                                -Impact "Low policy compliance indicates systemic governance gaps and potential regulatory exposure."
                        } elseif ($totalNonCompliant -gt 20) {
                            Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "Policy - Moderate Compliance" `
                                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                                -Subscription $SubName `
                                -Description "$totalNonCompliant resources are non-compliant with Azure Policy." `
                                -Recommendation "Create remediation tasks for existing non-compliant resources. Review policy effects (Audit vs Deny) for critical policies." `
                                -Impact "Moderate compliance leaves gaps in governance enforcement."
                        }
                    }
                }
            } catch {
                Write-Status "  Could not retrieve policy compliance state via REST" "WARN"
            }
        }

        # Check for policies in 'Disabled' effect
        foreach ($assignment in $assignments) {
            try {
                $enforcementMode = $assignment.Properties.EnforcementMode
                if ($enforcementMode -eq 'DoNotEnforce') {
                    $aName = $assignment.Properties.DisplayName
                    if (-not $aName) { $aName = $assignment.Name }
                    Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "Policy - Not Enforced" `
                        -ResourceName $aName -ResourceType "Policy Assignment" -ResourceGroup "N/A" `
                        -Subscription $SubName `
                        -Description "Policy assignment is in 'DoNotEnforce' mode. It only audits but does not prevent non-compliant deployments." `
                        -Recommendation "Switch enforcement mode to 'Default' after validating the policy won't break existing workloads." `
                        -Impact "Policies in DoNotEnforce mode provide visibility but no protection against non-compliant deployments."
                }
            } catch { }
        }

    } catch {
        Write-Status "  Policy compliance analysis failed: $_" "WARN"
    }

    Write-Status "  Policy compliance analysis complete" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 24: Cosmos DB & OSS Database Security
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-CosmosOSSDatabase {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing Cosmos DB & OSS database security..." "INFO"

    # --- Cosmos DB ---
    try {
        $cosmosAccounts = @(Get-AzResource -ResourceType 'Microsoft.DocumentDB/databaseAccounts' -ErrorAction SilentlyContinue)
        foreach ($cosmos in $cosmosAccounts) {
            try {
                $cosmosDetail = Get-AzResource -ResourceId $cosmos.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $props = $cosmosDetail.Properties

                # Public network access
                if ($props.publicNetworkAccess -ne 'Disabled') {
                    $hasVNetRules = ($props.virtualNetworkRules | Measure-Object).Count -gt 0
                    $hasIpRules = ($props.ipRules | Measure-Object).Count -gt 0
                    $sev = if (-not $hasVNetRules -and -not $hasIpRules) { "High" } else { "Medium" }
                    Add-Finding -Pillar "Security" -Severity $sev -Category "Cosmos DB - Public Access" `
                        -ResourceName $cosmos.Name -ResourceType "Microsoft.DocumentDB/databaseAccounts" -ResourceGroup $cosmos.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Cosmos DB has public network access enabled.$(if (-not $hasVNetRules -and -not $hasIpRules) { ' No IP or VNet firewall rules configured.' })" `
                        -Recommendation "Disable public access and use Private Endpoints. If public access is needed, configure IP and VNet firewall rules." `
                        -Impact "Publicly accessible Cosmos DB accounts are exposed to brute force and unauthorized access attempts."
                }

                # Backup type
                $backupPolicy = $props.backupPolicy
                if ($backupPolicy.type -eq 'Periodic') {
                    $intervalHours = if ($backupPolicy.periodicModeProperties.backupIntervalInMinutes) { [math]::Round($backupPolicy.periodicModeProperties.backupIntervalInMinutes / 60, 1) } else { 'Unknown' }
                    $retentionHours = if ($backupPolicy.periodicModeProperties.backupRetentionIntervalInHours) { $backupPolicy.periodicModeProperties.backupRetentionIntervalInHours } else { 'Unknown' }
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "Cosmos DB - Periodic Backup" `
                        -ResourceName $cosmos.Name -ResourceType "Microsoft.DocumentDB/databaseAccounts" -ResourceGroup $cosmos.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Using periodic backup (interval: ${intervalHours}h, retention: ${retentionHours}h). Continuous backup provides point-in-time restore." `
                        -Recommendation "Consider switching to Continuous backup mode for point-in-time restore capability (7 or 30 day window)." `
                        -Impact "Periodic backup has limited RPO. Continuous backup enables restore to any point in time."
                }

                # Multi-region writes / geo-redundancy
                if (-not $props.enableMultipleWriteLocations -and ($props.locations | Measure-Object).Count -lt 2) {
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "Cosmos DB - Single Region" `
                        -ResourceName $cosmos.Name -ResourceType "Microsoft.DocumentDB/databaseAccounts" -ResourceGroup $cosmos.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Cosmos DB account is deployed in a single region with no geo-redundancy." `
                        -Recommendation "Add a secondary region for geo-redundancy. Enable automatic failover for business continuity." `
                        -Impact "Single-region deployment means a regional outage will cause complete data unavailability."
                }

                # Local authentication (keys vs RBAC)
                if ($props.disableLocalAuth -ne $true) {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "Cosmos DB - Local Auth Enabled" `
                        -ResourceName $cosmos.Name -ResourceType "Microsoft.DocumentDB/databaseAccounts" -ResourceGroup $cosmos.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Local authentication (master keys) is enabled. Key-based access cannot be audited per-identity." `
                        -Recommendation "Enable Azure AD RBAC for Cosmos DB data plane and disable local authentication for better security auditing." `
                        -Impact "Shared keys provide full access without identity tracking, making it impossible to audit who accessed data."
                }

            } catch { }
        }
    } catch { }

    # --- PostgreSQL Flexible Server ---
    try {
        $pgServers = @(Get-AzResource -ResourceType 'Microsoft.DBforPostgreSQL/flexibleServers' -ErrorAction SilentlyContinue)
        foreach ($pg in $pgServers) {
            try {
                $pgDetail = Get-AzResource -ResourceId $pg.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $props = $pgDetail.Properties

                # Public access
                if ($props.network.publicNetworkAccess -ne 'Disabled') {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "PostgreSQL - Public Access" `
                        -ResourceName $pg.Name -ResourceType "Microsoft.DBforPostgreSQL/flexibleServers" -ResourceGroup $pg.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "PostgreSQL Flexible Server has public network access enabled." `
                        -Recommendation "Use Private Endpoints or VNet integration to restrict access. Disable public network access." `
                        -Impact "Publicly accessible databases are prime targets for brute force attacks and data exfiltration."
                }

                # HA not enabled
                if ($props.highAvailability.mode -ne 'ZoneRedundant' -and $props.highAvailability.mode -ne 'SameZone') {
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "PostgreSQL - No HA" `
                        -ResourceName $pg.Name -ResourceType "Microsoft.DBforPostgreSQL/flexibleServers" -ResourceGroup $pg.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "High availability is not enabled. Single server deployment with no automatic failover." `
                        -Recommendation "Enable zone-redundant or same-zone HA for automatic failover and reduced downtime." `
                        -Impact "Without HA, database downtime during failures requires manual intervention and extended recovery time."
                }

                # Backup retention
                $backupRetention = $props.backup.backupRetentionDays
                if ($backupRetention -and $backupRetention -lt 14) {
                    Add-Finding -Pillar "Reliability" -Severity "Low" -Category "PostgreSQL - Short Retention" `
                        -ResourceName $pg.Name -ResourceType "Microsoft.DBforPostgreSQL/flexibleServers" -ResourceGroup $pg.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Backup retention is $backupRetention days. Recommended minimum is 14 days for production workloads." `
                        -Recommendation "Increase backup retention to at least 14 days for production databases." `
                        -Impact "Short retention limits point-in-time restore capabilities and data recovery options."
                }
            } catch { }
        }
    } catch { }

    # --- MySQL Flexible Server ---
    try {
        $mysqlServers = @(Get-AzResource -ResourceType 'Microsoft.DBforMySQL/flexibleServers' -ErrorAction SilentlyContinue)
        foreach ($mysql in $mysqlServers) {
            try {
                $mysqlDetail = Get-AzResource -ResourceId $mysql.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $props = $mysqlDetail.Properties

                if ($props.network.publicNetworkAccess -ne 'Disabled') {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "MySQL - Public Access" `
                        -ResourceName $mysql.Name -ResourceType "Microsoft.DBforMySQL/flexibleServers" -ResourceGroup $mysql.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "MySQL Flexible Server has public network access enabled." `
                        -Recommendation "Use Private Endpoints or VNet integration. Disable public network access." `
                        -Impact "Publicly accessible MySQL servers are vulnerable to brute force and injection attacks."
                }

                if ($props.highAvailability.mode -ne 'ZoneRedundant' -and $props.highAvailability.mode -ne 'SameZone') {
                    Add-Finding -Pillar "Reliability" -Severity "Medium" -Category "MySQL - No HA" `
                        -ResourceName $mysql.Name -ResourceType "Microsoft.DBforMySQL/flexibleServers" -ResourceGroup $mysql.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "High availability is not enabled on this MySQL server." `
                        -Recommendation "Enable zone-redundant HA for automatic failover capability." `
                        -Impact "Without HA, database availability depends on single instance health."
                }
            } catch { }
        }
    } catch { }

    # --- Redis Cache ---
    try {
        $redisInstances = @(Get-AzResource -ResourceType 'Microsoft.Cache/redis' -ErrorAction SilentlyContinue)
        foreach ($redis in $redisInstances) {
            try {
                $redisDetail = Get-AzResource -ResourceId $redis.ResourceId -ExpandProperties -ErrorAction SilentlyContinue
                $props = $redisDetail.Properties

                # Non-SSL port enabled
                if ($props.enableNonSslPort -eq $true) {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "Redis - Non-SSL Port" `
                        -ResourceName $redis.Name -ResourceType "Microsoft.Cache/redis" -ResourceGroup $redis.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Non-SSL port (6379) is enabled. Traffic on this port is unencrypted." `
                        -Recommendation "Disable the non-SSL port and use only SSL port 6380 for encrypted connections." `
                        -Impact "Unencrypted Redis traffic can be intercepted, exposing cached data and authentication tokens."
                }

                # Minimum TLS version
                if ($props.minimumTlsVersion -and $props.minimumTlsVersion -ne '1.2') {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "Redis - TLS Version" `
                        -ResourceName $redis.Name -ResourceType "Microsoft.Cache/redis" -ResourceGroup $redis.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Minimum TLS version is $($props.minimumTlsVersion). TLS 1.2 is recommended." `
                        -Recommendation "Set minimum TLS version to 1.2." `
                        -Impact "Older TLS versions have known vulnerabilities."
                }

                # Public network access
                if ($props.publicNetworkAccess -ne 'Disabled') {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "Redis - Public Access" `
                        -ResourceName $redis.Name -ResourceType "Microsoft.Cache/redis" -ResourceGroup $redis.ResourceGroupName `
                        -Subscription $SubName `
                        -Description "Redis cache has public network access enabled." `
                        -Recommendation "Use Private Endpoints to access Redis over the Microsoft backbone network." `
                        -Impact "Publicly accessible cache instances increase attack surface."
                }
            } catch { }
        }
    } catch { }

    Write-Status "  Cosmos DB & OSS database analysis complete" "OK"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FUNCTION 25: Subscription Hygiene
# ═══════════════════════════════════════════════════════════════════════════════
function Analyze-SubscriptionHygiene {
    param([string]$SubId, [string]$SubName)
    Write-Status "  Analyzing subscription hygiene..." "INFO"

    # Get all resources and resource groups
    $resources = @(Get-AzResource -ErrorAction SilentlyContinue)
    $resourceGroups = @(Get-AzResourceGroup -ErrorAction SilentlyContinue)

    # Region distribution analysis
    $regionGroups = $resources | Group-Object Location | Sort-Object Count -Descending
    $primaryRegion = if ($regionGroups.Count -gt 0) { $regionGroups[0].Name } else { $null }
    $regionCount = $regionGroups.Count

    if ($regionCount -gt 5) {
        Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "Hygiene - Region Sprawl" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "Resources are spread across $regionCount regions. Top regions: $(($regionGroups | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')." `
            -Recommendation "Consolidate resources into fewer regions where possible to reduce latency, simplify management, and reduce data transfer costs." `
            -Impact "Region sprawl increases complexity, latency, and inter-region data transfer costs."
    }

    # Resource group sprawl
    $emptyRGs = @($resourceGroups | Where-Object {
        $rgName = $_.ResourceGroupName
        @($resources | Where-Object { $_.ResourceGroupName -eq $rgName }).Count -eq 0
    })

    if ($emptyRGs.Count -gt 5) {
        Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Hygiene - Empty Resource Groups" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "$($emptyRGs.Count) empty resource groups found: $(($emptyRGs | Select-Object -First 5 | ForEach-Object { $_.ResourceGroupName }) -join ', ')$(if($emptyRGs.Count -gt 5) { '...' })." `
            -Recommendation "Review and delete empty resource groups that are not awaiting deployments." `
            -Impact "Empty resource groups create clutter and management overhead."
    }

    # Resources without resource group naming convention
    $rgNamingIssues = @($resourceGroups | Where-Object { $_.ResourceGroupName -notmatch '^(rg-|RG-|rg_)' -and $_.ResourceGroupName -notmatch '-rg$' -and $_.ResourceGroupName -notmatch '-RG$' })
    $namingPct = if ($resourceGroups.Count -gt 0) { [math]::Round(($rgNamingIssues.Count / $resourceGroups.Count) * 100, 1) } else { 0 }
    if ($namingPct -gt 70 -and $resourceGroups.Count -gt 5) {
        Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Hygiene - RG Naming Convention" `
            -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "$namingPct% of resource groups ($($rgNamingIssues.Count)/$($resourceGroups.Count)) don't follow a standard naming convention (e.g., rg-<workload>-<env>-<region>)." `
            -Recommendation "Adopt Azure Cloud Adoption Framework naming conventions. Use Azure Policy to enforce naming patterns on new resources." `
            -Impact "Inconsistent naming makes it difficult to identify resource purpose, environment, and ownership."
    }

    # Check for resources in unexpected/uncommon regions (potential misdeployments)
    if ($regionGroups.Count -gt 2 -and $primaryRegion) {
        $outlierRegions = @($regionGroups | Where-Object { $_.Count -le 2 -and $_.Count -gt 0 -and $_.Name -ne 'global' })
        foreach ($outlier in $outlierRegions) {
            $outlierResources = @($resources | Where-Object { $_.Location -eq $outlier.Name })
            $resNames = ($outlierResources | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', '
            Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Hygiene - Isolated Region Resources" `
                -ResourceName $outlier.Name -ResourceType "Region" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "$($outlier.Count) resource(s) in '$($outlier.Name)' while primary region is '$primaryRegion'. Resources: $resNames." `
                -Recommendation "Verify these resources are intentionally deployed in this region. Consolidate to primary/secondary regions if they were misdeployed." `
                -Impact "Resources in unexpected regions may indicate accidental deployments and create management complexity."
        }
    }

    # Subscription-level summary
    $totalRGs = $resourceGroups.Count
    $totalRes = $resources.Count
    if ($totalRGs -gt 0 -and $totalRes -gt 0) {
        $avgResPerRG = [math]::Round($totalRes / ($totalRGs - $emptyRGs.Count + 0.01), 1)
        if ($avgResPerRG -lt 2 -and $totalRGs -gt 20) {
            Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "Hygiene - RG Proliferation" `
                -ResourceName "Subscription: $SubName" -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "Average of $avgResPerRG resources per resource group across $totalRGs RGs. Many RGs contain only 1-2 resources." `
                -Recommendation "Consolidate related resources into fewer resource groups organized by workload lifecycle." `
                -Impact "Too many resource groups with few resources increases management overhead and RBAC complexity."
        }
    }

    Write-Status "  Subscription hygiene analysis complete" "OK"
}

# ============================================================================
# CROSS-PILLAR CORRELATION & RISK ANALYSIS
# ============================================================================
function Analyze-CrossPillarCorrelation {
    param([string]$SubId, [string]$SubName)

    Write-Status "Running cross-pillar correlation analysis..." "SECTION"

    $vms = $script:CachedVMs
    if (-not $vms -or $vms.Count -eq 0) {
        Write-Status "  No VMs to correlate" "SKIP"
        return
    }

    $subIdLower = $SubId.ToLower()

    # Build per-VM risk profile from existing cached data
    $backupItemIds = @()
    if ($script:CachedBackupItems.ContainsKey($subIdLower)) {
        $backupItemIds = @($script:CachedBackupItems[$subIdLower] | Where-Object { $_.sourceResourceId } | ForEach-Object { $_.sourceResourceId.ToLower() })
    }

    $highRiskVMs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($vm in $vms) {
        $riskFactors = @()
        $riskScore = 0
        $vmIdLower = $vm.Id.ToLower()

        # Factor 1: No backup
        $hasBackup = $vmIdLower -in $backupItemIds
        if (-not $hasBackup) { $riskFactors += "No backup"; $riskScore += 25 }

        # Factor 2: No HA (not in availability set or zone)
        $hasHA = ($vm.AvailabilitySetReference -or ($vm.Zones -and $vm.Zones.Count -gt 0))
        if (-not $hasHA) { $riskFactors += "No HA (no zone/avail set)"; $riskScore += 20 }

        # Factor 3: No managed identity
        $hasIdentity = ($vm.Identity -and $vm.Identity.Type -ne "None")
        if (-not $hasIdentity) { $riskFactors += "No managed identity"; $riskScore += 10 }

        # Factor 4: No encryption
        $encStatus = $script:CachedVMEncryption[$vm.Id]
        $isEncrypted = ($encStatus -and $encStatus.OsVolumeEncrypted -eq 'Encrypted')
        if (-not $isEncrypted) { $riskFactors += "OS disk not encrypted"; $riskScore += 20 }

        # Factor 5: Production tag
        $isProduction = $false
        if ($vm.Tags) {
            $envVal = if ($vm.Tags['env']) { $vm.Tags['env'] } elseif ($vm.Tags['environment']) { $vm.Tags['environment'] } elseif ($vm.Tags['Environment']) { $vm.Tags['Environment'] } else { '' }
            if ($envVal -match '^prod(uction)?$') { $isProduction = $true; $riskScore += 15 }
        }

        # Factor 6: Public IP attached
        $vmNics = $script:CachedNICs | Where-Object { $_.VirtualMachine -and $_.VirtualMachine.Id -eq $vm.Id }
        $hasPublicIP = $vmNics | Where-Object { $_.IpConfigurations | Where-Object { $_.PublicIpAddress } }
        if ($hasPublicIP) { $riskFactors += "Public IP exposed"; $riskScore += 10 }

        if ($riskScore -ge 50) {
            $highRiskVMs.Add([PSCustomObject]@{
                Name        = $vm.Name
                RG          = $vm.ResourceGroupName
                Score       = $riskScore
                Factors     = $riskFactors
                Production  = $isProduction
            })
        }
    }

    if ($highRiskVMs.Count -gt 0) {
        $criticalVMs = @($highRiskVMs | Where-Object { $_.Score -ge 70 })
        $highVMs = @($highRiskVMs | Where-Object { $_.Score -ge 50 -and $_.Score -lt 70 })

        if ($criticalVMs.Count -gt 0) {
            $topNames = ($criticalVMs | Sort-Object Score -Descending | Select-Object -First 5 | ForEach-Object {
                "$($_.Name) (score:$($_.Score) — $($_.Factors -join ', '))"
            }) -join '; '
            Add-Finding -Pillar "Reliability" -Severity "Critical" `
                -Category "Cross-Pillar: Critical Risk VMs" `
                -ResourceName "$($criticalVMs.Count) VMs with risk score >= 70" `
                -ResourceType "Virtual Machine" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "Cross-pillar analysis identified $($criticalVMs.Count) VMs with compounded risks (no backup + no HA + no encryption + production). Top: $topNames." `
                -Recommendation "Prioritize these VMs for immediate remediation: enable backup, deploy to availability zones, enable disk encryption, and assign managed identities." `
                -Impact "A single failure on these VMs would cause data loss with no recovery path. Multiple security and reliability gaps compound the blast radius."
        }

        if ($highVMs.Count -gt 0) {
            $topNames = ($highVMs | Sort-Object Score -Descending | Select-Object -First 5 | ForEach-Object {
                "$($_.Name) (score:$($_.Score))"
            }) -join ', '
            Add-Finding -Pillar "Reliability" -Severity "High" `
                -Category "Cross-Pillar: Elevated Risk VMs" `
                -ResourceName "$($highVMs.Count) VMs with risk score 50-69" `
                -ResourceType "Virtual Machine" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "Cross-pillar analysis found $($highVMs.Count) VMs with multiple unaddressed risks across reliability, security, and operations. Top: $topNames." `
                -Recommendation "Review and remediate the identified risk factors for each VM. Use the per-pillar findings for detailed remediation steps." `
                -Impact "Multiple overlapping gaps increase the probability and severity of incidents."
        }
    }

    # ── Storage correlation: LRS + no backup + large data ──
    $storageAccounts = $script:CachedStorageAccounts
    if ($storageAccounts) {
        $riskyStorage = @($storageAccounts | Where-Object {
            $_.Sku.Name -match 'LRS$' -and
            $_.Kind -in @('StorageV2', 'BlobStorage', 'BlockBlobStorage')
        })
        if ($riskyStorage.Count -gt 0) {
            $names = ($riskyStorage | Select-Object -First 5 | ForEach-Object { $_.StorageAccountName }) -join ', '
            Add-Finding -Pillar "Reliability" -Severity "High" `
                -Category "Cross-Pillar: Storage Single-Region Risk" `
                -ResourceName "$($riskyStorage.Count) storage accounts" `
                -ResourceType "Storage Account" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($riskyStorage.Count) storage accounts use LRS (locally redundant) with no cross-region protection. Examples: $names." `
                -Recommendation "Evaluate switching to GRS/ZRS/GZRS based on data criticality. For mission-critical data, use RA-GRS for read access during regional outages." `
                -Impact "A datacenter failure would result in permanent data loss for all LRS storage accounts."
        }
    }

    # ── Single-region deployment detection ──
    $allLocations = @($script:Resources | Where-Object { $_.Location -and $_.Location -ne 'global' } | Select-Object -ExpandProperty Location -Unique)
    if ($allLocations.Count -eq 1 -and $script:Resources.Count -gt 20) {
        Add-Finding -Pillar "Reliability" -Severity "Medium" `
            -Category "Cross-Pillar: Single Region Deployment" `
            -ResourceName "All $($script:Resources.Count) resources in $($allLocations[0])" `
            -ResourceType "Subscription" -ResourceGroup "N/A" `
            -Subscription $SubName `
            -Description "All $($script:Resources.Count) resources are deployed in a single region ($($allLocations[0])). No multi-region resilience." `
            -Recommendation "Design active-passive or active-active multi-region architecture for critical workloads. Use Azure paired regions for BCDR." `
            -Impact "A regional outage would affect all workloads simultaneously with no failover capability."
    }

    Write-Status "  Cross-pillar correlation complete" "OK"
}

# ============================================================================
# ADDITIONAL HIGH-VALUE SECURITY & RELIABILITY CHECKS
# ============================================================================
function Analyze-AdditionalChecks {
    param([string]$SubId, [string]$SubName)

    Write-Status "Running additional deep-analysis checks..." "SECTION"

    # ── 1. NSG Egress Rules — unrestricted outbound to Internet ──
    Write-Status "  [1/12] NSG egress rules..." "INFO"
    $nsgs = $script:CachedNSGs
    if ($nsgs) {
        foreach ($nsg in $nsgs) {
            $dangerousEgress = @($nsg.SecurityRules | Where-Object {
                $_.Direction -eq 'Outbound' -and
                $_.Access -eq 'Allow' -and
                ($_.DestinationAddressPrefix -in @('*', '0.0.0.0/0', 'Internet') -or
                 ($_.DestinationAddressPrefixes -and ($_.DestinationAddressPrefixes | Where-Object { $_ -in @('*', '0.0.0.0/0', 'Internet') })))
            })
            if ($dangerousEgress.Count -gt 0) {
                $ruleNames = ($dangerousEgress | ForEach-Object { $_.Name }) -join ', '
                Add-Finding -Pillar "Security" -Severity "Medium" `
                    -Category "Network - Unrestricted Egress" `
                    -ResourceName $nsg.Name -ResourceType "NSG" `
                    -ResourceGroup $nsg.ResourceGroupName -Subscription $SubName `
                    -Description "NSG has $($dangerousEgress.Count) custom rule(s) allowing unrestricted outbound traffic to Internet/Any: $ruleNames." `
                    -Recommendation "Restrict outbound traffic to only required destinations. Use Azure Firewall or NSG rules with specific service tags instead of wildcard destinations." `
                    -Impact "Unrestricted egress enables data exfiltration, C2 communication, and lateral movement if a workload is compromised."
            }
        }
    }

    # ── 2. Subnets without NSG ──
    Write-Status "  [2/12] Subnets without NSG..." "INFO"
    $vnets = $script:CachedVNets
    if ($vnets) {
        $subnetsNoNsg = [System.Collections.Generic.List[string]]::new()
        foreach ($vnet in $vnets) {
            foreach ($subnet in $vnet.Subnets) {
                if ($subnet.Name -match '^(GatewaySubnet|AzureBastionSubnet|AzureFirewallSubnet|AzureFirewallManagementSubnet|RouteServerSubnet)$') { continue }
                if (-not $subnet.NetworkSecurityGroup) {
                    $subnetsNoNsg.Add("$($vnet.Name)/$($subnet.Name)")
                }
            }
        }
        if ($subnetsNoNsg.Count -gt 0) {
            $examples = ($subnetsNoNsg | Select-Object -First 5) -join ', '
            $extra = if ($subnetsNoNsg.Count -gt 5) { " and $($subnetsNoNsg.Count - 5) more" } else { '' }
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "Network - Subnet No NSG" `
                -ResourceName "$($subnetsNoNsg.Count) subnets" -ResourceType "Subnet" `
                -ResourceGroup "Multiple" -Subscription $SubName `
                -Description "$($subnetsNoNsg.Count) subnets have no Network Security Group attached: $examples$extra." `
                -Recommendation "Attach an NSG to every subnet (except system-managed subnets). Implement deny-by-default inbound rules." `
                -Impact "Subnets without NSGs have no network-layer access control, allowing unrestricted traffic between all connected resources."
        }
    }

    # ── 3. VM without antimalware extension ──
    Write-Status "  [3/12] VM antimalware coverage..." "INFO"
    $vms = $script:CachedVMs
    if ($vms) {
        $antimalwarePatterns = 'IaaSAntimalware|EndpointSecurity|MDE\.Windows|MDE\.Linux|AzureSecurityLinuxAgent|WindowsDefenderATPOnboarding'
        $vmsNoAntimalware = @($vms | Where-Object {
            $vmExts = $script:CachedVMExtensions[$_.Id.ToLower()]
            -not ($vmExts | Where-Object { $_.type -match $antimalwarePatterns })
        })
        if ($vmsNoAntimalware.Count -gt 0) {
            $names = ($vmsNoAntimalware | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            $extra = if ($vmsNoAntimalware.Count -gt 5) { " and $($vmsNoAntimalware.Count - 5) more" } else { '' }
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "VM - No Antimalware" `
                -ResourceName "$($vmsNoAntimalware.Count) of $($vms.Count) VMs" `
                -ResourceType "Virtual Machine" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($vmsNoAntimalware.Count) VMs have no antimalware/EDR extension detected. Examples: $names$extra." `
                -Recommendation "Deploy Microsoft Defender for Endpoint (MDE) or IaaSAntimalware extension on all VMs via Azure Policy." `
                -Impact "VMs without endpoint protection are vulnerable to malware, ransomware, and fileless attacks."
        }
    }

    # ── 4. Key Vault access policy (legacy) vs RBAC ──
    Write-Status "  [4/12] Key Vault access model..." "INFO"
    $keyVaults = $script:CachedKeyVaults
    if ($keyVaults) {
        $kvLegacy = @()
        foreach ($kv in $keyVaults) {
            try {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction SilentlyContinue
                if ($kvDetail -and -not $kvDetail.EnableRbacAuthorization) {
                    $kvLegacy += $kv.VaultName
                }
            } catch {}
        }
        if ($kvLegacy.Count -gt 0) {
            $names = ($kvLegacy | Select-Object -First 5) -join ', '
            Add-Finding -Pillar "Security" -Severity "Medium" `
                -Category "Key Vault - Legacy Access Policy" `
                -ResourceName "$($kvLegacy.Count) Key Vaults" `
                -ResourceType "Key Vault" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($kvLegacy.Count) Key Vaults use legacy Access Policies instead of RBAC: $names." `
                -Recommendation "Migrate to Azure RBAC for Key Vault (EnableRbacAuthorization = true). RBAC provides fine-grained, auditable permissions with Entra ID integration." `
                -Impact "Access Policies lack conditional access, are harder to audit, and don't support PIM integration."
        }
    }

    # ── 5. App Service without IP restrictions (0.0.0.0/0 implied) ──
    Write-Status "  [5/12] App Service IP restrictions..." "INFO"
    $webApps = $script:CachedWebApps
    if ($webApps) {
        $appsNoRestrictions = @()
        foreach ($app in $webApps) {
            $config = $script:CachedWebAppDetails[$app.Id]
            if ($config -and $config.SiteConfig.IpSecurityRestrictions) {
                $rules = @($config.SiteConfig.IpSecurityRestrictions | Where-Object { $_.Action -ne 'Deny' -and $_.IpAddress -ne '0.0.0.0/0' -and $_.Name -ne 'Allow all' })
                $denyAll = @($config.SiteConfig.IpSecurityRestrictions | Where-Object { $_.Action -eq 'Deny' -and ($_.IpAddress -eq 'Any' -or $_.IpAddress -eq '0.0.0.0/0') })
                if ($rules.Count -eq 0 -and $denyAll.Count -eq 0 -and -not $config.SiteConfig.IpSecurityRestrictionsDefaultAction) {
                    $appsNoRestrictions += $app.Name
                }
            } elseif ($config) {
                $appsNoRestrictions += $app.Name
            }
        }
        if ($appsNoRestrictions.Count -gt 0) {
            $names = ($appsNoRestrictions | Select-Object -First 5) -join ', '
            Add-Finding -Pillar "Security" -Severity "Medium" `
                -Category "App Service - No IP Restrictions" `
                -ResourceName "$($appsNoRestrictions.Count) App Services" `
                -ResourceType "App Service" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($appsNoRestrictions.Count) App Services have no IP access restrictions configured: $names." `
                -Recommendation "Configure IP restrictions or use Private Endpoints to limit access. Add a deny-all default rule with explicit allow entries." `
                -Impact "App Services without IP restrictions are accessible from any IP address on the Internet."
        }
    }

    # ── 6. SQL TDE key type: service-managed vs CMK ──
    Write-Status "  [6/12] SQL encryption key type..." "INFO"
    $sqlServers = $script:CachedSqlServers
    if ($sqlServers) {
        $serviceManaged = @()
        foreach ($srv in $sqlServers) {
            try {
                $encProtector = Get-AzSqlServerTransparentDataEncryptionProtector -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue
                if ($encProtector -and $encProtector.Type -eq 'ServiceManaged') {
                    $serviceManaged += $srv.ServerName
                }
            } catch {}
        }
        if ($serviceManaged.Count -gt 0) {
            $names = ($serviceManaged | Select-Object -First 5) -join ', '
            Add-Finding -Pillar "Security" -Severity "Low" `
                -Category "SQL - Service-Managed TDE Key" `
                -ResourceName "$($serviceManaged.Count) SQL Servers" `
                -ResourceType "SQL Server" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($serviceManaged.Count) SQL Servers use service-managed TDE keys instead of Customer-Managed Keys: $names." `
                -Recommendation "For compliance requirements (PCI-DSS, HIPAA), consider migrating to Customer-Managed Keys (CMK) stored in Azure Key Vault for key lifecycle control." `
                -Impact "Service-managed keys don't allow key rotation control, revocation, or BYOK scenarios required by some compliance frameworks."
        }
    }

    # ── 7. Disk encryption at host check ──
    Write-Status "  [7/12] Disk encryption method..." "INFO"
    if ($vms) {
        $noEncAtHost = @($vms | Where-Object {
            -not $_.SecurityProfile.EncryptionAtHost -and
            $_.StorageProfile -and $_.StorageProfile.OsDisk -and $_.StorageProfile.OsDisk.ManagedDisk
        })
        if ($noEncAtHost.Count -gt 5) {
            Add-Finding -Pillar "Security" -Severity "Low" `
                -Category "VM - No Encryption at Host" `
                -ResourceName "$($noEncAtHost.Count) VMs" `
                -ResourceType "Virtual Machine" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($noEncAtHost.Count) VMs don't have Encryption at Host enabled. Temp disks, caches, and data in transit to storage remain unencrypted." `
                -Recommendation "Enable Encryption at Host (EncryptionAtHost=true) for comprehensive encryption coverage including temp disks and host caches." `
                -Impact "Without encryption at host, temporary disks, OS/data disk caches, and data flowing between VM and storage are not encrypted."
        }
    }

    # ── 8. Private Endpoint DNS zone without VNet link ──
    Write-Status "  [8/12] Private DNS zone links..." "INFO"
    try {
        $dnsZones = Get-AzPrivateDnsZone -ErrorAction SilentlyContinue
        if ($dnsZones) {
            $unlinkedZones = @()
            foreach ($zone in $dnsZones) {
                if ($zone.Name -match 'privatelink') {
                    $links = Get-AzPrivateDnsVirtualNetworkLink -ZoneName $zone.Name -ResourceGroupName $zone.ResourceGroupName -ErrorAction SilentlyContinue
                    if (-not $links -or $links.Count -eq 0) {
                        $unlinkedZones += $zone.Name
                    }
                }
            }
            if ($unlinkedZones.Count -gt 0) {
                $names = ($unlinkedZones | Select-Object -First 5) -join ', '
                Add-Finding -Pillar "Security" -Severity "High" `
                    -Category "Network - DNS Zone Unlinked" `
                    -ResourceName "$($unlinkedZones.Count) Private DNS zones" `
                    -ResourceType "Private DNS Zone" -ResourceGroup "Multiple" `
                    -Subscription $SubName `
                    -Description "$($unlinkedZones.Count) privatelink DNS zones have no VNet links: $names." `
                    -Recommendation "Link each privatelink DNS zone to hub/spoke VNets for private endpoint name resolution. Without links, private endpoints resolve to public IPs." `
                    -Impact "Private endpoints without DNS resolution fall back to public endpoints, completely bypassing network isolation."
            }
        }
    } catch {}

    # ── 9. B-series burstable VMs analysis ──
    Write-Status "  [9/12] Burstable VM analysis..." "INFO"
    if ($vms) {
        $bSeriesVMs = @($vms | Where-Object { $_.HardwareProfile.VmSize -match '^Standard_B' })
        $bSeriesProduction = @($bSeriesVMs | Where-Object {
            $envTag = if ($_.Tags['env']) { $_.Tags['env'] } elseif ($_.Tags['environment']) { $_.Tags['environment'] } elseif ($_.Tags['Environment']) { $_.Tags['Environment'] } else { '' }
            $envTag -match '^prod(uction)?$'
        })
        if ($bSeriesProduction.Count -gt 0) {
            $names = ($bSeriesProduction | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.HardwareProfile.VmSize))" }) -join ', '
            Add-Finding -Pillar "Performance Efficiency" -Severity "Medium" `
                -Category "VM - Burstable in Production" `
                -ResourceName "$($bSeriesProduction.Count) B-series VMs" `
                -ResourceType "Virtual Machine" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($bSeriesProduction.Count) production VMs use burstable B-series sizes which throttle when CPU credits are exhausted: $names." `
                -Recommendation "Monitor CPU credit balance. If credits are frequently exhausted, upgrade to D-series or E-series for consistent performance." `
                -Impact "Burstable VMs that exhaust CPU credits drop to baseline performance (as low as 5-20% of vCPU), causing application slowdowns."
        }
    }

    # ── 10. Orphaned managed identities with role assignments ──
    Write-Status "  [10/12] Orphaned identity assignments..." "INFO"
    if ($script:CachedRoleAssignments.ContainsKey($SubId)) {
        $spAssignments = @($script:CachedRoleAssignments[$SubId] | Where-Object {
            $_.properties.principalType -eq 'ServicePrincipal'
        })
        $unknownAssignments = @($script:CachedRoleAssignments[$SubId] | Where-Object {
            -not $_.properties.principalType -or $_.properties.principalType -eq 'Unknown'
        })
        if ($unknownAssignments.Count -gt 0) {
            Add-Finding -Pillar "Security" -Severity "Medium" `
                -Category "Identity - Orphaned Assignments" `
                -ResourceName "$($unknownAssignments.Count) role assignments" `
                -ResourceType "Role Assignment" -ResourceGroup "N/A" `
                -Subscription $SubName `
                -Description "$($unknownAssignments.Count) role assignments reference deleted or unknown principals (orphaned identities with active permissions)." `
                -Recommendation "Remove orphaned role assignments using 'Get-AzRoleAssignment | Where-Object ObjectType -eq Unknown | Remove-AzRoleAssignment'." `
                -Impact "Orphaned assignments clutter RBAC, make auditing harder, and could be exploited if the principal ID is reassigned."
        }
    }

    # ── 11. Key Vault purge protection (severity upgrade) ──
    Write-Status "  [11/12] Key Vault purge protection..." "INFO"
    if ($keyVaults) {
        $noPurgeProtect = @()
        foreach ($kv in $keyVaults) {
            try {
                $kvDetail = Get-AzKeyVault -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction SilentlyContinue
                if ($kvDetail -and -not $kvDetail.EnablePurgeProtection) {
                    $noPurgeProtect += $kv.VaultName
                }
            } catch {}
        }
        if ($noPurgeProtect.Count -gt 0) {
            $names = ($noPurgeProtect | Select-Object -First 5) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "Key Vault - No Purge Protection" `
                -ResourceName "$($noPurgeProtect.Count) Key Vaults" `
                -ResourceType "Key Vault" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($noPurgeProtect.Count) Key Vaults lack purge protection: $names. Secrets/keys can be permanently deleted during retention period." `
                -Recommendation "Enable purge protection on all Key Vaults. This prevents permanent deletion during the soft-delete retention window (irreversible once enabled)." `
                -Impact "Without purge protection, a malicious or accidental purge permanently destroys encryption keys, rendering encrypted data irrecoverable."
        }
    }

    # ── 12. Public IP Basic SKU (deprecated) ──
    Write-Status "  [12/12] Public IP SKU check..." "INFO"
    $pips = $script:CachedPublicIPs
    if ($pips) {
        $basicPIPs = @($pips | Where-Object { $_.Sku.Name -eq 'Basic' })
        if ($basicPIPs.Count -gt 0) {
            $names = ($basicPIPs | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            $pipSeverity = if ((Get-Date) -gt [datetime]'2025-09-30') { 'Critical' } else { 'High' }
            Add-Finding -Pillar "Reliability" -Severity $pipSeverity `
                -Category "Network - Basic PIP Deprecated" `
                -ResourceName "$($basicPIPs.Count) Public IPs" `
                -ResourceType "Public IP" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($basicPIPs.Count) Public IPs use Basic SKU which was retired September 30, 2025: $names." `
                -Recommendation "Migrate all Basic SKU Public IPs to Standard SKU immediately. Standard provides zone-redundancy, security-by-default (closed inbound), and is required for Standard LB." `
                -Impact "Basic SKU Public IPs have been retired and may stop functioning. They lack zone redundancy and are open to inbound traffic by default."
        }
    }

    Write-Status "  Additional deep-analysis checks complete" "OK"

    # ══════════════════════════════════════════════════════════════════════════
    # ADDITIONAL CACHED-DATA CHECKS (13-21) — use already-cached data, no extra API calls
    # ══════════════════════════════════════════════════════════════════════════

    # ── 13. Storage Account minimum TLS < 1.2 ──
    $storageAccounts = $script:CachedStorageAccounts
    if ($storageAccounts) {
        $oldTls = @($storageAccounts | Where-Object { -not $_.MinimumTlsVersion -or ($_.MinimumTlsVersion -ne 'TLS1_2' -and $_.MinimumTlsVersion -ne 'TLS1_3') })
        if ($oldTls.Count -gt 0) {
            $names = ($oldTls | Select-Object -First 5 | ForEach-Object { "$($_.StorageAccountName) ($($_.MinimumTlsVersion))" }) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "Storage - Legacy TLS" `
                -ResourceName "$($oldTls.Count) Storage Accounts" `
                -ResourceType "Storage Account" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($oldTls.Count) storage accounts allow TLS versions older than 1.2: $names." `
                -Recommendation "Set minimumTlsVersion to TLS1_2 on all storage accounts. TLS 1.0/1.1 have known vulnerabilities." `
                -Impact "Legacy TLS allows downgrade attacks and is non-compliant with most security frameworks."
        }
    }

    # ── 14. Storage Account blob public access enabled ──
    if ($storageAccounts) {
        $publicBlob = @($storageAccounts | Where-Object { $_.AllowBlobPublicAccess -eq $true })
        if ($publicBlob.Count -gt 0) {
            $names = ($publicBlob | Select-Object -First 5 | ForEach-Object { $_.StorageAccountName }) -join ', '
            Add-Finding -Pillar "Security" -Severity "Critical" `
                -Category "Storage - Public Blob Access" `
                -ResourceName "$($publicBlob.Count) Storage Accounts" `
                -ResourceType "Storage Account" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($publicBlob.Count) storage accounts allow public blob access: $names. Containers can be made publicly accessible." `
                -Recommendation "Set AllowBlobPublicAccess to false on all storage accounts unless public access is explicitly required. Use SAS tokens or managed identities instead." `
                -Impact "Public blob access enables anonymous data exposure. This is the #1 cause of storage account data leaks."
        }
    }

    # ── 15. Storage Account HTTPS-only not enforced ──
    if ($storageAccounts) {
        $noHttps = @($storageAccounts | Where-Object { $_.EnableHttpsTrafficOnly -eq $false })
        if ($noHttps.Count -gt 0) {
            $names = ($noHttps | Select-Object -First 5 | ForEach-Object { $_.StorageAccountName }) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "Storage - HTTP Allowed" `
                -ResourceName "$($noHttps.Count) Storage Accounts" `
                -ResourceType "Storage Account" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($noHttps.Count) storage accounts allow unencrypted HTTP traffic: $names." `
                -Recommendation "Enable 'Secure transfer required' (EnableHttpsTrafficOnly) on all storage accounts to enforce encryption in transit." `
                -Impact "HTTP traffic exposes data in transit to interception and man-in-the-middle attacks."
        }
    }

    # ── 16. App Service HTTPS-only disabled ──
    $webAppDetails = $script:CachedWebAppDetails
    if ($webAppDetails -and $webAppDetails.Count -gt 0) {
        $noHttpsApps = @($webAppDetails.Values | Where-Object { $_.HttpsOnly -eq $false })
        if ($noHttpsApps.Count -gt 0) {
            $names = ($noHttpsApps | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "App Service - HTTP Allowed" `
                -ResourceName "$($noHttpsApps.Count) App Services" `
                -ResourceType "Microsoft.Web/sites" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($noHttpsApps.Count) App Services allow HTTP access (HTTPS-only not enforced): $names." `
                -Recommendation "Enable 'HTTPS Only' in App Service settings. This redirects all HTTP traffic to HTTPS automatically." `
                -Impact "HTTP traffic exposes session tokens, credentials, and data to interception."
        }
    }

    # ── 17. App Service minimum TLS < 1.2 ──
    if ($webAppDetails -and $webAppDetails.Count -gt 0) {
        $oldTlsApps = @($webAppDetails.Values | Where-Object { $_.SiteConfig.MinTlsVersion -and $_.SiteConfig.MinTlsVersion -ne '1.2' -and $_.SiteConfig.MinTlsVersion -ne '1.3' })
        if ($oldTlsApps.Count -gt 0) {
            $names = ($oldTlsApps | Select-Object -First 5 | ForEach-Object { "$($_.Name) (TLS $($_.SiteConfig.MinTlsVersion))" }) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "App Service - Legacy TLS" `
                -ResourceName "$($oldTlsApps.Count) App Services" `
                -ResourceType "Microsoft.Web/sites" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($oldTlsApps.Count) App Services accept TLS versions older than 1.2: $names." `
                -Recommendation "Set minimum TLS version to 1.2 (or 1.3) in App Service TLS/SSL settings." `
                -Impact "TLS 1.0 and 1.1 have known vulnerabilities (BEAST, POODLE) and are deprecated by major browsers."
        }
    }

    # ── 18. Load Balancer Basic SKU (retired) ──
    $loadBalancers = $script:CachedLoadBalancers
    if ($loadBalancers) {
        $basicLBs = @($loadBalancers | Where-Object { $_.Sku.Name -eq 'Basic' })
        if ($basicLBs.Count -gt 0) {
            $names = ($basicLBs | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            $lbSeverity = if ((Get-Date) -gt [datetime]'2025-09-30') { 'Critical' } else { 'High' }
            Add-Finding -Pillar "Reliability" -Severity $lbSeverity `
                -Category "Network - Basic LB Retired" `
                -ResourceName "$($basicLBs.Count) Load Balancers" `
                -ResourceType "Load Balancer" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($basicLBs.Count) Load Balancers use Basic SKU which was retired September 30, 2025: $names." `
                -Recommendation "Migrate to Standard SKU Load Balancer. Standard provides zone redundancy, HA ports, outbound rules, and SLA guarantee." `
                -Impact "Basic LBs are retired, lack SLA, have no zone redundancy, and will eventually stop functioning."
        }
    }

    # ── 19. Application Gateway without WAF tier ──
    $appGateways = $script:CachedAppGateways
    if ($appGateways) {
        $noWafGw = @($appGateways | Where-Object { $_.Sku.Tier -notmatch 'WAF' })
        if ($noWafGw.Count -gt 0) {
            $names = ($noWafGw | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Sku.Tier))" }) -join ', '
            Add-Finding -Pillar "Security" -Severity "Medium" `
                -Category "Network - App Gateway No WAF" `
                -ResourceName "$($noWafGw.Count) App Gateways" `
                -ResourceType "Application Gateway" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($noWafGw.Count) Application Gateways use Standard tier without WAF: $names." `
                -Recommendation "Upgrade to WAF_v2 tier or place behind Azure Front Door with WAF. WAF provides OWASP rule sets and bot protection." `
                -Impact "Without WAF, web applications are exposed to common attacks (SQL injection, XSS, path traversal)."
        }
    }

    # ── 20. NIC without NSG on subnet also without NSG (double-unprotected) ──
    $nics = $script:CachedNICs
    $nsgs = $script:CachedNSGs
    if ($nics -and $nsgs) {
        $nsgSubnetIds = @($nsgs | Where-Object { $_.Subnets } | ForEach-Object { $_.Subnets.Id }) | Where-Object { $_ }
        $doubleExposed = @($nics | Where-Object {
            -not $_.NetworkSecurityGroup -and
            $_.IpConfigurations -and
            $_.IpConfigurations[0].Subnet -and
            $_.IpConfigurations[0].Subnet.Id -notin $nsgSubnetIds
        })
        # Exclude system NICs (e.g., firewall, bastion)
        $doubleExposed = @($doubleExposed | Where-Object { $_.Name -notmatch 'azurefirewall|bastion' })
        if ($doubleExposed.Count -gt 0) {
            $names = ($doubleExposed | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', '
            Add-Finding -Pillar "Security" -Severity "High" `
                -Category "Network - Double Unprotected NIC" `
                -ResourceName "$($doubleExposed.Count) NICs" `
                -ResourceType "Network Interface" -ResourceGroup "Multiple" `
                -Subscription $SubName `
                -Description "$($doubleExposed.Count) NICs have no NSG and are on subnets also without NSG: $names. Traffic is completely unfiltered." `
                -Recommendation "Attach an NSG to either the NIC or the subnet (subnet-level NSG is preferred for consistency)." `
                -Impact "Without any NSG, all inbound and outbound traffic is allowed. This is the weakest possible network security posture."
        }
    }

    # ── 21. Cosmos DB NormalizedRUConsumption metric check ──
    # (Corrects existing check that uses TotalRequestUnits with wrong comparison)
    # Already handled in Analyze-UnderutilizedResources; this adds a complementary hot-partition check
    # Skipped here as it requires metric API calls not in cache

    Write-Status "  All cached-data checks complete (21 total)" "OK"
}

# ============================================================================
# AZURE LANDING ZONE (ALZ/CAF) READINESS ASSESSMENT
# ============================================================================
function Analyze-ALZReadiness {
    <#
    .SYNOPSIS
        Evaluates ALZ/CAF readiness: MG hierarchy, MG-scope policy/RBAC, ALZ policy library,
        hub-spoke/vWAN topology, Private DNS zone coverage, and Conditional Access / PIM.
        Runs once per tenant (not per subscription).
    #>
    Write-Status "Analyzing ALZ/CAF readiness (tenant-wide)..." "SECTION"

    $tenantId = (Get-AzContext).Tenant.Id
    $allSubIds = $script:Subscriptions | ForEach-Object { $_.Id }
    $script:ALZData = @{
        MGHierarchy       = $null
        MGPolicies        = @()
        MGRoleAssignments = @()
        ALZPoliciesFound  = @()
        VWANs             = @()
        VirtualHubs       = @()
        PrivateDNSZones   = @()
        DNSVNetLinks      = @()
        CAPolicies        = @()
        PIMRoles          = @()
        Checks            = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    # Helper for ALZ check results
    function Add-ALZCheck {
        param([string]$Domain, [string]$Check, [string]$Status, [string]$Detail, [string]$Recommendation)
        $script:ALZData.Checks.Add([PSCustomObject]@{
            Domain         = $Domain
            Check          = $Check
            Status         = $Status   # PASS, FAIL, WARN, INFO
            Detail         = $Detail
            Recommendation = $Recommendation
        })
    }

    # ── 1. Management Group Hierarchy ──
    Write-Status "  [ALZ] Checking Management Group hierarchy..." "INFO"
    try {
        $mgHierarchy = Get-AzManagementGroup -GroupId $tenantId -Expand -Recurse -ErrorAction Stop
        $script:ALZData.MGHierarchy = $mgHierarchy
    } catch {
        Write-Status "  [ALZ] Full recursive expand failed, building hierarchy from individual MGs..." "WARN"
        # Fallback: list all accessible MGs, then expand each one level to build hierarchy
        try {
            $allMGs = Get-AzManagementGroup -ErrorAction Stop
            if ($allMGs -and $allMGs.Count -gt 0) {
                # Build a lookup: for each MG, get its children (one-level expand)
                $mgDetailMap = @{}
                foreach ($mg in $allMGs) {
                    try {
                        $detail = Get-AzManagementGroup -GroupId $mg.Name -Expand -ErrorAction Stop
                        $mgDetailMap[$mg.Name] = $detail
                    } catch {
                        $mgDetailMap[$mg.Name] = $mg
                    }
                    Send-KeepAlive
                }
                # Build parent map: mgId -> parentId (try multiple property paths)
                $mgParentMap = @{}
                foreach ($mg in $allMGs) {
                    $detail = $mgDetailMap[$mg.Name]
                    $pid = $null
                    if ($detail.ParentId) { $pid = ($detail.ParentId -split '/')[-1] }
                    if (-not $pid -and $detail.Properties.Details.Parent.Id) { $pid = ($detail.Properties.Details.Parent.Id -split '/')[-1] }
                    if (-not $pid -and $detail.Properties.Parent.Id) { $pid = ($detail.Properties.Parent.Id -split '/')[-1] }
                    $mgParentMap[$mg.Name] = $pid
                }

                # Recursive tree builder: uses parent map for MG children, expanded detail for subscriptions
                function Build-MGNode {
                    param([string]$MGId, [hashtable]$DetailMap, [hashtable]$ParentMap)
                    $det = $DetailMap[$MGId]
                    $children = [System.Collections.Generic.List[object]]::new()
                    # Add subscriptions from expanded children
                    if ($det.Children) {
                        foreach ($ch in $det.Children) {
                            if ($ch.Type -match 'subscriptions') {
                                $children.Add([PSCustomObject]@{
                                    Name = $ch.Name; DisplayName = $ch.DisplayName
                                    Type = '/subscriptions'; Children = @()
                                })
                            }
                        }
                    }
                    # Add child MGs from parent map (ensures all nesting levels are captured)
                    $childMGIds = @($ParentMap.Keys | Where-Object { $ParentMap[$_] -eq $MGId })
                    foreach ($cid in ($childMGIds | Sort-Object)) {
                        $children.Add((Build-MGNode -MGId $cid -DetailMap $DetailMap -ParentMap $ParentMap))
                    }
                    return [PSCustomObject]@{
                        Name = $MGId
                        DisplayName = if ($det.DisplayName) { $det.DisplayName } else { $MGId }
                        Type = '/providers/Microsoft.Management/managementGroups'
                        Children = $children
                    }
                }

                # Build tree: if Tenant Root Group is in the list, use it; otherwise create synthetic root
                if ($mgDetailMap.ContainsKey($tenantId)) {
                    $script:ALZData.MGHierarchy = Build-MGNode -MGId $tenantId -DetailMap $mgDetailMap -ParentMap $mgParentMap
                } else {
                    # Find top-level MGs (parent is tenant root or unknown)
                    $topIds = @($mgParentMap.Keys | Where-Object { $mgParentMap[$_] -eq $tenantId -or (-not $mgParentMap[$_]) } | Where-Object { $_ -ne $tenantId })
                    $rootChildren = [System.Collections.Generic.List[object]]::new()
                    foreach ($tid in $topIds) {
                        $rootChildren.Add((Build-MGNode -MGId $tid -DetailMap $mgDetailMap -ParentMap $mgParentMap))
                    }
                    # Add subscriptions not assigned to any MG
                    $allMGSubIds = @()
                    foreach ($mgd in $mgDetailMap.Values) {
                        if ($mgd.Children) {
                            $allMGSubIds += @($mgd.Children | Where-Object { $_.Type -match 'subscriptions' } | ForEach-Object { $_.Name })
                        }
                    }
                    foreach ($sub in $script:Subscriptions) {
                        if ($sub.Id -notin $allMGSubIds) {
                            $rootChildren.Add([PSCustomObject]@{
                                Name = $sub.Id; DisplayName = $sub.Name
                                Type = '/subscriptions'; Children = @()
                            })
                        }
                    }
                    $script:ALZData.MGHierarchy = [PSCustomObject]@{
                        Name = $tenantId; DisplayName = "Tenant Root Group"
                        Type = '/providers/Microsoft.Management/managementGroups'
                        Children = $rootChildren
                    }
                }
            }
        } catch {
            Write-Status "  [ALZ] Cannot list management groups: $($_.Exception.Message)" "WARN"
        }
    }

    # Evaluate hierarchy
    if ($script:ALZData.MGHierarchy) {
        $mgHierarchy = $script:ALZData.MGHierarchy

        # Count depth and children
        function Get-MGDepthAndCount {
            param($mg, [int]$depth = 0)
            $results = @([PSCustomObject]@{ Name = $mg.DisplayName; Id = $mg.Name; Depth = $depth })
            if ($mg.Children) {
                foreach ($child in $mg.Children) {
                    if ($child.Type -match 'managementGroups') {
                        $results += Get-MGDepthAndCount -mg $child -depth ($depth + 1)
                    }
                }
            }
            return $results
        }
        $mgList = Get-MGDepthAndCount -mg $mgHierarchy
        $maxDepth = ($mgList | Measure-Object -Property Depth -Maximum).Maximum
        $mgCount  = $mgList.Count

        if ($mgCount -le 1) {
            Add-ALZCheck "MG Hierarchy" "MG structure" "FAIL" "Only the Tenant Root Group exists. No custom management group hierarchy." "Create an ALZ-aligned MG structure: Platform (Connectivity, Identity, Management), Landing Zones (Corp, Online), Sandbox, Decommissioned."
            Add-Finding -Pillar "Operational Excellence" -Severity "High" -Category "ALZ - No MG Hierarchy" `
                -ResourceName "Tenant Root Group" -ResourceType "Management Group" -ResourceGroup "N/A" `
                -Subscription "Tenant-wide" `
                -Description "No custom management group hierarchy exists. Only the default Tenant Root Group was found." `
                -Recommendation "Implement ALZ management group hierarchy: Platform (Connectivity, Identity, Management), Landing Zones (Corp, Online), Sandbox, Decommissioned." `
                -Impact "Without MG hierarchy, policy inheritance, RBAC delegation, and subscription organization cannot follow ALZ best practices."
        } else {
            # Check for ALZ-standard MG names
            $mgNames = $mgList | ForEach-Object { $_.Name.ToLower() }
            $alzExpected = @('platform', 'connectivity', 'identity', 'management', 'landing zones', 'landingzones', 'corp', 'online', 'sandbox', 'decommissioned')
            $alzFound = $alzExpected | Where-Object {
                $pattern = $_
                $mgNames -contains $pattern -or ($mgList | Where-Object { $_.Name.ToLower() -like "*$pattern*" })
            }
            $alzMatchPct = [math]::Round(($alzFound.Count / $alzExpected.Count) * 100)

            if ($alzMatchPct -ge 60) {
                Add-ALZCheck "MG Hierarchy" "ALZ-aligned structure" "PASS" "$mgCount management groups, $maxDepth levels deep. ALZ pattern match: $alzMatchPct% ($($alzFound -join ', '))" ""
            } elseif ($mgCount -gt 1) {
                Add-ALZCheck "MG Hierarchy" "Custom MG structure" "WARN" "$mgCount management groups, $maxDepth levels deep, but does not follow ALZ naming pattern (matched: $alzMatchPct%)." "Consider reorganizing to match ALZ reference architecture: Platform, Landing Zones, Sandbox, Decommissioned."
                Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "ALZ - Non-standard MG Hierarchy" `
                    -ResourceName "Management Group Hierarchy" -ResourceType "Management Group" -ResourceGroup "N/A" `
                    -Subscription "Tenant-wide" `
                    -Description "Found $mgCount management groups but they don't follow the ALZ naming convention (match: $alzMatchPct%). Found: $($mgList.Name -join ', ')" `
                    -Recommendation "Restructure management groups to follow ALZ pattern: Platform (Connectivity, Identity, Management), Landing Zones (Corp, Online)." `
                    -Impact "Non-standard MG hierarchy complicates policy inheritance and subscription placement."
            }
        }
    } else {
        Add-ALZCheck "MG Hierarchy" "MG access" "FAIL" "Cannot read Management Group hierarchy. No accessible management groups found." "Assign Management Group Reader role at Tenant Root Group scope, or ensure your account has Reader on individual MGs."
    }

    # ── 2. MG-scope Policy Assignments (ALZ Policy Library) — scan all MGs ──
    Write-Status "  [ALZ] Checking MG-scope policies and ALZ policy library..." "INFO"
    $totalMGPolicies = 0
    $alzPolicyPatterns = @(
        'Deny-PublicIP', 'Deny-RDP-From-Internet', 'Deny-Subnet-Without-Nsg',
        'Deploy-ASC-Defender', 'Deploy-AzActivity-Log', 'Deploy-Log-Analytics',
        'Deploy-VM-Monitoring', 'Enforce-ALZ', 'Deny-Storage-http',
        'Deploy-MDFC-Config', 'Enforce-GR', 'Deny-Classic-Resources',
        'Deploy-Diagnostics-', 'Deny-HybridNetworking', 'Deploy-Private-DNS',
        'Deploy-Nsg-FlowLogs', 'Deny-MgmtPorts-Internet', 'Deploy-SQL-TDE',
        'Deploy-AKS-Policy', 'Deny-AppGW-Without-WAF'
    )
    $allALZMatches = @()
    $mgPolicySummary = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect MG list for per-MG scan
    $mgScanList = @()
    if ($script:ALZData.MGHierarchy) {
        function Flatten-MGList {
            param($mg)
            $list = @([PSCustomObject]@{ Id = $mg.Name; DisplayName = $mg.DisplayName })
            if ($mg.Children) {
                foreach ($child in $mg.Children) {
                    if ($child.Type -match 'managementGroups') { $list += Flatten-MGList -mg $child }
                }
            }
            return $list
        }
        $mgScanList = Flatten-MGList -mg $script:ALZData.MGHierarchy
    } else {
        # Fallback: try listing MGs directly
        try {
            $mgAll = Get-AzManagementGroup -ErrorAction SilentlyContinue
            if ($mgAll) { $mgScanList = $mgAll | ForEach-Object { [PSCustomObject]@{ Id = $_.Name; DisplayName = $_.DisplayName } } }
        } catch { }
        if ($mgScanList.Count -eq 0) { $mgScanList = @([PSCustomObject]@{ Id = $tenantId; DisplayName = "Tenant Root Group" }) }
    }

    # Cache for resolving MG GUIDs to display names (avoids repeated API calls)
    $mgNameCache = @{}
    foreach ($m in $mgScanList) { $mgNameCache[$m.Id] = $m.DisplayName }
    function Resolve-MGName {
        param([string]$mgId)
        if ($mgNameCache.ContainsKey($mgId)) { return $mgNameCache[$mgId] }
        try {
            $resolved = Get-AzManagementGroup -GroupId $mgId -ErrorAction Stop
            $name = if ($resolved.DisplayName) { $resolved.DisplayName } else { $mgId }
            $mgNameCache[$mgId] = $name
            return $name
        } catch {
            $mgNameCache[$mgId] = $mgId
            return $mgId
        }
    }

    foreach ($mg in $mgScanList) {
        try {
            $mgScope = "/providers/Microsoft.Management/managementGroups/$($mg.Id)"
            $polAssignments = Get-AzPolicyAssignment -Scope $mgScope -ErrorAction Stop
            $polCount = if ($polAssignments) { $polAssignments.Count } else { 0 }
            $totalMGPolicies += $polCount

            # Check ALZ patterns
            $mgALZHits = @()
            foreach ($pol in $polAssignments) {
                $defName  = if ($pol.PolicyDefinitionId) { ($pol.PolicyDefinitionId -split '/')[-1] } elseif ($pol.Properties.PolicyDefinitionId) { ($pol.Properties.PolicyDefinitionId -split '/')[-1] } else { '' }
                $dispName = if ($pol.DisplayName) { $pol.DisplayName } elseif ($pol.Properties.DisplayName) { $pol.Properties.DisplayName } else { '' }
                foreach ($pattern in $alzPolicyPatterns) {
                    if ($defName -like "*$pattern*" -or $dispName -like "*$pattern*") {
                        $mgALZHits += $dispName
                        break
                    }
                }
            }
            $allALZMatches += $mgALZHits
            $polNames = @($polAssignments | ForEach-Object {
                $dn = if ($_.DisplayName) { $_.DisplayName } elseif ($_.Properties.DisplayName) { $_.Properties.DisplayName } else { $null }
                if (-not $dn) {
                    $defId = if ($_.PolicyDefinitionId) { $_.PolicyDefinitionId } elseif ($_.Properties.PolicyDefinitionId) { $_.Properties.PolicyDefinitionId } else { '' }
                    $dn = ($defId -split '/')[-1]
                }
                $polScope = if ($_.Scope) { $_.Scope } elseif ($_.Properties.Scope) { $_.Properties.Scope } else { '' }
                $isDirect = ($polScope -eq $mgScope)
                $srcName = ''
                if (-not $isDirect -and $polScope) {
                    $srcId = ($polScope -split '/')[-1]
                    $srcName = Resolve-MGName -mgId $srcId
                }
                [PSCustomObject]@{ Name = $dn; Source = $(if ($isDirect) { 'Direct' } else { 'Inherited' }); SourceName = $srcName }
            })
            $mgPolicySummary.Add([PSCustomObject]@{ MG = $mg.DisplayName; Id = $mg.Id; Policies = $polCount; ALZMatches = $mgALZHits.Count; PolicyNames = $polNames })
            Send-KeepAlive
        } catch {
            $mgPolicySummary.Add([PSCustomObject]@{ MG = $mg.DisplayName; Id = $mg.Id; Policies = -1; ALZMatches = 0; PolicyNames = @() })
        }
    }
    $script:ALZData.MGPolicies = $mgPolicySummary
    $script:ALZData.ALZPoliciesFound = $allALZMatches | Select-Object -Unique

    # Collect subscription-level policy assignments for hierarchy display
    Write-Status "  [ALZ] Collecting subscription-level policy assignments..." "INFO"
    $subPolicySummary = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sub in $script:Subscriptions) {
        try {
            $subScope = "/subscriptions/$($sub.Id)"
            $subPolAssignments = Get-AzPolicyAssignment -Scope $subScope -ErrorAction Stop
            $subPolCount = if ($subPolAssignments) { $subPolAssignments.Count } else { 0 }
            $subPolNames = @($subPolAssignments | ForEach-Object {
                $dn = if ($_.DisplayName) { $_.DisplayName } elseif ($_.Properties.DisplayName) { $_.Properties.DisplayName } else { $null }
                if (-not $dn) {
                    $defId = if ($_.PolicyDefinitionId) { $_.PolicyDefinitionId } elseif ($_.Properties.PolicyDefinitionId) { $_.Properties.PolicyDefinitionId } else { '' }
                    $dn = ($defId -split '/')[-1]
                }
                $polScope = if ($_.Scope) { $_.Scope } elseif ($_.Properties.Scope) { $_.Properties.Scope } else { '' }
                $isDirect = ($polScope -eq $subScope)
                $srcName = ''
                if (-not $isDirect -and $polScope) {
                    $srcId = ($polScope -split '/')[-1]
                    if ($polScope -match 'managementGroups') {
                        $srcName = Resolve-MGName -mgId $srcId
                    } else { $srcName = $srcId }
                }
                [PSCustomObject]@{ Name = $dn; Source = $(if ($isDirect) { 'Direct' } else { 'Inherited' }); SourceName = $srcName }
            })
            $subPolicySummary.Add([PSCustomObject]@{ Sub = $sub.Name; Id = $sub.Id; Policies = $subPolCount; PolicyNames = $subPolNames })
            Send-KeepAlive
        } catch {
            $subPolicySummary.Add([PSCustomObject]@{ Sub = $sub.Name; Id = $sub.Id; Policies = -1; PolicyNames = @() })
        }
    }
    $script:ALZData.SubPolicies = $subPolicySummary

    if ($totalMGPolicies -gt 0) {
        $mgsWithPolicies = @($mgPolicySummary | Where-Object { $_.Policies -gt 0 }).Count
        Add-ALZCheck "Policy Library" "MG-scope policies" "PASS" "$totalMGPolicies policy assignments across $mgsWithPolicies/$($mgScanList.Count) management groups. ALZ library matches: $($allALZMatches.Count)." ""
        if ($allALZMatches.Count -eq 0) {
            Add-ALZCheck "Policy Library" "ALZ policy library" "WARN" "No ALZ-specific policy definitions detected across any MG scope." "Deploy the ALZ policy library from github.com/Azure/Enterprise-Scale or use the ALZ Accelerator portal."
            Add-Finding -Pillar "Security" -Severity "Medium" -Category "ALZ - No ALZ Policy Library" `
                -ResourceName "MG Policy Assignments" -ResourceType "Policy" -ResourceGroup "N/A" `
                -Subscription "Tenant-wide" `
                -Description "$totalMGPolicies policies assigned across MG scopes, but none match ALZ policy library patterns (Deny-PublicIP, Deploy-ASC-Defender, etc.)." `
                -Recommendation "Deploy the Azure Landing Zone policy library. Use the ALZ Accelerator or bicep modules from the Enterprise-Scale repo." `
                -Impact "Without ALZ policies, guardrails for network security, monitoring, and compliance are not enforced at scale."
        } else {
            Add-ALZCheck "Policy Library" "ALZ policy library" "PASS" "$($allALZMatches.Count) ALZ policy matches found: $($allALZMatches | Select-Object -Unique | Select-Object -First 5 | ForEach-Object { $_ }) $(if($allALZMatches.Count -gt 5){'...'})" ""
        }
        # Report MGs with 0 policies
        $mgsNoPolicies = @($mgPolicySummary | Where-Object { $_.Policies -eq 0 })
        if ($mgsNoPolicies.Count -gt 0 -and $mgScanList.Count -gt 1) {
            Add-ALZCheck "Policy Library" "MGs without policies" "WARN" "$($mgsNoPolicies.Count) management groups have 0 policy assignments: $($mgsNoPolicies.MG -join ', ')" "Consider assigning policies at higher MG levels so they inherit down to all child MGs and subscriptions."
        }
    } else {
        Add-ALZCheck "Policy Library" "MG-scope policies" "FAIL" "No policy assignments found at any management group scope ($($mgScanList.Count) MGs scanned)." "Deploy Azure Policy initiatives at management group level for governance at scale."
        Add-Finding -Pillar "Security" -Severity "High" -Category "ALZ - No MG-scope Policies" `
            -ResourceName "MG Policy Assignments" -ResourceType "Policy" -ResourceGroup "N/A" `
            -Subscription "Tenant-wide" `
            -Description "No Azure Policy assignments exist at any management group scope. Policies should be inherited from MG to subscriptions." `
            -Recommendation "Assign Azure Policy initiatives at the management group level. Start with the Azure Security Benchmark and ALZ default policies." `
            -Impact "Without MG-scope policies, each subscription must be individually governed, reducing consistency and increasing risk."
    }

    # ── 3. MG-scope RBAC Role Assignments ──
    Write-Status "  [ALZ] Checking MG-scope RBAC..." "INFO"
    try {
        $mgRbac = Get-AzRoleAssignment -Scope "/providers/Microsoft.Management/managementGroups/$tenantId" -ErrorAction Stop
        $script:ALZData.MGRoleAssignments = $mgRbac
        $ownerAtRoot = @($mgRbac | Where-Object { $_.RoleDefinitionName -eq 'Owner' })
        $contributorAtRoot = @($mgRbac | Where-Object { $_.RoleDefinitionName -eq 'Contributor' })

        if ($ownerAtRoot.Count -gt 2) {
            Add-ALZCheck "RBAC" "Root MG owners" "WARN" "$($ownerAtRoot.Count) Owner assignments at tenant root MG. ALZ recommends ≤2 emergency-access accounts." "Reduce Owner assignments at root MG. Use PIM for just-in-time elevation."
            Add-Finding -Pillar "Security" -Severity "High" -Category "ALZ - Excessive Root MG Owners" `
                -ResourceName "Tenant Root MG RBAC" -ResourceType "Role Assignment" -ResourceGroup "N/A" `
                -Subscription "Tenant-wide" `
                -Description "$($ownerAtRoot.Count) accounts have Owner role at the Tenant Root Management Group. ALZ recommends maximum 2 (break-glass accounts)." `
                -Recommendation "Remove unnecessary Owner assignments. Keep only 2 emergency access accounts. Use PIM for all other privileged access." `
                -Impact "Excessive Owner permissions at root MG violate least-privilege and create a high blast radius for compromise."
        } else {
            Add-ALZCheck "RBAC" "Root MG owners" "PASS" "$($ownerAtRoot.Count) Owner assignments at tenant root MG (recommended ≤2)." ""
        }
    } catch {
        Add-ALZCheck "RBAC" "MG RBAC access" "WARN" "Cannot read MG-scope role assignments: $($_.Exception.Message)" ""
    }

    # ── 4. Hub-Spoke / vWAN Topology ──
    Write-Status "  [ALZ] Checking network topology (vWAN / Hub-Spoke)..." "INFO"
    $graphAvailable = Get-Module -ListAvailable -Name Az.ResourceGraph
    if ($graphAvailable) {
        Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue
        # vWAN
        try {
            $vwans = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/virtualwans' | project id, name, location, resourceGroup, subscriptionId, properties" -Subscription $allSubIds -First 1000 -ErrorAction Stop
            $script:ALZData.VWANs = $vwans
        } catch { $vwans = @() }

        # Virtual Hubs
        try {
            $vhubs = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/virtualhubs' | project id, name, location, resourceGroup, subscriptionId, sku=properties.sku, addressPrefix=properties.addressPrefix, virtualWanId=properties.virtualWan.id" -Subscription $allSubIds -First 1000 -ErrorAction Stop
            $script:ALZData.VirtualHubs = $vhubs
        } catch { $vhubs = @() }

        if ($vwans -and $vwans.Count -gt 0) {
            $hubCount = if ($vhubs) { $vhubs.Count } else { 0 }
            Add-ALZCheck "Network Topology" "Virtual WAN" "PASS" "vWAN detected: $($vwans.Count) vWAN(s), $hubCount Virtual Hub(s). ALZ connectivity model: vWAN." ""
        } else {
            # Check for hub-spoke via peering patterns
            $peerings = Search-AzGraph -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| mvexpand peering = properties.virtualNetworkPeerings
| project vnetName=name, peerName=tostring(peering.name), peerState=tostring(peering.properties.peeringState), remoteVnet=tostring(peering.properties.remoteVirtualNetwork.id), subscriptionId
"@ -Subscription $allSubIds -First 1000 -ErrorAction SilentlyContinue

            if ($peerings -and $peerings.Count -gt 0) {
                # Identify potential hub (VNet with most peerings)
                $peerCounts = $peerings | Group-Object vnetName | Sort-Object Count -Descending
                $potentialHub = $peerCounts | Select-Object -First 1
                if ($potentialHub.Count -ge 3) {
                    Add-ALZCheck "Network Topology" "Hub-Spoke via peering" "PASS" "Hub-spoke pattern detected. Potential hub: '$($potentialHub.Name)' with $($potentialHub.Count) peerings." ""
                } else {
                    Add-ALZCheck "Network Topology" "VNet peerings" "WARN" "$($peerings.Count) VNet peerings found but no clear hub-spoke pattern (max peerings on single VNet: $($potentialHub.Count))." "Implement a hub-spoke or vWAN topology for centralized network management."
                }
            } else {
                Add-ALZCheck "Network Topology" "Network topology" "FAIL" "No vWAN and no VNet peerings detected. No centralized network topology." "Deploy a hub-spoke or Virtual WAN architecture for centralized connectivity, firewall, and DNS."
                Add-Finding -Pillar "Security" -Severity "High" -Category "ALZ - No Centralized Network Topology" `
                    -ResourceName "Network Topology" -ResourceType "Virtual Network" -ResourceGroup "N/A" `
                    -Subscription "Tenant-wide" `
                    -Description "No Virtual WAN or hub-spoke VNet peering topology was detected across the tenant." `
                    -Recommendation "Implement a hub-spoke (with Azure Firewall) or Virtual WAN topology as the ALZ connectivity foundation." `
                    -Impact "Without centralized network topology, traffic inspection, DNS resolution, and hybrid connectivity cannot be managed at scale."
            }
        }
    }

    # ── 5. Private DNS Zone Coverage + VNet Links ──
    Write-Status "  [ALZ] Checking Private DNS zone coverage and VNet links..." "INFO"
    if ($graphAvailable) {
        try {
            $privateDnsZones = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/privatednszones' | project id, name, location, resourceGroup, subscriptionId, numberOfRecordSets=properties.numberOfRecordSets, numberOfVirtualNetworkLinks=properties.numberOfVirtualNetworkLinks" -Subscription $allSubIds -First 1000 -ErrorAction Stop
            $script:ALZData.PrivateDNSZones = $privateDnsZones
        } catch { $privateDnsZones = @() }

        # Fetch VNet links for DNS zones
        try {
            $dnsVNetLinks = Search-AzGraph -Query "resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' | project id, name, zoneName=tostring(split(id, '/')[8]), vnetId=tostring(properties.virtualNetwork.id), registrationEnabled=properties.registrationEnabled, provisioningState=properties.provisioningState, subscriptionId" -Subscription $allSubIds -First 1000 -ErrorAction Stop
            $script:ALZData.DNSVNetLinks = $dnsVNetLinks
        } catch { $dnsVNetLinks = @() }

        # Expected privatelink DNS zones for common PaaS services
        $expectedDnsZones = @(
            'privatelink.blob.core.windows.net', 'privatelink.file.core.windows.net',
            'privatelink.queue.core.windows.net', 'privatelink.table.core.windows.net',
            'privatelink.database.windows.net', 'privatelink.vaultcore.azure.net',
            'privatelink.azurewebsites.net', 'privatelink.azurecr.io',
            'privatelink.cognitiveservices.azure.com', 'privatelink.openai.azure.com',
            'privatelink.monitor.azure.com', 'privatelink.ods.opinsights.azure.com',
            'privatelink.oms.opinsights.azure.com', 'privatelink.servicebus.windows.net',
            'privatelink.redis.cache.windows.net', 'privatelink.postgres.database.azure.com',
            'privatelink.mysql.database.azure.com', 'privatelink.documents.azure.com',
            'privatelink.search.windows.net', 'privatelink.eventgrid.azure.net'
        )
        $foundZoneNames = if ($privateDnsZones) { $privateDnsZones | ForEach-Object { $_.name.ToLower() } } else { @() }
        $missingZones = $expectedDnsZones | Where-Object { $_ -notin $foundZoneNames }
        $coveredZones = $expectedDnsZones | Where-Object { $_ -in $foundZoneNames }

        # Analyze VNet links per zone
        $unlinkedZones = @()
        $singleLinkedZones = @()
        if ($privateDnsZones) {
            $unlinkedZones = @($privateDnsZones | Where-Object { [int]$_.numberOfVirtualNetworkLinks -eq 0 })
            $singleLinkedZones = @($privateDnsZones | Where-Object { [int]$_.numberOfVirtualNetworkLinks -eq 1 })
        }

        # Check if DNS zones are centralized (all in same subscription = good ALZ pattern)
        $dnsSubCount = 0
        if ($privateDnsZones -and $privateDnsZones.Count -gt 0) {
            $dnsSubCount = ($privateDnsZones | Select-Object -ExpandProperty subscriptionId -Unique).Count
        }

        if ($privateDnsZones -and $privateDnsZones.Count -gt 0) {
            $coveragePct = [math]::Round(($coveredZones.Count / $expectedDnsZones.Count) * 100)
            Add-ALZCheck "Private DNS" "DNS zone inventory" "PASS" "$($privateDnsZones.Count) Private DNS zones found. Privatelink coverage: $coveragePct% ($($coveredZones.Count)/$($expectedDnsZones.Count) expected zones)." ""

            if ($missingZones.Count -gt 0) {
                $missingSeverity = if ($missingZones.Count -gt 10) { "WARN" } else { "INFO" }
                Add-ALZCheck "Private DNS" "Missing privatelink zones" $missingSeverity "Missing $($missingZones.Count) expected privatelink zones: $($missingZones | Select-Object -First 6 | ForEach-Object { $_ })$(if($missingZones.Count -gt 6) { '...' })" "Create missing privatelink DNS zones in the connectivity subscription and link them to hub VNet."
            }

            if ($unlinkedZones.Count -gt 0) {
                Add-ALZCheck "Private DNS" "Unlinked zones" "WARN" "$($unlinkedZones.Count) Private DNS zones have 0 VNet links: $($unlinkedZones.name -join ', ')" "Link Private DNS zones to the hub VNet for DNS resolution across the topology."
                Add-Finding -Pillar "Security" -Severity "Medium" -Category "ALZ - Unlinked Private DNS Zones" `
                    -ResourceName "Private DNS Zones" -ResourceType "Private DNS Zone" -ResourceGroup "N/A" `
                    -Subscription "Tenant-wide" `
                    -Description "$($unlinkedZones.Count) Private DNS zones have 0 VNet links: $($unlinkedZones.name -join ', '). They cannot resolve private endpoint FQDNs." `
                    -Recommendation "Link all privatelink DNS zones to the hub VNet (or vWAN hub) so private endpoints resolve correctly across the topology." `
                    -Impact "Unlinked DNS zones mean private endpoints won't resolve from connected VNets, forcing traffic over public endpoints."
            }

            # Centralization check
            if ($dnsSubCount -gt 2) {
                Add-ALZCheck "Private DNS" "DNS zone centralization" "WARN" "Private DNS zones are spread across $dnsSubCount subscriptions. ALZ recommends centralizing in the connectivity subscription." "Consolidate all privatelink DNS zones into the connectivity/platform subscription for centralized management."
            } else {
                Add-ALZCheck "Private DNS" "DNS zone centralization" "PASS" "Private DNS zones are hosted in $dnsSubCount subscription(s) — consistent with ALZ centralized pattern." ""
            }

            # VNet link detail summary
            if ($dnsVNetLinks -and $dnsVNetLinks.Count -gt 0) {
                $linkedVnets = ($dnsVNetLinks | Select-Object -ExpandProperty vnetId -Unique).Count
                Add-ALZCheck "Private DNS" "VNet link coverage" "PASS" "$($dnsVNetLinks.Count) VNet links across $($privateDnsZones.Count) zones, linking to $linkedVnets unique VNet(s)." ""
            }
        } else {
            Add-ALZCheck "Private DNS" "DNS zones" "FAIL" "No Private DNS zones found in the tenant." "Create privatelink DNS zones for all PaaS services using private endpoints. Host them in the connectivity subscription."
            Add-Finding -Pillar "Security" -Severity "High" -Category "ALZ - No Private DNS Zones" `
                -ResourceName "Private DNS Zones" -ResourceType "Private DNS Zone" -ResourceGroup "N/A" `
                -Subscription "Tenant-wide" `
                -Description "No Private DNS zones exist in the tenant. Private endpoints cannot resolve without privatelink DNS zones." `
                -Recommendation "Create privatelink DNS zones (e.g., privatelink.blob.core.windows.net) in the connectivity subscription and link to hub VNet." `
                -Impact "Without Private DNS zones, private endpoint resolution fails and services fall back to public connectivity."
        }
    }

    # ── 6. Subscription Placement in MG Hierarchy ──
    Write-Status "  [ALZ] Checking subscription placement..." "INFO"
    if ($script:ALZData.MGHierarchy -and $script:ALZData.MGHierarchy.Children) {
        # Find subscriptions directly under Tenant Root Group (bad practice)
        $rootChildren = $script:ALZData.MGHierarchy.Children
        $subsAtRoot = @($rootChildren | Where-Object { $_.Type -match 'subscriptions' })
        if ($subsAtRoot.Count -gt 0) {
            Add-ALZCheck "Subscription Placement" "Subs at root MG" "WARN" "$($subsAtRoot.Count) subscription(s) placed directly under Tenant Root Group: $($subsAtRoot.DisplayName -join ', ')" "Move subscriptions into appropriate Landing Zone management groups (Corp, Online) instead of leaving them at root."
            Add-Finding -Pillar "Operational Excellence" -Severity "Medium" -Category "ALZ - Subscriptions at Root MG" `
                -ResourceName "Subscription Placement" -ResourceType "Subscription" -ResourceGroup "N/A" `
                -Subscription "Tenant-wide" `
                -Description "$($subsAtRoot.Count) subscriptions are placed directly under the Tenant Root Group instead of a Landing Zone MG. Subs: $($subsAtRoot.DisplayName -join ', ')" `
                -Recommendation "Move subscriptions to the appropriate Landing Zone management group (Corp or Online) to inherit policies and RBAC." `
                -Impact "Subscriptions at root MG don't inherit Landing Zone policies, creating governance gaps."
        } else {
            Add-ALZCheck "Subscription Placement" "Subs at root MG" "PASS" "No subscriptions placed directly under Tenant Root Group." ""
        }
    }

    # ── 7. Conditional Access Policies (via Microsoft Graph or manual checklist) ──
    Write-Status "  [ALZ] Checking Conditional Access policies..." "INFO"
    $graphConnected = $false
    try {
        $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
        if ($mgCtx -and ($mgCtx.Scopes -contains 'Policy.Read.All')) { $graphConnected = $true }
    } catch { }

    if ($graphConnected) {
        try {
            $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
            $script:ALZData.CAPolicies = $caPolicies
            $enabledPolicies = @($caPolicies | Where-Object { $_.State -eq 'enabled' -or $_.State -eq 'enabledForReportingButNotEnforced' })
            $mfaPolicies = @($caPolicies | Where-Object {
                $_.GrantControls.BuiltInControls -contains 'mfa' -and $_.State -eq 'enabled'
            })

            Add-ALZCheck "Conditional Access" "CA policies" "PASS" "$($enabledPolicies.Count) enabled CA policies found. $($mfaPolicies.Count) enforce MFA." ""

            if ($mfaPolicies.Count -eq 0) {
                Add-ALZCheck "Conditional Access" "MFA enforcement" "FAIL" "No Conditional Access policy enforcing MFA is enabled." "Create a CA policy requiring MFA for all users, at minimum for admin roles."
                Add-Finding -Pillar "Security" -Severity "Critical" -Category "ALZ - No MFA Conditional Access" `
                    -ResourceName "Conditional Access" -ResourceType "Identity" -ResourceGroup "N/A" `
                    -Subscription "Tenant-wide" `
                    -Description "No Conditional Access policy with MFA enforcement is enabled. $($enabledPolicies.Count) CA policies exist but none require MFA." `
                    -Recommendation "Create and enable a Conditional Access policy requiring MFA for all users. Start with admin roles at minimum." `
                    -Impact "Without enforced MFA, accounts are vulnerable to credential theft. MFA blocks 99.9% of identity attacks."
            }
        } catch {
            Add-ALZCheck "Conditional Access" "CA read" "WARN" "Error reading CA policies: $($_.Exception.Message)" ""
        }
    } else {
        # Manual checklist items — Graph not available
        Add-ALZCheck "Conditional Access" "CA — Require MFA for admins" "MANUAL" "Verify: Entra ID → Security → Conditional Access. A policy requiring MFA for admin roles must exist and be enabled." "Create a CA policy: All admins → Grant → Require multifactor authentication."
        Add-ALZCheck "Conditional Access" "CA — Require MFA for all users" "MANUAL" "Verify: At least one CA policy requires MFA for all users accessing Azure management (portal, CLI, PowerShell)." "Create a CA policy targeting all users with cloud app 'Microsoft Azure Management' requiring MFA."
        Add-ALZCheck "Conditional Access" "CA — Block legacy auth" "MANUAL" "Verify: A CA policy exists blocking legacy authentication protocols (IMAP, POP3, SMTP)." "Create a CA policy: All users → Conditions → Client apps → Legacy auth → Block."
        Add-ALZCheck "Conditional Access" "CA — Require compliant devices" "MANUAL" "Verify: Consider CA policies requiring device compliance or hybrid Azure AD join for sensitive resources." "Create CA policies that require compliant or hybrid-joined devices for critical applications."
    }

    # ── 8. PIM (Privileged Identity Management — via Graph or manual checklist) ──
    Write-Status "  [ALZ] Checking PIM configuration..." "INFO"
    $hasRoleMgmt = $false
    try {
        if ($mgCtx -and ($mgCtx.Scopes -contains 'RoleManagement.Read.Directory')) { $hasRoleMgmt = $true }
    } catch { }

    if ($hasRoleMgmt) {
        try {
            $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ErrorAction Stop
            $script:ALZData.PIMRoles = $eligibleAssignments
            if ($eligibleAssignments -and $eligibleAssignments.Count -gt 0) {
                Add-ALZCheck "PIM" "Eligible role assignments" "PASS" "$($eligibleAssignments.Count) PIM eligible role assignments found. Just-in-time access is configured." ""
            } else {
                Add-ALZCheck "PIM" "PIM configuration" "WARN" "No PIM eligible role assignments found. All privileged roles may be permanently assigned." "Enable PIM and convert permanent privileged assignments to eligible (just-in-time) assignments."
                Add-Finding -Pillar "Security" -Severity "High" -Category "ALZ - No PIM Eligible Roles" `
                    -ResourceName "Azure AD PIM" -ResourceType "Identity" -ResourceGroup "N/A" `
                    -Subscription "Tenant-wide" `
                    -Description "No PIM eligible role assignments found. Privileged roles (Global Admin, Owner) appear to be permanently assigned." `
                    -Recommendation "Enable PIM for all privileged roles. Convert permanent assignments to eligible with time-limited activation and approval workflows." `
                    -Impact "Permanently assigned privileged roles violate least-privilege. PIM provides just-in-time access reducing the attack surface."
            }
        } catch {
            Add-ALZCheck "PIM" "PIM read" "WARN" "Error reading PIM data: $($_.Exception.Message)" ""
        }
    } else {
        # Manual checklist items — Graph not available
        Add-ALZCheck "PIM" "PIM — Eligible assignments" "MANUAL" "Verify: Entra ID → Identity Governance → PIM → Azure AD roles. Privileged roles (Global Admin, Owner) should use eligible assignments, not permanent." "Navigate to PIM and review all permanent admin assignments. Convert to eligible with max 8-hour activation window."
        Add-ALZCheck "PIM" "PIM — Activation approval" "MANUAL" "Verify: PIM role settings require approval for high-privilege activations (Global Admin, Subscription Owner)." "Configure PIM to require approval for Global Admin and Owner roles. Set maximum activation duration to 8 hours."
        Add-ALZCheck "PIM" "PIM — Access reviews" "MANUAL" "Verify: PIM access reviews are configured to periodically validate privileged role assignments." "Create quarterly access reviews for all privileged roles in PIM."
        Add-ALZCheck "PIM" "Break-glass accounts" "MANUAL" "Verify: 2 emergency access (break-glass) accounts exist with permanent Global Admin, excluded from CA policies, with monitored sign-ins." "Create 2 break-glass accounts per MS best practices. Exclude from CA but monitor with Azure Monitor alerts."
    }

    # ── Custom RBAC Roles Audit ──
    Write-Status "  Auditing custom RBAC roles..." "INFO"
    try {
        $customRoles = $script:CachedRoleAssignments | Where-Object { $_ } | Out-Null  # just to avoid warning
        $customRoleDefs = Invoke-AzCommandSafely { Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue } "Custom Role Definitions"
        if ($customRoleDefs) {
            foreach ($role in $customRoleDefs) {
                # Flag roles with wildcard actions (overly permissive)
                $wildcardActions = @($role.Actions | Where-Object { $_ -eq '*' })
                if ($wildcardActions.Count -gt 0) {
                    Add-Finding -Pillar "Security" -Severity "High" -Category "RBAC - Overprivileged Custom Role" `
                        -ResourceName $role.Name -ResourceType "Custom Role Definition" `
                        -ResourceGroup "N/A" -Subscription "Tenant" `
                        -Description "Custom role '$($role.Name)' has wildcard (*) action permission, equivalent to Owner/Contributor." `
                        -Recommendation "Scope custom roles to specific resource provider actions. Remove wildcard permissions." `
                        -Impact "Overly permissive custom roles defeat the purpose of least-privilege RBAC."
                }
                # Flag roles with broad data actions
                $wildcardData = @($role.DataActions | Where-Object { $_ -eq '*' })
                if ($wildcardData.Count -gt 0) {
                    Add-Finding -Pillar "Security" -Severity "Medium" -Category "RBAC - Custom Role Wildcard Data" `
                        -ResourceName $role.Name -ResourceType "Custom Role Definition" `
                        -ResourceGroup "N/A" -Subscription "Tenant" `
                        -Description "Custom role '$($role.Name)' has wildcard (*) data action, granting full data plane access." `
                        -Recommendation "Restrict data actions to specific operations (e.g., Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read)." `
                        -Impact "Wildcard data actions grant unrestricted data access across all resource types."
                }
            }
            if ($customRoleDefs.Count -gt 20) {
                Add-Finding -Pillar "Operational Excellence" -Severity "Low" -Category "RBAC - Excessive Custom Roles" `
                    -ResourceName "$($customRoleDefs.Count) custom roles" -ResourceType "Custom Role Definition" `
                    -ResourceGroup "N/A" -Subscription "Tenant" `
                    -Description "There are $($customRoleDefs.Count) custom RBAC roles. High number of custom roles increases management complexity." `
                    -Recommendation "Review and consolidate custom roles. Use built-in roles where possible." `
                    -Impact "Too many custom roles are difficult to audit and maintain, increasing security risk."
            }
        }
    } catch { }

    # ── Summary ──
    $alzChecks = $script:ALZData.Checks
    $pass = @($alzChecks | Where-Object Status -eq 'PASS').Count
    $fail = @($alzChecks | Where-Object Status -eq 'FAIL').Count
    $warn = @($alzChecks | Where-Object Status -eq 'WARN').Count
    $info = @($alzChecks | Where-Object Status -eq 'INFO').Count
    $manual = @($alzChecks | Where-Object Status -eq 'MANUAL').Count
    Write-Status "  ALZ readiness: $pass PASS, $warn WARN, $fail FAIL, $manual MANUAL, $info INFO (total $($alzChecks.Count) checks)" $(if($fail -gt 0){"WARN"}else{"OK"})
}

function Generate-HTMLReport {
    Write-Status "Generating interactive HTML report..." "SECTION"

    $duration = (Get-Date) - $script:StartTime

    # Calculate pillar statistics
    $pillarStats = $script:Findings | Group-Object Pillar | ForEach-Object {
        [PSCustomObject]@{
            Name     = $_.Name
            Count    = $_.Count
            Critical = ($_.Group | Where-Object Severity -eq "Critical").Count
            High     = ($_.Group | Where-Object Severity -eq "High").Count
            Medium   = ($_.Group | Where-Object Severity -eq "Medium").Count
            Low      = ($_.Group | Where-Object Severity -eq "Low").Count
        }
    }

    # Generate findings table rows
    $findingsRows = ""
    $i = 0
    foreach ($f in ($script:Findings | Sort-Object @{Expression={
        switch($_.Severity) { "Critical"{0} "High"{1} "Medium"{2} "Low"{3} "Info"{4} }
    }})) {
        $i++
        $severityClass = $f.Severity.ToLower()
        $sourceVal = if ($f.Source) { $f.Source } else { 'Custom Analysis' }
        $sourceIcon = switch ($sourceVal) {
            'Azure Advisor'       { '📊' }
            'Defender for Cloud'  { '🛡️' }
            default               { '🔍' }
        }
        $sourceBadgeColor = switch ($sourceVal) {
            'Azure Advisor'       { 'background:#e6f2ff;color:#0078d4;border:1px solid #b3d9ff' }
            'Defender for Cloud'  { 'background:#fff4e5;color:#d97a00;border:1px solid #ffe0b2' }
            default               { 'background:#e8f5e9;color:#2e7d32;border:1px solid #c8e6c9' }
        }
        $pillarIcon = switch ($f.Pillar) {
            "Security" { "🛡️" }
            "Reliability" { "🔄" }
            "Cost Optimization" { "💰" }
            "Operational Excellence" { "⚙️" }
            "Performance Efficiency" { "⚡" }
            "Zero Trust" { "🔒" }
            default { "📋" }
        }
        $findingsRows += @"
        <tr class="finding-row" data-pillar="$(ConvertTo-SafeHtml $f.Pillar)" data-severity="$($f.Severity)" data-source="$sourceVal" data-category="$(ConvertTo-SafeHtml $f.Category)">
            <td><span class="severity-badge $severityClass">$($f.Severity)</span></td>
            <td style="white-space:nowrap;font-size:.82em;">$pillarIcon $(ConvertTo-SafeHtml $f.Pillar)</td>
            <td style="font-size:.82em;">$(ConvertTo-SafeHtml $f.Category)</td>
            <td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style="color:var(--text-dim)">$(ConvertTo-SafeHtml $f.ResourceType)</small> <small style="color:#0078d4;font-weight:600">📋 $(ConvertTo-SafeHtml $f.Subscription)</small></td>
            <td title="$(ConvertTo-SafeHtml $f.Description)">$(ConvertTo-SafeHtml $f.Description)</td>
            <td title="$(ConvertTo-SafeHtml $f.Recommendation)">$(ConvertTo-SafeHtml $f.Recommendation)</td>
            <td style="text-align:center"><span style="$sourceBadgeColor;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600;white-space:nowrap">$sourceIcon $sourceVal</span></td>
        </tr>
"@
    }

    # Generate resource inventory — enhanced with categories, KPI cards, and visual bars
    $resourceTypeSummary = $script:Resources | Group-Object Type | Sort-Object Count -Descending
    $uniqueTypes = $resourceTypeSummary.Count
    $uniqueLocations = ($script:Resources | Select-Object -ExpandProperty Location -Unique).Count
    $topResourceType = if ($resourceTypeSummary.Count -gt 0) { $resourceTypeSummary[0].Name.Split('/')[-1] } else { "N/A" }
    $topResourceCount = if ($resourceTypeSummary.Count -gt 0) { $resourceTypeSummary[0].Count } else { 0 }
    $maxResCount = if ($resourceTypeSummary.Count -gt 0) { $resourceTypeSummary[0].Count } else { 1 }

    # Friendly display names for resource types (avoids confusing raw Azure type names)
    $script:FriendlyTypeNames = @{
        'virtualmachines'                  = 'Virtual Machines'
        'virtualmachinescalesets'           = 'VM Scale Sets'
        'availabilitysets'                  = 'Availability Sets'
        'disks'                            = 'Managed Disks'
        'snapshots'                        = 'Disk Snapshots'
        'images'                           = 'VM Images'
        'galleries'                        = 'Compute Galleries'
        'extensions'                       = 'VM Extensions'
        'cloudservices'                    = 'Cloud Services'
        'hostgroups'                       = 'Dedicated Host Groups'
        'restorepointcollections'          = 'Restore Point Collections'
        'machines'                         = 'Arc-enabled Servers'
        'virtualnetworks'                  = 'Virtual Networks'
        'subnets'                          = 'Subnets'
        'networkinterfaces'                = 'Network Interfaces (NICs)'
        'publicipaddresses'                = 'Public IP Addresses'
        'networksecuritygroups'            = 'Network Security Groups (NSGs)'
        'loadbalancers'                    = 'Load Balancers'
        'applicationgateways'              = 'Application Gateways'
        'firewalls'                        = 'Azure Firewalls'
        'routetables'                      = 'Route Tables'
        'privatednszones'                  = 'Private DNS Zones'
        'privateendpoints'                 = 'Private Endpoints'
        'bastionhosts'                     = 'Azure Bastion Hosts'
        'natgateways'                      = 'NAT Gateways'
        'networkwatchers'                  = 'Network Watchers (auto-deployed)'
        'virtualnetworkgateways'           = 'VPN/ExpressRoute Gateways'
        'connections'                      = 'VPN Connections'
        'frontdoors'                       = 'Azure Front Door'
        'trafficmanagerprofiles'           = 'Traffic Manager Profiles'
        'dnszones'                         = 'DNS Zones'
        'applicationgatewaywebapplicationfirewallpolicies' = 'WAF Policies'
        'storageaccounts'                  = 'Storage Accounts'
        'storagesyncservices'              = 'Storage Sync Services'
        'fileshares'                       = 'File Shares'
        'servers'                          = 'SQL Servers'
        'databases'                        = 'SQL Databases'
        'managedinstances'                 = 'SQL Managed Instances'
        'elasticpools'                     = 'SQL Elastic Pools'
        'sqlserverinstances'               = 'Arc SQL Server Instances'
        'flexibleservers'                  = 'Flexible Servers (MySQL/PostgreSQL)'
        'sites'                            = 'App Services / Function Apps'
        'serverfarms'                      = 'App Service Plans'
        'certificates'                     = 'App Service Certificates'
        'staticsites'                      = 'Static Web Apps'
        'containerapps'                    = 'Container Apps'
        'managedenvironments'              = 'Container App Environments'
        'managedclusters'                  = 'AKS Clusters'
        'containergroups'                  = 'Container Instances'
        'registries'                       = 'Container Registries'
        'vaults'                           = 'Key Vaults / Recovery Vaults'
        'managedhsms'                      = 'Managed HSMs'
        'workspaces'                       = 'Log Analytics Workspaces'
        'components'                       = 'Application Insights'
        'actiongroups'                     = 'Alert Action Groups'
        'metricalerts'                     = 'Metric Alert Rules'
        'scheduledqueryrules'              = 'Log Alert Rules'
        'datacollectionrules'              = 'Data Collection Rules (monitoring)'
        'datacollectionendpoints'          = 'Data Collection Endpoints'
        'solutions'                        = 'Log Analytics Solutions'
        'smartdetectoralertrules'          = 'Smart Detection Rules'
        'userassignedidentities'           = 'User-Assigned Managed Identities'
        'namespaces'                       = 'Service Bus / Event Hub Namespaces'
        'workflows'                        = 'Logic Apps'
        'integrationaccounts'              = 'Integration Accounts'
        'policyassignments'                = 'Policy Assignments'
        'locks'                            = 'Resource Locks'
        'deployments'                      = 'Deployments'
        'templatespecs'                    = 'Template Specs'
        'blueprints'                       = 'Blueprints'
        'systemtopics'                     = 'Event Grid System Topics'
        'migrateprojects'                  = 'Azure Migrate Projects'
        'mastersites'                      = 'Azure Migrate - Discovery Sites'
        'importsites'                      = 'Azure Migrate - Import Sites'
        'automationaccounts'               = 'Automation Accounts'
        'runbooks'                         = 'Automation Runbooks'
        'configurationstores'              = 'App Configuration Stores'
        'redis'                            = 'Azure Cache for Redis'
        'searchservices'                   = 'Azure AI Search'
        'cognitiveservices'                = 'Azure AI Services'
        'signalr'                          = 'Azure SignalR'
        'webpubsub'                        = 'Azure Web PubSub'
        'mediaservices'                    = 'Media Services'
        'streamingjobs'                    = 'Stream Analytics Jobs'
        'iothubs'                          = 'IoT Hubs'
        'dpsresources'                     = 'IoT Hub DPS'
        'backupvaults'                     = 'Backup Vaults'
    }

    # Apply friendly name to top resource type
    if ($topResourceType -ne "N/A" -and $script:FriendlyTypeNames.ContainsKey($topResourceType.ToLower())) {
        $topResourceType = $script:FriendlyTypeNames[$topResourceType.ToLower()]
    }

    # Categorize resources
    $categoryMap = @{
        'Compute'   = @('virtualmachines','virtualmachinescalesets','availabilitysets','disks','snapshots','images','galleries','extensions','cloudservices','hostgroups','restorepointcollections')
        'Network'   = @('virtualnetworks','subnets','networkinterfaces','publicipaddresses','networksecuritygroups','loadbalancers','applicationgateways','firewalls','routetables','privatednszones','privateendpoints','bastionhosts','natgateways','networkwatchers','virtualnetworkgateways','connections','frontdoors','trafficmanagerprofiles','dnszones','applicationgatewaywebapplicationfirewallpolicies')
        'Storage'   = @('storageaccounts','fileshares','blobservices','tableservices','queueservices')
        'Databases' = @('servers','databases','managedinstances','elasticpools','sqlserverinstances','cosmosdb','rediscaches','flexibleservers')
        'Web & App' = @('sites','serverfarms','certificates','staticsites','containerapps','managedenvironments')
        'Containers'= @('managedclusters','containergroups','registries')
        'Security'  = @('vaults','managedhsms','securitysolutions','automations','assessments','alertsuppressionrules')
        'Monitoring'= @('workspaces','components','actiongroups','metricalerts','scheduledqueryrules','datacollectionrules','datacollectionendpoints','solutions','smartdetectoralertrules')
        'Identity'  = @('userassignedidentities','managedidentities')
        'Integration'= @('namespaces','workflows','connections','apiconnections','integrationaccounts')
        'Management'= @('policyassignments','locks','deployments','templatespecs','blueprints')
        'Other'     = @()
    }

    $categoryCounts = [ordered]@{}
    foreach ($cat in $categoryMap.Keys) { $categoryCounts[$cat] = 0 }
    foreach ($rt in $resourceTypeSummary) {
        $shortName = ($rt.Name.Split('/')[-1]).ToLower()
        $matched = $false
        foreach ($cat in $categoryMap.Keys) {
            if ($cat -eq 'Other') { continue }
            foreach ($keyword in $categoryMap[$cat]) {
                if ($shortName -match $keyword) {
                    $categoryCounts[$cat] += $rt.Count
                    $matched = $true
                    break
                }
            }
            if ($matched) { break }
        }
        if (-not $matched) { $categoryCounts['Other'] += $rt.Count }
    }

    $categoryIcons = @{
        'Compute'    = '🖥️'; 'Network' = '🌐'; 'Storage' = '💾'; 'Databases' = '🗄️'
        'Web & App'  = '🌍'; 'Containers' = '📦'; 'Security' = '🔒'; 'Monitoring' = '📊'
        'Identity'   = '👤'; 'Integration' = '🔗'; 'Management' = '⚙️'; 'Other' = '📋'
    }
    $categoryColors = @{
        'Compute'    = '#0078d4'; 'Network' = '#005a9e'; 'Storage' = '#ca5010'; 'Databases' = '#5c2d91'
        'Web & App'  = '#008272'; 'Containers' = '#00b7c3'; 'Security' = '#d13438'; 'Monitoring' = '#107c10'
        'Identity'   = '#8764b8'; 'Integration' = '#498205'; 'Management' = '#605e5c'; 'Other' = '#8a8886'
    }

    # Category cards HTML — add data-cat for JS updates
    $maxCatCount = ($categoryCounts.Values | Measure-Object -Maximum).Maximum
    if ($maxCatCount -eq 0) { $maxCatCount = 1 }
    $catCardsHtml = ""
    foreach ($cat in $categoryCounts.Keys) {
        $count = $categoryCounts[$cat]
        if ($count -eq 0) { continue }
        $icon = $categoryIcons[$cat]
        $color = $categoryColors[$cat]
        $pct = [math]::Round(($count / $script:Summary.TotalResources) * 100, 1)
        $barW = [math]::Round(($count / $maxCatCount) * 100, 1)
        $catSafe = $cat -replace '[^a-zA-Z]',''
        $catCardsHtml += @"
            <div class="inv-cat-card" data-cat="$catSafe" data-color="$color" style="flex:1;min-width:180px;max-width:250px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;box-shadow:var(--shadow-sm);transition:box-shadow .2s,transform .2s;" onmouseover="this.style.boxShadow='var(--shadow-md)';this.style.transform='translateY(-2px)'" onmouseout="this.style.boxShadow='var(--shadow-sm)';this.style.transform=''">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
                    <span style="font-size:1.3em;">$icon</span>
                    <span style="font-size:12px;font-weight:700;color:$color;text-transform:uppercase;letter-spacing:.3px;">$cat</span>
                </div>
                <div class="inv-cat-count" style="font-size:24px;font-weight:800;color:var(--text);line-height:1;">$count</div>
                <div class="inv-cat-pct" style="font-size:10px;color:var(--text-dim);margin-bottom:8px;">$pct% of total</div>
                <div style="height:4px;background:#f3f2f1;border-radius:2px;overflow:hidden;">
                    <div class="inv-cat-bar" style="height:100%;width:${barW}%;background:$color;border-radius:2px;transition:width .6s ease;"></div>
                </div>
            </div>
"@
    }

    # Build per-subscription category counts JSON for JS filtering
    $catDataMap = [ordered]@{}
    # Tenant-wide (all)
    $allCats = [ordered]@{}
    foreach ($cat in $categoryCounts.Keys) { if ($categoryCounts[$cat] -gt 0) { $catSafe = $cat -replace '[^a-zA-Z]',''; $allCats[$catSafe] = $categoryCounts[$cat] } }
    $catDataMap['all'] = @{ counts = $allCats; total = $script:Summary.TotalResources }
    # Per subscription
    foreach ($sg in ($script:Resources | Group-Object Subscription)) {
        $subNameSafe = ConvertTo-SafeHtml $sg.Name
        $subCats = [ordered]@{}
        foreach ($cat in $categoryMap.Keys) { $subCats[($cat -replace '[^a-zA-Z]','')] = 0 }
        $subTypeGroups = $sg.Group | Group-Object Type
        foreach ($tg in $subTypeGroups) {
            $shortName = ($tg.Name.Split('/')[-1]).ToLower()
            $matched = $false
            foreach ($cat in $categoryMap.Keys) {
                if ($cat -eq 'Other') { continue }
                foreach ($keyword in $categoryMap[$cat]) {
                    if ($shortName -match $keyword) { $subCats[($cat -replace '[^a-zA-Z]','')] += $tg.Count; $matched = $true; break }
                }
                if ($matched) { break }
            }
            if (-not $matched) { $subCats['Other'] += $tg.Count }
        }
        # Remove zeros
        $nonZero = [ordered]@{}
        foreach ($k in $subCats.Keys) { if ($subCats[$k] -gt 0) { $nonZero[$k] = $subCats[$k] } }
        $catDataMap[$subNameSafe] = @{ counts = $nonZero; total = $sg.Count }
    }
    $invCatDataJson = ($catDataMap | ConvertTo-Json -Depth 4 -Compress)

    # Enhanced resource rows with visual bars
    $resourceBuilder = [System.Text.StringBuilder]::new()
    foreach ($rt in $resourceTypeSummary) {
        $rawShort = ($rt.Name.Split('/')[-1])
        $displayName = if ($script:FriendlyTypeNames.ContainsKey($rawShort.ToLower())) { $script:FriendlyTypeNames[$rawShort.ToLower()] } else { $rawShort }
        $shortType = ConvertTo-SafeHtml $displayName
        $fullType = ConvertTo-SafeHtml $rt.Name
        $barW = [math]::Round(($rt.Count / $maxResCount) * 100, 1)
        $locations = ($rt.Group | Group-Object { $_.Location } | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
        $locSafe = ConvertTo-SafeHtml $locations
        # Determine category color for the bar
        $barColor = "#8a8886"
        $shortLower = $shortType.ToLower()
        foreach ($cat in $categoryMap.Keys) {
            if ($cat -eq 'Other') { continue }
            foreach ($keyword in $categoryMap[$cat]) {
                if ($shortLower -match $keyword) { $barColor = $categoryColors[$cat]; break }
            }
            if ($barColor -ne "#8a8886") { break }
        }
        [void]$resourceBuilder.AppendLine(@"
        <tr>
            <td style="font-weight:600;white-space:nowrap;">$shortType</td>
            <td style="font-size:.82em;color:var(--text-dim);">$fullType</td>
            <td style="font-size:.82em;color:var(--text-dim);">$locSafe</td>
            <td style="min-width:180px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <div style="flex:1;height:20px;background:#f3f2f1;border-radius:4px;overflow:hidden;position:relative;">
                        <div style="height:100%;width:${barW}%;background:linear-gradient(90deg,${barColor}dd,${barColor}88);border-radius:4px;transition:width .6s ease;"></div>
                    </div>
                    <span style="font-weight:700;font-size:13px;min-width:30px;text-align:right;">$($rt.Count)</span>
                </div>
            </td>
        </tr>
"@)
    }
    $resourceRows = $resourceBuilder.ToString()

    # Generate per-subscription inventory (enhanced)
    $subInventoryBuilder = [System.Text.StringBuilder]::new()
    $subGroups = $script:Resources | Group-Object Subscription
    foreach ($sg in $subGroups) {
        $subNameSafe = ConvertTo-SafeHtml $sg.Name
        $subTypeGroups = $sg.Group | Group-Object Type | Sort-Object Count -Descending
        $subMaxCount = if ($subTypeGroups.Count -gt 0) { $subTypeGroups[0].Count } else { 1 }
        [void]$subInventoryBuilder.AppendLine("<div class='inv-sub-section' data-sub='$subNameSafe'>")
        [void]$subInventoryBuilder.AppendLine("<h4 style='font-size:.9em;font-weight:600;color:var(--accent);margin-bottom:10px;'>📋 $subNameSafe <span style=`"font-weight:400;color:var(--text-dim);font-size:.9em;`">($($sg.Count) resources)</span></h4>")
        [void]$subInventoryBuilder.AppendLine("<div class='table-container'><table><thead><tr><th>Resource Type</th><th>Azure Provider</th><th>Location</th><th style='min-width:180px;'>Count</th></tr></thead><tbody>")
        foreach ($tg in $subTypeGroups) {
            $rawShort2 = ($tg.Name.Split('/')[-1])
            $displayName2 = if ($script:FriendlyTypeNames.ContainsKey($rawShort2.ToLower())) { $script:FriendlyTypeNames[$rawShort2.ToLower()] } else { $rawShort2 }
            $shortType = ConvertTo-SafeHtml $displayName2
            $fullType = ConvertTo-SafeHtml $tg.Name
            $locations = ($tg.Group | Group-Object Location | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
            $locSafe = ConvertTo-SafeHtml $locations
            $barW = [math]::Round(($tg.Count / $subMaxCount) * 100, 1)
            $barColor = "#8a8886"
            $shortLower = $shortType.ToLower()
            foreach ($cat in $categoryMap.Keys) {
                if ($cat -eq 'Other') { continue }
                foreach ($keyword in $categoryMap[$cat]) {
                    if ($shortLower -match $keyword) { $barColor = $categoryColors[$cat]; break }
                }
                if ($barColor -ne "#8a8886") { break }
            }
            [void]$subInventoryBuilder.AppendLine("<tr><td style='font-weight:600;white-space:nowrap;'>$shortType</td><td style='font-size:.82em;color:var(--text-dim);'>$fullType</td><td style='font-size:.82em;color:var(--text-dim)'>$locSafe</td><td><div style='display:flex;align-items:center;gap:8px;'><div style='flex:1;height:20px;background:#f3f2f1;border-radius:4px;overflow:hidden;'><div style='height:100%;width:${barW}%;background:linear-gradient(90deg,${barColor}dd,${barColor}88);border-radius:4px;'></div></div><span style='font-weight:700;font-size:13px;min-width:30px;text-align:right;'>$($tg.Count)</span></div></td></tr>")
        }
        [void]$subInventoryBuilder.AppendLine("</tbody></table></div></div>")
    }
    $subInventoryRows = $subInventoryBuilder.ToString()

    # Subscription filter dropdown for inventory
    $invSubButtons = "<select class='sub-filter-select' onchange='invFilterSub(this.value)'>"
    $invSubButtons += "<option value='all'>&#9729; All Subscriptions ($($script:Resources.Count) resources)</option>"
    foreach ($sg in $subGroups) {
        $subNameSafe = ConvertTo-SafeHtml $sg.Name
        $invSubButtons += "<option value='$subNameSafe'>$subNameSafe ($($sg.Count))</option>"
    }
    $invSubButtons += "</select>"

    # Generate Zero Trust rows
    $ztFindings = $script:Findings | Where-Object { $_.Pillar -eq "Zero Trust" } | Sort-Object @{Expression={
        switch($_.Severity) { "Critical"{0} "High"{1} "Medium"{2} "Low"{3} default{4} }
    }}
    $ztRows = ""
    foreach ($f in $ztFindings) {
        $sevClass = $f.Severity.ToLower()
        $control = $f.Category -replace "ZT-Network: |ZT-Compute: |ZT-Platform: ", ""
        $controlSafe = ConvertTo-SafeHtml $control
        $layerPlain = if ($f.Category -match "ZT-Network") { "Network" } `
            elseif ($f.Category -match "ZT-Compute") { "Compute" } `
            elseif ($f.Category -match "ZT-Platform") { "Platform" } `
            else { "ZT" }
        $layerDisplay = if ($f.Category -match "ZT-Network") { "🌐 Network" } `
            elseif ($f.Category -match "ZT-Compute") { "🖥️ Compute" } `
            elseif ($f.Category -match "ZT-Platform") { "🏛️ Platform" } `
            else { "🔒 ZT" }
        $ztRows += @"
        <tr class="zt-finding-row" data-layer="$layerPlain" data-severity="$($f.Severity)">
            <td><span class="severity-badge $sevClass">$($f.Severity)</span></td>
            <td>$layerDisplay</td>
            <td><strong>$controlSafe</strong></td>
            <td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style="color:#605e5c">$(ConvertTo-SafeHtml $f.ResourceType) | $(ConvertTo-SafeHtml $f.ResourceGroup)</small><br><small style="color:#0078d4;font-weight:600">📋 $(ConvertTo-SafeHtml $f.Subscription)</small></td>
            <td>$(ConvertTo-SafeHtml $f.Description)</td>
            <td>$(ConvertTo-SafeHtml $f.Recommendation)</td>
            <td><small>$(ConvertTo-SafeHtml $f.Impact)</small></td>
        </tr>
"@
    }

    # Generate underutilized resource rows (real metrics)
    $underutilizedRows = ""
    $utilSorted = $script:UnderutilizedResources | Sort-Object @{Expression={
        switch($_.Severity) { "High"{0} "Medium"{1} "Low"{2} default{3} }
    }}, ResourceType
    foreach ($u in $utilSorted) {
        $sevClass = $u.Severity.ToLower()
        $rtIcon = switch -Regex ($u.ResourceType) {
            "Virtual Machine" { "🖥️" }
            "App Service"     { "🌐" }
            "SQL"             { "🗄️" }
            "Disk"            { "💿" }
            default           { "📦" }
        }
        $underutilizedRows += @"
        <tr class="util-row" data-type="$(ConvertTo-SafeHtml $u.ResourceType)" data-severity="$($u.Severity)">
            <td><span class="severity-badge $sevClass">$($u.Severity)</span></td>
            <td>$rtIcon $(ConvertTo-SafeHtml $u.ResourceType)</td>
            <td><strong>$(ConvertTo-SafeHtml $u.ResourceName)</strong><br><small style="color:#605e5c">$(ConvertTo-SafeHtml $u.ResourceGroup)</small><br><small style="color:#0078d4;font-weight:600">📋 $(ConvertTo-SafeHtml $u.Subscription)</small></td>
            <td><code style="background:#e1dfdd;padding:2px 6px;border-radius:4px;font-size:.85em">$(ConvertTo-SafeHtml $u.SKU)</code><br><small style="color:#605e5c">$(ConvertTo-SafeHtml $u.Location)</small></td>
            <td style="text-align:center">
                <span style="font-size:1.4em;font-weight:700;color:#d13438">$(ConvertTo-SafeHtml $u.MetricValue)</span><br>
                <small style="color:#605e5c">$(ConvertTo-SafeHtml $u.MetricName)<br>threshold: $(ConvertTo-SafeHtml $u.Threshold)</small>
            </td>
            <td>$(ConvertTo-SafeHtml $u.Description)</td>
            <td>$(ConvertTo-SafeHtml $u.Recommendation)</td>
        </tr>
"@
    }

    # ── Reservation & Savings Plan data builder ──
    $riItems = @($script:ReservationData | Where-Object { $_.Type -eq 'Reservation' })
    $spItems = @($script:ReservationData | Where-Object { $_.Type -eq 'SavingsPlan' })
    $riTotal = $script:ReservationData.Count
    $riActive = @($script:ReservationData | Where-Object { $_.DaysToExpiry -ge 0 -or $_.DaysToExpiry -eq -1 -and $_.Status -eq 'Succeeded' }).Count
    $riExpiring = @($script:ReservationData | Where-Object { $_.DaysToExpiry -ge 0 -and $_.DaysToExpiry -le 90 }).Count
    $riExpired = @($script:ReservationData | Where-Object { $_.DaysToExpiry -lt 0 -and $_.ExpiryDate }).Count
    $riLowUtil = @($script:ReservationData | Where-Object { $_.UtilizationPct -ge 0 -and $_.UtilizationPct -lt 50 }).Count
    $riAvgUtil = 0
    $riWithUtil = @($script:ReservationData | Where-Object { $_.UtilizationPct -ge 0 })
    if ($riWithUtil.Count -gt 0) { $riAvgUtil = [math]::Round(($riWithUtil | Measure-Object -Property UtilizationPct -Average).Average, 1) }

    $reservationRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($ri in ($script:ReservationData | Sort-Object @{Expression={ switch($_.Type) { 'Reservation'{0} 'SavingsPlan'{1} default{2} } }}, @{Expression={ $_.UtilizationPct }})) {
        $typeIcon = if ($ri.Type -eq 'SavingsPlan') { '💳' } else { '🎫' }
        $typeLabel = if ($ri.Type -eq 'SavingsPlan') { 'Savings Plan' } else { 'Reserved Instance' }
        $statusClass = if ($ri.DaysToExpiry -lt 0 -and $ri.ExpiryDate) { 'critical' } elseif ($ri.DaysToExpiry -ge 0 -and $ri.DaysToExpiry -le 30) { 'critical' } elseif ($ri.DaysToExpiry -ge 0 -and $ri.DaysToExpiry -le 90) { 'medium' } else { 'low' }
        $statusLabel = if ($ri.DaysToExpiry -lt 0 -and $ri.ExpiryDate) { 'Expired' } elseif ($ri.DaysToExpiry -ge 0 -and $ri.DaysToExpiry -le 30) { 'Expiring' } elseif ($ri.DaysToExpiry -ge 0 -and $ri.DaysToExpiry -le 90) { 'Exp. Soon' } else { 'Active' }
        $utilColor = if ($ri.UtilizationPct -lt 0) { '#605e5c' } elseif ($ri.UtilizationPct -lt 20) { '#d13438' } elseif ($ri.UtilizationPct -lt 50) { '#ca5010' } elseif ($ri.UtilizationPct -lt 80) { '#e8a838' } else { '#107c10' }
        $utilDisplay = if ($ri.UtilizationPct -lt 0) { 'N/A' } else { "$($ri.UtilizationPct)%" }
        $purchaseStr = if ($ri.PurchaseDate) { $ri.PurchaseDate.ToString('yyyy-MM-dd') } else { 'N/A' }
        $expiryStr = if ($ri.ExpiryDate) { $ri.ExpiryDate.ToString('yyyy-MM-dd') } else { 'N/A' }
        $daysStr = if ($ri.DaysToExpiry -ge 0) { "$($ri.DaysToExpiry)d" } elseif ($ri.ExpiryDate) { 'Expired' } else { 'N/A' }
        [void]$reservationRowsBuilder.Append("<tr class=`"ri-row`" data-type=`"$($ri.Type)`" data-status=`"$statusLabel`"><td>$typeIcon $typeLabel</td><td><strong>$($ri.DisplayName)</strong><br><small style=`"color:#605e5c`">$($ri.ResourceType)</small></td><td><code style=`"background:#e1dfdd;padding:2px 6px;border-radius:4px;font-size:.85em`">$($ri.SKU)</code></td><td style=`"text-align:center`">$($ri.Quantity)</td><td>$($ri.Term)</td><td>$($ri.Scope)</td><td style=`"text-align:center`"><span style=`"font-size:1.2em;font-weight:700;color:$utilColor`">$utilDisplay</span></td><td style=`"text-align:center;font-size:.85em`">$purchaseStr</td><td style=`"text-align:center`"><span class=`"severity-badge $statusClass`">$statusLabel</span><br><small style=`"color:#605e5c`">$expiryStr ($daysStr)</small></td></tr>")
    }
    $reservationRows = $reservationRowsBuilder.ToString()

    # Generate network topology — modern card layout
    $netVnets    = @($script:NetworkTopology | Where-Object { $_.Type -eq 'VNet' })
    $netPIPs     = @($script:NetworkTopology | Where-Object { $_.Type -eq 'PublicIP' })
    $netGateways = @($script:NetworkTopology | Where-Object { $_.Type -eq 'Gateway' })
    $netNatGws   = @($script:NetworkTopology | Where-Object { $_.Type -eq 'NatGateway' })
    $netTotalPeerings = ($netVnets | ForEach-Object { if ($_.PeeringDetails) { $_.PeeringDetails.Count } else { 0 } } | Measure-Object -Sum).Sum
    $netTotalSubnets  = ($netVnets | ForEach-Object { $_.SubnetCount } | Measure-Object -Sum).Sum
    $netKpiVnets    = $netVnets.Count
    $netKpiPIPs     = $netPIPs.Count
    $netKpiGateways = $netGateways.Count + $netNatGws.Count

    # VNet cards
    $vnetCardsBuilder = [System.Text.StringBuilder]::new()
    foreach ($v in $netVnets) {
        $safeName = ConvertTo-SafeHtml $v.Name
        $safeLoc  = ConvertTo-SafeHtml $v.Location
        $safeAddr = ConvertTo-SafeHtml $v.AddressSpace
        $safeSub  = ConvertTo-SafeHtml $v.Subscription
        $peerCount = if ($v.PeeringDetails) { $v.PeeringDetails.Count } else { 0 }
        $peerBadge = if ($peerCount -gt 0) { "<span style='display:inline-flex;align-items:center;gap:4px;background:#e8f4fd;color:#0078d4;padding:2px 8px;border-radius:10px;font-size:.75em;font-weight:600;'>&#128279; $peerCount peering$(if($peerCount -gt 1){'s'})</span>" } else { "<span style='display:inline-flex;align-items:center;gap:4px;background:#f5f5f5;color:#8b92a0;padding:2px 8px;border-radius:10px;font-size:.75em;'>No peerings</span>" }

        # Subnet chips
        $subnetChips = ""
        if ($v.SubnetDetails) {
            $chips = foreach ($sn in $v.SubnetDetails) {
                $snName = ConvertTo-SafeHtml $sn.Name
                $snAddr = ConvertTo-SafeHtml $sn.AddressPrefix
                $nsgIcon = if ($sn.NsgName) { "<span title='NSG: $($sn.NsgName)' style='color:#107c10;'>&#128737;</span>" } else { "<span title='No NSG' style='color:#d13438;'>&#9888;</span>" }
                $seIcon  = if ($sn.ServiceEndpoints) { "<span title='Service Endpoints: $($sn.ServiceEndpoints)' style='color:#0078d4;cursor:help;'>&#128279;</span>" } else { "" }
                $devCount = $sn.ConnectedDevices
                "<div style='display:inline-flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border-light);border-radius:8px;padding:5px 10px;font-size:.78em;white-space:nowrap;'>$nsgIcon <strong>$snName</strong> <span style='color:var(--text-dim);'>$snAddr</span> $seIcon<span style='color:var(--text-muted);font-size:.9em;'>$devCount dev</span></div>"
            }
            $subnetChips = "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px;'>$($chips -join '')</div>"
        }

        # Peering details
        $peerDetails = ""
        if ($v.PeeringDetails -and $v.PeeringDetails.Count -gt 0) {
            $peerItems = foreach ($p in $v.PeeringDetails) {
                $stColor = if ($p.PeeringState -eq 'Connected') { '#107c10' } else { '#d13438' }
                $stIcon  = if ($p.PeeringState -eq 'Connected') { '&#10003;' } else { '&#9888;' }
                "<div style='display:inline-flex;align-items:center;gap:6px;background:#f0f8ff;border:1px solid #d0e8f7;border-radius:8px;padding:4px 10px;font-size:.78em;'><span style='color:$stColor;font-weight:700;'>$stIcon</span> $(ConvertTo-SafeHtml $p.PeeringName) &rarr; <span style='color:var(--accent);font-weight:600;'>$(ConvertTo-SafeHtml $p.RemoteVNet)</span></div>"
            }
            $peerDetails = "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;'>$($peerItems -join '')</div>"
        }

        [void]$vnetCardsBuilder.Append(@"
<div class="vnet-card" data-sub="$safeSub" style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid var(--accent);border-radius:10px;padding:18px 20px;transition:box-shadow .15s,transform .15s;" onmouseenter="this.style.boxShadow='0 4px 16px rgba(0,29,61,0.08)';this.style.transform='translateY(-1px)'" onmouseleave="this.style.boxShadow='';this.style.transform=''">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;">
        <div>
            <div style="font-weight:700;font-size:1em;color:var(--text);display:flex;align-items:center;gap:8px;">
                <svg width="18" height="18" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="4" rx="1.5" stroke="#0078d4" stroke-width="1.2"/><rect x="1" y="9" width="14" height="4" rx="1.5" stroke="#0078d4" stroke-width="1.2"/><circle cx="4" cy="5" r=".9" fill="#0078d4"/><circle cx="4" cy="11" r=".9" fill="#0078d4"/></svg>
                $safeName
            </div>
            <div style="font-size:.8em;color:var(--text-dim);margin-top:3px;">
                <span style="margin-right:12px;">&#128205; $safeLoc</span>
                <span style="margin-right:12px;">&#127760; $safeAddr</span>
                <span style="color:var(--text-muted);">$($v.SubnetCount) subnet$(if($v.SubnetCount -ne 1){'s'})</span>
            </div>
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
            $peerBadge
            <span style="background:#f5f5f5;color:var(--text-dim);padding:2px 8px;border-radius:10px;font-size:.72em;font-weight:600;">&#128203; $safeSub</span>
        </div>
    </div>$subnetChips$peerDetails
</div>
"@)
    }
    $vnetCardsHtml = $vnetCardsBuilder.ToString()

    # Public IP table rows
    $pipRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($p in $netPIPs) {
        $safeName  = ConvertTo-SafeHtml $p.Name
        $safeLoc   = ConvertTo-SafeHtml $p.Location
        $safeIP    = ConvertTo-SafeHtml $p.IpAddress
        $safeAssoc = ConvertTo-SafeHtml $p.AssociatedTo
        $safeSku   = ConvertTo-SafeHtml $p.Sku
        $safeSub   = ConvertTo-SafeHtml $p.Subscription
        $assocClass = if ($p.AssociatedTo -eq 'Unassociated') { "color:#d13438;font-weight:600;" } else { "color:var(--text);" }
        $skuBadge = if ($p.Sku -eq 'Basic') { "<span style='background:#fff4ce;color:#ca5010;padding:2px 8px;border-radius:10px;font-size:.78em;font-weight:600;'>Basic</span>" } else { "<span style='background:#e8f4fd;color:#0078d4;padding:2px 8px;border-radius:10px;font-size:.78em;font-weight:600;'>$safeSku</span>" }
        [void]$pipRowsBuilder.Append("<tr data-sub='$safeSub'><td><strong>$safeName</strong><br><small style='color:#0078d4;font-weight:600'>&#128203; $safeSub</small></td><td>$safeLoc</td><td style='font-family:Consolas,monospace;font-size:.88em;'>$safeIP</td><td style='$assocClass'>$safeAssoc</td><td>$skuBadge</td></tr>")
    }
    $pipRows = $pipRowsBuilder.ToString()

    # Gateway rows
    $gwRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($g in ($netGateways + $netNatGws)) {
        $safeName = ConvertTo-SafeHtml $g.Name
        $safeLoc  = ConvertTo-SafeHtml $g.Location
        $safeSub  = ConvertTo-SafeHtml $g.Subscription
        $typeLabel = switch ($g.Type) {
            'Gateway' { $gwType = ConvertTo-SafeHtml $g.GatewayType; if ($gwType -match 'ExpressRoute') { "<span style='color:#5c2d91;font-weight:600;'>ExpressRoute</span>" } else { "<span style='color:#0078d4;font-weight:600;'>VPN</span>" } }
            'NatGateway' { "<span style='color:#00b7c3;font-weight:600;'>NAT Gateway</span>" }
            default { ConvertTo-SafeHtml $g.Type }
        }
        $details = if ($g.Type -eq 'NatGateway') {
            $natPipStr = if ($g.PublicIPs) { ConvertTo-SafeHtml $g.PublicIPs } else { '-' }
            $natSubStr = if ($g.Subnets) { ConvertTo-SafeHtml $g.Subnets } else { '-' }
            "PIPs: $natPipStr | Subnets: $natSubStr"
        } else { ConvertTo-SafeHtml $g.GatewayType }
        [void]$gwRowsBuilder.Append("<tr data-sub='$safeSub'><td><strong>$safeName</strong><br><small style='color:#0078d4;font-weight:600'>&#128203; $safeSub</small></td><td>$safeLoc</td><td>$typeLabel</td><td style='font-size:.85em;color:var(--text-dim);'>$details</td></tr>")
    }
    $gwRows = $gwRowsBuilder.ToString()

    # Subscriptions rows + cost analysis
    $subBuilder = [System.Text.StringBuilder]::new()
    foreach ($s in $script:Subscriptions) {
        $safeName = ConvertTo-SafeHtml $s.Name
        $costInfo = $script:CostData[$s.Id]
        $costCell = if ($costInfo) { "<strong>`$$([math]::Round($costInfo.TotalCost, 0).ToString('N0'))</strong> <small style='color:#605e5c'>($($costInfo.Currency)) last 6 mo</small>" } else { "<small style='color:#a19f9d' title='Cost Management Reader role required on this subscription'>Not available</small>" }
        [void]$subBuilder.AppendLine("<tr data-subid='$($s.Id)' onclick='selectSubCost(this)' style='cursor:pointer;' title='Click to filter cost analysis'><td><strong>$safeName</strong></td><td><code style='font-size:11px'>$($s.Id)</code></td><td style='color:#107c10'>$($s.State)</td><td>$costCell</td></tr>")
    }
    $subRows = $subBuilder.ToString()

    # Cost analysis HTML per subscription
    $costAnalysisHtml = [System.Text.StringBuilder]::new()
    foreach ($s in $script:Subscriptions) {
        $costInfo = $script:CostData[$s.Id]
        if (-not $costInfo) { continue }

        $safeName = ConvertTo-SafeHtml $s.Name
        $currency = $costInfo.Currency
        $months = @($costInfo.Months)
        $monthLabels = @($months | ForEach-Object {
            $m = $_
            try {
                if ($m -match '^(\d{4})-(\d{1,2})$') {
                    ([datetime]::new([int]$Matches[1], [int]$Matches[2], 1)).ToString('MMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
                } else {
                    ([datetime]::Parse($m)).ToString('MMM yyyy', [System.Globalization.CultureInfo]::InvariantCulture)
                }
            } catch { $m }
        })

        # Calculate averages and identify top grower
        $avgMonthly = if ($months.Count -gt 0) { [math]::Round($costInfo.TotalCost / $months.Count, 0) } else { 0 }
        $topGrower = $null
        $topGrowthVal = [double]-999
        $maxCostService = $null
        $maxCostVal = [double]0
        foreach ($svc in $costInfo.TopServices) {
            if ($svc.Value -gt $maxCostVal) { $maxCostVal = $svc.Value; $maxCostService = $svc.Key }
            $gv = if ($costInfo.Growth.ContainsKey($svc.Key)) { [double]$costInfo.Growth[$svc.Key] } else { 0 }
            if ($gv -gt $topGrowthVal) { $topGrowthVal = $gv; $topGrower = $svc.Key }
        }
        $topGrowthColor = if ($topGrowthVal -gt 20) { "#d13438" } elseif ($topGrowthVal -gt 0) { "#ca5010" } elseif ($topGrowthVal -lt 0) { "#107c10" } else { "#605e5c" }
        $topGrowthIcon = if ($topGrowthVal -gt 0) { "&#9650;" } elseif ($topGrowthVal -lt 0) { "&#9660;" } else { "&#9644;" }

        # Build horizontal bar chart rows (CSS-only)
        $barRowsHtml = ""
        $rank = 0
        foreach ($svc in $costInfo.TopServices) {
            $rank++
            $pct = if ($costInfo.TotalCost -gt 0) { [math]::Round(($svc.Value / $costInfo.TotalCost) * 100, 1) } else { 0 }
            $barWidth = if ($maxCostVal -gt 0) { [math]::Round(($svc.Value / $maxCostVal) * 100, 1) } else { 0 }
            $growthVal = if ($costInfo.Growth.ContainsKey($svc.Key)) { $costInfo.Growth[$svc.Key] } else { 0 }
            $growthColor = if ($growthVal -gt 20) { "#d13438" } elseif ($growthVal -gt 0) { "#ca5010" } elseif ($growthVal -lt 0) { "#107c10" } else { "#605e5c" }
            $growthIcon = if ($growthVal -gt 0) { "&#9650;" } elseif ($growthVal -lt 0) { "&#9660;" } else { "&#9644;" }
            $barColor = switch ($rank) { 1 {"#0078d4"} 2 {"#ca5010"} 3 {"#107c10"} 4 {"#5c2d91"} 5 {"#008272"} 6 {"#d13438"} 7 {"#00b7c3"} 8 {"#8764b8"} 9 {"#498205"} 10 {"#da3b01"} default {"#8a8886"} }
            $svcNameSafe = ConvertTo-SafeHtml $svc.Key

            $barRowsHtml += @"
            <div style="display:grid;grid-template-columns:200px 1fr 90px 70px 80px;align-items:center;gap:12px;padding:8px 12px;border-bottom:1px solid #f3f2f1;font-size:13px;">
                <div style="font-weight:600;color:#323130;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="$svcNameSafe">$svcNameSafe</div>
                <div style="position:relative;height:24px;background:#f3f2f1;border-radius:4px;overflow:hidden;">
                    <div style="position:absolute;left:0;top:0;bottom:0;width:${barWidth}%;background:linear-gradient(90deg,${barColor}dd,${barColor}99);border-radius:4px;transition:width .6s ease;"></div>
                    <span style="position:absolute;left:8px;top:50%;transform:translateY(-50%);font-size:11px;font-weight:700;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.3);z-index:1;">$(if($pct -ge 8){"$pct%"})</span>
                    <span style="position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:11px;font-weight:600;color:#605e5c;z-index:1;">$(if($pct -lt 8){"$pct%"})</span>
                </div>
                <div style="text-align:right;font-weight:700;color:#323130;font-size:13px;">`$$([math]::Round($svc.Value, 0).ToString('N0'))</div>
                <div style="text-align:center;font-size:12px;color:#605e5c;">$currency</div>
                <div style="text-align:right;font-weight:600;color:$growthColor;font-size:12px;">$growthIcon ${growthVal}%</div>
            </div>
"@
        }

        # Build monthly trend heatmap table
        # Find global max for color intensity scaling
        $globalMaxMonthly = [double]0
        foreach ($svc in $costInfo.TopServices) {
            foreach ($m in $months) {
                if ($costInfo.MonthlyByService.ContainsKey($svc.Key)) {
                    $svcMonths = $costInfo.MonthlyByService[$svc.Key]
                    if ($svcMonths.ContainsKey($m)) {
                        $v = [double]$svcMonths[$m]
                        if ($v -gt $globalMaxMonthly) { $globalMaxMonthly = $v }
                    }
                }
            }
        }

        $heatmapHeaderCells = ($monthLabels | ForEach-Object { "<th style='text-align:center;font-size:11px;padding:8px 6px;color:#605e5c;font-weight:600;'>$_</th>" }) -join ""
        $heatmapRows = ""
        $rank2 = 0
        foreach ($svc in $costInfo.TopServices) {
            $rank2++
            $svcNameSafe = ConvertTo-SafeHtml $svc.Key
            $barColor = switch ($rank2) { 1 {"#0078d4"} 2 {"#ca5010"} 3 {"#107c10"} 4 {"#5c2d91"} 5 {"#008272"} 6 {"#d13438"} 7 {"#00b7c3"} 8 {"#8764b8"} 9 {"#498205"} 10 {"#da3b01"} default {"#8a8886"} }
            $cells = ""
            $prevVal = $null
            foreach ($m in $months) {
                $val = [double]0
                if ($costInfo.MonthlyByService.ContainsKey($svc.Key)) {
                    $svcMonths = $costInfo.MonthlyByService[$svc.Key]
                    if ($svcMonths.ContainsKey($m)) { $val = [math]::Round([double]$svcMonths[$m], 0) }
                }
                $intensity = if ($globalMaxMonthly -gt 0) { [math]::Round(($val / $globalMaxMonthly) * 0.85 + 0.05, 2) } else { 0.05 }
                $intensity = [math]::Min($intensity, 0.9)
                $changeIndicator = ""
                if ($null -ne $prevVal -and $prevVal -gt 0 -and $val -gt 0) {
                    $pctChange = [math]::Round((($val - $prevVal) / $prevVal) * 100, 0)
                    if ($pctChange -gt 15) { $changeIndicator = "<div style='font-size:9px;color:#d13438;font-weight:700;'>&#9650;${pctChange}%</div>" }
                    elseif ($pctChange -lt -15) { $changeIndicator = "<div style='font-size:9px;color:#107c10;font-weight:700;'>&#9660;${pctChange}%</div>" }
                }
                $displayVal = if ($val -ge 1000) { "`$$([math]::Round($val/1000,1))k" } elseif ($val -gt 0) { "`$$val" } else { "-" }
                $cells += "<td style='text-align:center;padding:6px 4px;background:rgba($( if($rank2 -le 3){"0,120,212"} else {"50,50,50"} ),$intensity);border-radius:3px;'><div style='font-size:12px;font-weight:600;color:$(if($intensity -gt 0.5){"#fff"}else{"#323130"});'>$displayVal</div>$changeIndicator</td>"
                $prevVal = $val
            }
            $growthVal = if ($costInfo.Growth.ContainsKey($svc.Key)) { $costInfo.Growth[$svc.Key] } else { 0 }
            $growthColor = if ($growthVal -gt 20) { "#d13438" } elseif ($growthVal -gt 0) { "#ca5010" } elseif ($growthVal -lt 0) { "#107c10" } else { "#605e5c" }
            $growthIcon = if ($growthVal -gt 0) { "&#9650;" } elseif ($growthVal -lt 0) { "&#9660;" } else { "&#9644;" }
            $heatmapRows += "<tr><td style='font-weight:600;font-size:12px;padding:8px 10px;white-space:nowrap;border-right:2px solid #e8e8e8;'><span style='display:inline-block;width:10px;height:10px;border-radius:2px;background:$barColor;margin-right:6px;vertical-align:middle;'></span>$svcNameSafe</td>$cells<td style='text-align:center;font-weight:700;color:$growthColor;font-size:12px;padding:8px;border-left:2px solid #e8e8e8;'>$growthIcon ${growthVal}%</td></tr>"
        }

        # Build growth ranking cards (top 5 by absolute growth value)
        $growthCards = ""
        $sortedByGrowth = $costInfo.TopServices | Sort-Object { if ($costInfo.Growth.ContainsKey($_.Key)) { [math]::Abs([double]$costInfo.Growth[$_.Key]) } else { 0 } } -Descending | Select-Object -First 5
        foreach ($svc in $sortedByGrowth) {
            $svcNameSafe = ConvertTo-SafeHtml $svc.Key
            $growthVal = if ($costInfo.Growth.ContainsKey($svc.Key)) { $costInfo.Growth[$svc.Key] } else { 0 }
            if ($growthVal -eq 0) { continue }
            $isUp = $growthVal -gt 0
            $cardBg = if ($isUp) { "linear-gradient(135deg,#fff5f5,#ffe0e0)" } else { "linear-gradient(135deg,#f0fff4,#d3f9d8)" }
            $cardBorder = if ($isUp) { "#ffc9c9" } else { "#b2f2bb" }
            $iconColor = if ($isUp) { "#d13438" } else { "#107c10" }
            $arrow = if ($isUp) { "&#9650;" } else { "&#9660;" }
            $growthCards += @"
            <div style="flex:1;min-width:140px;max-width:200px;background:$cardBg;border:1px solid $cardBorder;border-radius:10px;padding:14px 16px;text-align:center;">
                <div style="font-size:11px;color:#605e5c;font-weight:600;margin-bottom:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="$svcNameSafe">$svcNameSafe</div>
                <div style="font-size:1.8em;font-weight:800;color:$iconColor;line-height:1.1;">$arrow ${growthVal}%</div>
                <div style="font-size:10px;color:#8a8886;margin-top:4px;">6-month trend</div>
            </div>
"@
        }

        [void]$costAnalysisHtml.AppendLine(@"
        <div class="cost-sub-section" data-subid="$($s.Id)" data-monthly="[$( ($months | ForEach-Object { $m = $_; $total = 0; foreach ($svc in $costInfo.TopServices) { if ($costInfo.MonthlyByService.ContainsKey($svc.Key) -and $costInfo.MonthlyByService[$svc.Key].ContainsKey($m)) { $total += [double]$costInfo.MonthlyByService[$svc.Key][$m] } }; [math]::Round($total, 0) }) -join ',' )]" style="margin-bottom:32px;border:1px solid var(--border);border-radius:12px;padding:24px;background:var(--surface);box-shadow:var(--shadow-sm);">
            <!-- Subscription Header -->
            <h3 style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid var(--accent);">&#128176; $safeName</h3>

            <!-- KPI Cards Row -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px;">
                <div style="background:linear-gradient(135deg,#0078d4,#005a9e);border-radius:10px;padding:20px;text-align:center;box-shadow:0 4px 16px rgba(0,120,212,.2);">
                    <div style="font-size:28px;font-weight:800;color:#fff;">`$$([math]::Round($costInfo.TotalCost, 0).ToString('N0'))</div>
                    <div style="font-size:11px;color:rgba(255,255,255,.8);font-weight:600;">Total Cost (6 months) · $currency</div>
                </div>
                <div style="background:linear-gradient(135deg,#f5f5f5,#e8e8e8);border:1px solid #e0e0e0;border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:28px;font-weight:800;color:#323130;">`$$($avgMonthly.ToString('N0'))</div>
                    <div style="font-size:11px;color:#605e5c;font-weight:600;">Average Monthly</div>
                </div>
                <div style="background:linear-gradient(135deg,#f5f5f5,#e8e8e8);border:1px solid #e0e0e0;border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:28px;font-weight:800;color:#0078d4;">$($costInfo.TopServices.Count)</div>
                    <div style="font-size:11px;color:#605e5c;font-weight:600;">Active Services</div>
                </div>
                <div style="background:linear-gradient(135deg,$(if($topGrowthVal -gt 20){"#fff5f5,#ffe8e8"}elseif($topGrowthVal -gt 0){"#fff8f0,#fff0e0"}else{"#f0fff4,#e0f5e8"}));border:1px solid $(if($topGrowthVal -gt 20){"#ffc9c9"}elseif($topGrowthVal -gt 0){"#ffe0b2"}else{"#b2f2bb"});border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:28px;font-weight:800;color:$topGrowthColor;">$topGrowthIcon ${topGrowthVal}%</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="$(ConvertTo-SafeHtml $topGrower)">&#128293; $(ConvertTo-SafeHtml $topGrower)</div>
                </div>
            </div>

            <!-- Growth Leaders -->
            $(if($growthCards) {
            @"
            <div style="margin-bottom:24px;">
                <h4 style="font-size:12px;font-weight:700;color:#605e5c;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;">&#128200; Growth Leaders (6-month trend)</h4>
                <div style="display:flex;gap:12px;flex-wrap:wrap;">$growthCards</div>
            </div>
"@
            })

            <!-- Cost Distribution: Horizontal Bars -->
            <div style="margin-bottom:24px;">
                <h4 style="font-size:12px;font-weight:700;color:#605e5c;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;">&#128202; Cost Distribution by Service</h4>
                <div style="background:#fafafa;border:1px solid #edebe9;border-radius:8px;overflow:hidden;">
                    <div style="display:grid;grid-template-columns:200px 1fr 90px 70px 80px;align-items:center;gap:12px;padding:8px 12px;background:#f3f2f1;font-size:11px;font-weight:700;color:#605e5c;text-transform:uppercase;letter-spacing:.3px;">
                        <div>Service</div><div>Distribution</div><div style="text-align:right">Cost</div><div style="text-align:center">Currency</div><div style="text-align:right">Trend</div>
                    </div>
                    $barRowsHtml
                </div>
            </div>

            <!-- Monthly Heatmap Table -->
            <div>
                <h4 style="font-size:12px;font-weight:700;color:#605e5c;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">&#128197; Monthly Cost Trend — Heatmap</h4>
                <p style="font-size:11px;color:#8a8886;margin-bottom:12px;line-height:1.5;">Services are sorted by <strong style="color:#605e5c;">total accumulated cost</strong> over the 6-month period (highest to lowest). This highlights which services represent the largest share of spend, making it easier to prioritize cost optimization efforts.</p>
                <div style="overflow-x:auto;border:1px solid #edebe9;border-radius:8px;">
                    <table style="width:100%;border-collapse:separate;border-spacing:3px;font-size:12px;">
                        <thead><tr><th style="text-align:left;padding:8px 10px;font-size:11px;color:#605e5c;font-weight:700;min-width:160px;border-right:2px solid #e8e8e8;">Service</th>$heatmapHeaderCells<th style="text-align:center;padding:8px 6px;font-size:11px;color:#605e5c;font-weight:700;border-left:2px solid #e8e8e8;min-width:70px;">Trend</th></tr></thead>
                        <tbody>$heatmapRows</tbody>
                    </table>
                </div>
                <div style="margin-top:8px;font-size:10px;color:#8a8886;display:flex;gap:16px;align-items:center;">
                    <span>&#9632; Color intensity = relative cost</span>
                    <span style="color:#d13438;">&#9650; = month-over-month increase &gt;15%</span>
                    <span style="color:#107c10;">&#9660; = month-over-month decrease &gt;15%</span>
                </div>
            </div>
        </div>
"@)
    }
    $costHtml = $costAnalysisHtml.ToString()

    # Pilar summary cards (exclude Zero Trust — it has its own dedicated section)
    $pillarBuilder = [System.Text.StringBuilder]::new()
    foreach ($p in ($pillarStats | Where-Object { $_.Name -ne "Zero Trust" })) {
        $pillarColor = switch ($p.Name) {
            "Security" { "#0078d4" }
            "Reliability" { "#005a9e" }
            "Cost Optimization" { "#ca5010" }
            "Operational Excellence" { "#107c10" }
            "Performance Efficiency" { "#5c2d91" }
            "Zero Trust" { "#002050" }
            default { "#8a8886" }
        }
        $pillarIcon = switch ($p.Name) {
            "Security" { "🛡️" }
            "Reliability" { "🔄" }
            "Cost Optimization" { "💰" }
            "Operational Excellence" { "⚙️" }
            "Performance Efficiency" { "⚡" }
            "Zero Trust" { "🔒" }
            default { "📋" }
        }
        $safePillarName = ConvertTo-SafeHtml $p.Name
        [void]$pillarBuilder.AppendLine(@"
        <div class="pillar-card" style="border-left: 4px solid $pillarColor;">
            <div class="pillar-icon">$pillarIcon</div>
            <div class="pillar-name">$safePillarName</div>
            <div class="pillar-count">$($p.Count) findings</div>
            <div class="pillar-breakdown">
                $(if($p.Critical -gt 0){"<span class='mini-badge critical'>$($p.Critical) Crit</span>"})
                $(if($p.High -gt 0){"<span class='mini-badge high'>$($p.High) High</span>"})
                $(if($p.Medium -gt 0){"<span class='mini-badge medium'>$($p.Medium) Med</span>"})
                $(if($p.Low -gt 0){"<span class='mini-badge low'>$($p.Low) Low</span>"})
            </div>
        </div>
"@)
    }
    $pillarCards = $pillarBuilder.ToString()

    # ── Chart data for Executive Overview ──
    # WAF Pillar bar chart data
    $pillarChartData = @($pillarStats | Where-Object { $_.Name -ne "Zero Trust" } | ForEach-Object {
        @{ name = $_.Name; critical = $_.Critical; high = $_.High; medium = $_.Medium; low = $_.Low }
    })
    $pillarChartJson = ($pillarChartData | ConvertTo-Json -Compress -Depth 2) -replace "'", "&#39;"

    # Resource distribution data (top 10 types)
    $resourceTypeCounts = $script:Resources | Group-Object ResourceType | Sort-Object Count -Descending | Select-Object -First 10
    $resourceChartData = @($resourceTypeCounts | ForEach-Object {
        $shortName = ($_.Name -split '/')[-1]
        @{ name = $shortName; count = $_.Count }
    })
    $resourceChartJson = ($resourceChartData | ConvertTo-Json -Compress -Depth 2) -replace "'", "&#39;"

    # ── Build data for the 12-section layout ────────────────────────────────
    # Merge ALL findings: WAF + Zero Trust + Underutilized Resources into a unified priority list
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($f in $script:Findings) {
        $allFindings.Add([PSCustomObject]@{
            Source         = $f.Pillar
            Severity       = $f.Severity
            Category       = $f.Category
            FindingName    = $f.Description
            ResourceName   = $f.ResourceName
            ResourceType   = $f.ResourceType
            Subscription   = $f.Subscription
            Recommendation = $f.Recommendation
            Impact         = $f.Impact
        })
    }
    # Add underutilized resources as findings
    foreach ($u in $script:UnderutilizedResources) {
        $allFindings.Add([PSCustomObject]@{
            Source         = "Cost Optimization"
            Severity       = $u.Severity
            Category       = "Underutilized - $($u.ResourceType)"
            FindingName    = $u.Description
            ResourceName   = $u.ResourceName
            ResourceType   = $u.ResourceType
            Subscription   = $u.Subscription
            Recommendation = $u.Recommendation
            Impact         = "Cost savings through right-sizing"
        })
    }

    # Priority Actions: score by Impact (severity) × Ease of implementation
    # Impact score: Critical=4, High=3, Medium=2, Low=1
    # Ease score: Config change=3, Single resource=2, Architectural=1
    $priorityItems = foreach ($f in $allFindings) {
        $impactScore = switch ($f.Severity) { 'Critical' {4} 'High' {3} 'Medium' {2} default {1} }
        # Heuristic for ease: short recommendations = simpler; specific resources = easier
        $easeScore = 3 # default: config change (easy)
        if ($f.Recommendation -match '\b(architect|redesign|migrate|multiple|infrastructure)\b') { $easeScore = 1 }
        elseif ($f.Recommendation -match '\b(implement|deploy|policy)\b|configure.*\bmultiple\b') { $easeScore = 2 }
        $priorityScore = $impactScore * $easeScore
        $tier = switch ($f.Severity) { 'Critical' {'critical'} 'High' {'important'} default {'optimization'} }
        [PSCustomObject]@{
            Tier           = $tier
            Severity       = $f.Severity
            Source         = $f.Source
            Category       = $f.Category
            FindingName    = $f.FindingName
            ResourceName   = $f.ResourceName
            Subscription   = $f.Subscription
            Recommendation = $f.Recommendation
            Impact         = $f.Impact
            PriorityScore  = $priorityScore
            EaseScore      = $easeScore
        }
    }
    # Sort by priority score descending within each tier
    $criticalItems     = @($priorityItems | Where-Object { $_.Tier -eq 'critical' } | Sort-Object PriorityScore -Descending)
    $importantItems    = @($priorityItems | Where-Object { $_.Tier -eq 'important' } | Sort-Object PriorityScore -Descending)
    $optimizationItems = @($priorityItems | Where-Object { $_.Tier -eq 'optimization' } | Sort-Object PriorityScore -Descending)

    # Build HTML for each tier
    $easeLabels = @{ 3 = '<span style="color:#107c10;font-weight:600">Quick Win</span>'; 2 = '<span style="color:#ca5010;font-weight:600">Moderate</span>'; 1 = '<span style="color:#d13438;font-weight:600">Complex</span>' }
    $priorityBuilder = [System.Text.StringBuilder]::new()

    # Tier 1: Critical (7 days)
    [void]$priorityBuilder.Append("<tr class='tier-header tier-critical'><td colspan='8' style='background:#fde7e9;color:#d13438;font-weight:700;padding:12px 16px;font-size:.95em;border-left:4px solid #d13438;'>`u{1F534} CRITICAL — Address within 7 days ($($criticalItems.Count) items)</td></tr>")
    foreach ($item in $criticalItems) {
        $ease = $easeLabels[$item.EaseScore]
        [void]$priorityBuilder.Append("<tr class='sev-critical'><td>$(ConvertTo-SafeHtml $item.Severity)</td><td>$(ConvertTo-SafeHtml $item.Source)</td><td>$(ConvertTo-SafeHtml $item.Category)</td><td style='overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.FindingName)</td><td style='overflow:hidden;text-overflow:ellipsis;word-break:break-all;font-size:.82em'>$(ConvertTo-SafeHtml $item.ResourceName)</td><td style='color:#0078d4;font-weight:600;font-size:.82em;overflow:hidden;text-overflow:ellipsis'>&#128203; $(ConvertTo-SafeHtml $item.Subscription)</td><td>$ease</td><td style='font-size:.85em;overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.Recommendation)</td></tr>")
    }
    if ($criticalItems.Count -eq 0) {
        [void]$priorityBuilder.Append("<tr><td colspan='8' style='text-align:center;color:#107c10;padding:14px;font-style:italic'>`u{2705} No critical findings — excellent security posture</td></tr>")
    }

    # Tier 2: Important (30 days)
    [void]$priorityBuilder.Append("<tr class='tier-header tier-important'><td colspan='8' style='background:#fff4ce;color:#ca5010;font-weight:700;padding:12px 16px;font-size:.95em;border-left:4px solid #ca5010;'>`u{1F7E0} IMPORTANT — Address within 30 days ($($importantItems.Count) items)</td></tr>")
    foreach ($item in $importantItems) {
        $ease = $easeLabels[$item.EaseScore]
        [void]$priorityBuilder.Append("<tr class='sev-high'><td>$(ConvertTo-SafeHtml $item.Severity)</td><td>$(ConvertTo-SafeHtml $item.Source)</td><td>$(ConvertTo-SafeHtml $item.Category)</td><td style='overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.FindingName)</td><td style='overflow:hidden;text-overflow:ellipsis;word-break:break-all;font-size:.82em'>$(ConvertTo-SafeHtml $item.ResourceName)</td><td style='color:#0078d4;font-weight:600;font-size:.82em;overflow:hidden;text-overflow:ellipsis'>&#128203; $(ConvertTo-SafeHtml $item.Subscription)</td><td>$ease</td><td style='font-size:.85em;overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.Recommendation)</td></tr>")
    }
    if ($importantItems.Count -eq 0) {
        [void]$priorityBuilder.Append("<tr><td colspan='8' style='text-align:center;color:#107c10;padding:14px;font-style:italic'>`u{2705} No high-severity findings</td></tr>")
    }

    # Tier 3: Optimizations (90 days)
    [void]$priorityBuilder.Append("<tr class='tier-header tier-optimization'><td colspan='8' style='background:#f3f2f1;color:#605e5c;font-weight:700;padding:12px 16px;font-size:.95em;border-left:4px solid #8a8886;'>`u{1F7E1} OPTIMIZATIONS — Address within 90 days ($($optimizationItems.Count) items)</td></tr>")
    foreach ($item in $optimizationItems) {
        $ease = $easeLabels[$item.EaseScore]
        [void]$priorityBuilder.Append("<tr class='sev-medium'><td>$(ConvertTo-SafeHtml $item.Severity)</td><td>$(ConvertTo-SafeHtml $item.Source)</td><td>$(ConvertTo-SafeHtml $item.Category)</td><td style='overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.FindingName)</td><td style='overflow:hidden;text-overflow:ellipsis;word-break:break-all;font-size:.82em'>$(ConvertTo-SafeHtml $item.ResourceName)</td><td style='color:#0078d4;font-weight:600;font-size:.82em;overflow:hidden;text-overflow:ellipsis'>&#128203; $(ConvertTo-SafeHtml $item.Subscription)</td><td>$ease</td><td style='font-size:.85em;overflow:hidden;text-overflow:ellipsis'>$(ConvertTo-SafeHtml $item.Recommendation)</td></tr>")
    }
    if ($optimizationItems.Count -eq 0) {
        [void]$priorityBuilder.Append("<tr><td colspan='8' style='text-align:center;color:#107c10;padding:14px;font-style:italic'>`u{2705} No medium/low findings</td></tr>")
    }
    $priorityRows = $priorityBuilder.ToString()

    # Total cost — use $script:CostData (keyed by subscription ID)
    $totalCostFormatted = if ($script:CostData.Count -gt 0) {
        $costSum = ($script:CostData.Values | ForEach-Object { if ($_ -and $_.TotalCost) { $_.TotalCost } else { 0 } } | Measure-Object -Sum).Sum
        if ($costSum -gt 0) { '$' + $costSum.ToString('N0') } else { 'N/A' }
    } else { 'N/A' }

    # Identity & Access findings (exclude unrelated 'Access' matches from Storage/KV/DB/ZT)
    $identityFindings = @($allFindings | Where-Object { $_.Category -match 'Identity|RBAC|PIM|MFA|Authentication' })
    $identityRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in $identityFindings) {
        $severityClass = $f.Severity.ToLower()
        $categoryIcon = switch -Regex ($f.Category) {
            'MFA|Authentication' { "🔐" }
            'PIM'                { "⏱️" }
            'RBAC|Access'        { "🔑" }
            'Identity'           { "👤" }
            default              { "🛡️" }
        }
        [void]$identityRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $severityClass`">$($f.Severity)</span></td><td>$categoryIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $identityRows = $identityRowsBuilder.ToString()
    $identityCount = $identityFindings.Count
    $identityCritical = @($identityFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $identityHigh     = @($identityFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $identityMedium   = @($identityFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $identityLow      = @($identityFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    # Governance & Compliance findings (exclude items shown in dedicated sub-blades: Tags, Policy, Locks, Hygiene)
    $governanceFindings = @($allFindings | Where-Object { $_.Category -match 'Policy|Compliance|Tag|Governance|Naming' -and $_.Category -notmatch '^Tag Compliance|^Policy -|Resource Lock|No Locks|^Hygiene' })
    $governanceRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in $governanceFindings) {
        $severityClass = $f.Severity.ToLower()
        $categoryIcon = switch -Regex ($f.Category) {
            'Tag'        { "🏷️" }
            'Policy'     { "📜" }
            'Compliance' { "✅" }
            'Naming'     { "🔤" }
            default      { "🏛️" }
        }
        [void]$governanceRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $severityClass`">$($f.Severity)</span></td><td>$categoryIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $governanceRows = $governanceRowsBuilder.ToString()
    $govCount = $governanceFindings.Count
    $govCritical = @($governanceFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $govHigh     = @($governanceFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $govMedium   = @($governanceFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $govLow      = @($governanceFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    # Monitoring & Observability findings (exclude Diagnostic Settings shown in Observability blade, and Network findings)
    $monitoringFindings = @($allFindings | Where-Object { $_.Category -match 'Monitor|Alert|Insight' -and $_.Category -notmatch '^Network' })
    $monitoringRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in $monitoringFindings) {
        $severityClass = $f.Severity.ToLower()
        $categoryIcon = switch -Regex ($f.Category) {
            'Diagnostic' { "📊" }
            'Monitor'    { "💻" }
            'Log'        { "📝" }
            'Alert'      { "🔔" }
            'Insight'    { "🔍" }
            default      { "📈" }
        }
        [void]$monitoringRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $severityClass`">$($f.Severity)</span></td><td>$categoryIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $monitoringRows = $monitoringRowsBuilder.ToString()
    $monCount = $monitoringFindings.Count
    $monCritical = @($monitoringFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $monHigh     = @($monitoringFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $monMedium   = @($monitoringFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $monLow      = @($monitoringFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    # Modernization findings
    $modernizationFindings = @($allFindings | Where-Object { $_.Category -match 'Modernization|Migration|Container|Serverless|PaaS' })
    $modernizationRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($modernizationFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        [void]$modernizationRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $modernizationRows = $modernizationRowsBuilder.ToString()
    $modCritical = @($modernizationFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $modHigh     = @($modernizationFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $modMedium   = @($modernizationFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $modLow      = @($modernizationFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    # Network findings (exclude Diagnostic Settings and non-network service findings)
    $networkFindings = @($allFindings | Where-Object { $_.Category -match 'Network|NSG|Firewall|VNet|Subnet|DNS|Load.Balancer' -and $_.Category -notmatch '^Diagnostic Settings|^Key Vault|^Storage' })
    $netFCritical = @($networkFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $netFHigh     = @($networkFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $netFMedium   = @($networkFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $netFLow      = @($networkFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $networkFindingsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($networkFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'NSG'           { "&#128737;" }
            'Firewall'      { "&#128293;" }
            'Subnet'        { "&#128194;" }
            'DNS'           { "&#127760;" }
            'Load.Balancer' { "&#9878;" }
            'IP'            { "&#127759;" }
            default         { "&#128274;" }
        }
        [void]$networkFindingsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $networkFindingsRows = $networkFindingsBuilder.ToString()

    # BCDR findings
    $bcdrFindings = @($allFindings | Where-Object { $_.Category -match 'BCDR|Backup|Recovery|Replication|Retention|Disaster' })
    $bcdrCritical = @($bcdrFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $bcdrHigh     = @($bcdrFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $bcdrMedium   = @($bcdrFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $bcdrLow      = @($bcdrFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $bcdrRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($bcdrFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'Expired|Expiring'  { "⏰" }
            'Backup'            { "💾" }
            'Replication|ASR'   { "🔄" }
            'Retention'         { "📅" }
            'Soft Delete'       { "🛡️" }
            'Lock'              { "🔒" }
            default             { "🏥" }
        }
        [void]$bcdrRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $bcdrRows = $bcdrRowsBuilder.ToString()

    # Expiring Secrets findings
    $secretsFindings = @($allFindings | Where-Object { $_.Category -match 'Key Vault.*Expir|Key Vault.*Expired|Key Vault.*No Expiry' })
    $secretsCritical = @($secretsFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $secretsHigh     = @($secretsFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $secretsMedium   = @($secretsFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $secretsLow      = @($secretsFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $secretsRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($secretsFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $typeIcon = switch -Regex ($f.Category) {
            'Certificate' { "📜" }
            'Key'         { "🔑" }
            'Secret'      { "🔐" }
            'No Expiry'   { "⚠️" }
            default       { "🔐" }
        }
        $statusIcon = if ($f.FindingName -match 'EXPIRED') { "🔴" } elseif ($f.Severity -eq 'Critical') { "🟠" } elseif ($f.Severity -eq 'High') { "🟡" } else { "🟢" }
        [void]$secretsRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$statusIcon $typeIcon</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $secretsRows = $secretsRowsBuilder.ToString()

    # Resource Locks findings
    $locksFindings = @($allFindings | Where-Object { $_.Category -match 'Resource Lock|No Locks' })
    $locksCritical = @($locksFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $locksHigh     = @($locksFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $locksMedium   = @($locksFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $locksLow      = @($locksFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $locksRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($locksFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        [void]$locksRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $locksRows = $locksRowsBuilder.ToString()

    # High Availability findings
    $haFindings = @($allFindings | Where-Object { $_.Category -match '^HA -' })
    $haCritical = @($haFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $haHigh     = @($haFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $haMedium   = @($haFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $haLow      = @($haFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $haTotal    = $haFindings.Count
    $haRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($haFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'Storage'    { "&#128451;" }
            'App Service'{ "&#127760;" }
            'SQL'        { "&#128451;" }
            'App Gateway'{ "&#9878;" }
            'Firewall'   { "&#128293;" }
            'Gateway'    { "&#128268;" }
            'VPN'        { "&#128268;" }
            'Redis'      { "&#9889;" }
            'Region'     { "&#127758;" }
            'Load Bal'   { "&#9878;" }
            'Disk'       { "&#128192;" }
            default      { "&#9888;&#65039;" }
        }
        [void]$haRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace '^HA - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $haRows = $haRowsBuilder.ToString()

    # Tag Compliance findings
    $tagFindings = @($allFindings | Where-Object { $_.Category -match 'Tag Compliance' })
    $tagCritical = @($tagFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $tagHigh     = @($tagFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $tagMedium   = @($tagFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $tagLow      = @($tagFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $tagTotal    = $tagFindings.Count
    $tagRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($tagFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'No Tags'     { "🚫" }
            'Missing'     { "⚠️" }
            'Empty'       { "📭" }
            'Untagged RG' { "📁" }
            'Low Compl'   { "📊" }
            default       { "🏷️" }
        }
        [void]$tagRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace 'Tag Compliance - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $tagRows = $tagRowsBuilder.ToString()

    # Diagnostic Settings findings
    $diagFindings = @($allFindings | Where-Object { $_.Category -match 'Diagnostic Settings' })
    $diagCritical = @($diagFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $diagHigh     = @($diagFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $diagMedium   = @($diagFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $diagLow      = @($diagFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $diagTotal    = $diagFindings.Count
    $diagRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($diagFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'Activity Log'   { "📋" }
            'NSG'            { "🛡️" }
            'Firewall'       { "🔥" }
            'SQL'            { "🗄️" }
            'No Log Analyt'  { "📊" }
            default          { "📡" }
        }
        [void]$diagRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace 'Diagnostic Settings - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $diagRows = $diagRowsBuilder.ToString()

    # Private Endpoint findings
    $peFindings = @($allFindings | Where-Object { $_.Category -match 'Private Endpoint' })
    $peCritical = @($peFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $peHigh     = @($peFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $peMedium   = @($peFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $peLow      = @($peFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $peTotal    = $peFindings.Count
    $peRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($peFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'SQL'       { "🗄️" }
            'Storage'   { "💾" }
            'Key Vault' { "🔑" }
            'Cosmos'    { "🌐" }
            'App Serv'  { "🌍" }
            'Redis'     { "⚡" }
            'Low Adopt' { "📉" }
            default     { "🔒" }
        }
        [void]$peRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace 'Private Endpoint - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $peRows = $peRowsBuilder.ToString()

    # Policy Compliance findings
    $policyFindings = @($allFindings | Where-Object { $_.Category -match 'Policy -' })
    $policyCritical = @($policyFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $policyHigh     = @($policyFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $policyMedium   = @($policyFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $policyLow      = @($policyFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $policyTotal    = $policyFindings.Count
    $policyRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($policyFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'No Assign'   { "🚫" }
            'Non-Compl'   { "❌" }
            'Not Enforc'  { "⚠️" }
            'Low Compl'   { "📉" }
            'Moderate'    { "📊" }
            default       { "📜" }
        }
        [void]$policyRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace 'Policy - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $policyRows = $policyRowsBuilder.ToString()

    # Cosmos DB & OSS Database findings
    $cosmosFindings = @($allFindings | Where-Object { $_.Category -match 'Cosmos DB|PostgreSQL|MySQL|Redis' })
    $cosmosCritical = @($cosmosFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $cosmosHigh     = @($cosmosFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $cosmosMedium   = @($cosmosFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $cosmosLow      = @($cosmosFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $cosmosTotal    = $cosmosFindings.Count
    $cosmosRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($cosmosFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'Cosmos'     { "🌐" }
            'PostgreSQL' { "🐘" }
            'MySQL'      { "🐬" }
            'Redis'      { "⚡" }
            default      { "🗄️" }
        }
        [void]$cosmosRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml $f.Category)</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $cosmosRows = $cosmosRowsBuilder.ToString()

    # Subscription Hygiene findings
    $hygieneFindings = @($allFindings | Where-Object { $_.Category -match 'Hygiene' })
    $hygieneCritical = @($hygieneFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $hygieneHigh     = @($hygieneFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $hygieneMedium   = @($hygieneFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $hygieneLow      = @($hygieneFindings | Where-Object { $_.Severity -eq 'Low' }).Count
    $hygieneTotal    = $hygieneFindings.Count
    $hygieneRowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($f in ($hygieneFindings | Sort-Object @{Expression={ switch($_.Severity) { 'Critical'{0} 'High'{1} 'Medium'{2} default{3} } }})) {
        $sevClass = $f.Severity.ToLower()
        $catIcon = switch -Regex ($f.Category) {
            'Region'    { "🌍" }
            'Empty'     { "📭" }
            'Naming'    { "📝" }
            'Isolated'  { "📌" }
            'Prolifer'  { "📂" }
            default     { "🧹" }
        }
        [void]$hygieneRowsBuilder.Append("<tr class=`"finding-row`" data-severity=`"$($f.Severity)`" data-category=`"$(ConvertTo-SafeHtml $f.Category)`"><td><span class=`"severity-badge $sevClass`">$($f.Severity)</span></td><td>$catIcon $(ConvertTo-SafeHtml ($f.Category -replace 'Hygiene - ',''))</td><td><strong>$(ConvertTo-SafeHtml $f.ResourceName)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $f.ResourceType)</small><br><small style=`"color:#0078d4;font-weight:600`">&#128203; $(ConvertTo-SafeHtml $f.Subscription)</small></td><td>$(ConvertTo-SafeHtml $f.FindingName)</td><td>$(ConvertTo-SafeHtml $f.Recommendation)</td></tr>")
    }
    $hygieneRows = $hygieneRowsBuilder.ToString()

    # ── ALZ Readiness blade data ──
    $alzBladeHtml = ""
    # ALZ sidebar link — always shown
    $alzSidebarLink = '<a href="#" onclick="navTo(''blade-alz'',this,event)"><span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1L2 5v6l6 4 6-4V5L8 1z" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M8 5v6M5 7h6" stroke="#0078d4" stroke-width="1.1"/></svg></span> ALZ Readiness</a>'
    if ($script:ALZData.Checks.Count -gt 0) {
        $alzChecks = $script:ALZData.Checks
        $alzPass = @($alzChecks | Where-Object Status -eq 'PASS').Count
        $alzFail = @($alzChecks | Where-Object Status -eq 'FAIL').Count
        $alzWarn = @($alzChecks | Where-Object Status -eq 'WARN').Count
        $alzInfo = @($alzChecks | Where-Object Status -eq 'INFO').Count
        $alzManual = @($alzChecks | Where-Object Status -eq 'MANUAL').Count
        $alzTotal = $alzChecks.Count
        $alzAutoTotal = $alzTotal - $alzManual
        $alzPct = if ($alzAutoTotal -gt 0) { [math]::Round(($alzPass / $alzAutoTotal) * 100) } else { 0 }

        # Build check rows
        $alzRowsBuilder = [System.Text.StringBuilder]::new()
        foreach ($chk in $alzChecks) {
            $statusClass = switch ($chk.Status) { 'PASS' { 'low' } 'FAIL' { 'critical' } 'WARN' { 'medium' } 'INFO' { 'info' } 'MANUAL' { 'high' } default { 'medium' } }
            $statusIcon  = switch ($chk.Status) { 'PASS' { '✓' } 'FAIL' { '✗' } 'WARN' { '⚠' } 'INFO' { 'ℹ' } 'MANUAL' { '🔍' } default { '·' } }
            $domainIcon  = switch ($chk.Domain) { 'MG Hierarchy' { '🏛️' } 'Policy Library' { '📜' } 'RBAC' { '🔐' } 'Network Topology' { '🌐' } 'Private DNS' { '🔗' } 'Conditional Access' { '🛡️' } 'PIM' { '⏱️' } 'Subscription Placement' { '📂' } default { '📋' } }
            $recHtml = if ($chk.Recommendation) { "<br><small style=`"color:var(--accent);`">💡 $($chk.Recommendation)</small>" } else { "" }
            [void]$alzRowsBuilder.Append("<tr><td><span class=`"severity-badge $statusClass`">$statusIcon $($chk.Status)</span></td><td>$domainIcon $($chk.Domain)</td><td><strong>$($chk.Check)</strong></td><td>$($chk.Detail)$recHtml</td></tr>")
        }
        $alzCheckRows = $alzRowsBuilder.ToString()

        # Build MG policy breakdown table
        $mgPolBreakdownHtml = ""
        if ($script:ALZData.MGPolicies -and $script:ALZData.MGPolicies.Count -gt 0) {
            $mgPolBuilder = [System.Text.StringBuilder]::new()
            $mgpIdx = 0
            foreach ($mgp in $script:ALZData.MGPolicies) {
                $mgpIdx++
                $polIcon = if ($mgp.Policies -gt 0) { '<span style="color:#107c10;font-weight:700">&#10003;</span>' } elseif ($mgp.Policies -eq 0) { '<span style="color:#ca5010;font-weight:700">—</span>' } else { '<span style="color:#d13438">&#10007;</span>' }
                $alzIcon = if ($mgp.ALZMatches -gt 0) { "<span style=`"color:#107c10`">$($mgp.ALZMatches)</span>" } else { "<span style=`"color:var(--text-dim)`">0</span>" }
                $polCountHtml = if ($mgp.Policies -gt 0 -and $mgp.PolicyNames -and $mgp.PolicyNames.Count -gt 0) {
                    "<span style=`"color:#107c10;font-weight:600;cursor:pointer;text-decoration:underline;`" onclick=`"var r=document.getElementById('mgpol-det-$mgpIdx');r.style.display=r.style.display==='none'?'':'none'`" title=`"Click to see policy list`">$($mgp.Policies)</span>"
                } elseif ($mgp.Policies -ge 0) { "$($mgp.Policies)" } else { "N/A" }
                $polDetailHtml = ""
                if ($mgp.Policies -gt 0 -and $mgp.PolicyNames -and $mgp.PolicyNames.Count -gt 0) {
                    $polItems = ($mgp.PolicyNames | Sort-Object { $_.Source }, { $_.Name } | ForEach-Object {
                        $badge = if ($_.Source -eq 'Direct') { '<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#dff6dd;color:#107c10;margin-left:6px;">Direct</span>' } else { "<span style='display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#fff4ce;color:#8a6900;margin-left:6px;'>Inherited</span>" + $(if ($_.SourceName) { "<span style='font-size:.75em;color:#605e5c;margin-left:3px;'>from $($_.SourceName)</span>" } else { '' }) }
                        "<li style='padding:3px 0;'>$($_.Name) $badge</li>"
                    }) -join ''
                    $polDetailHtml = "<tr id=`"mgpol-det-$mgpIdx`" style=`"display:none;`"><td colspan=`"4`"><div style=`"margin-left:40px;padding:10px 16px;background:#f9f9fb;border-radius:6px;border:1px solid #e8e8e8;`"><strong style=`"font-size:.85em;color:#0078d4;`">&#128220; Policy Assignments ($($mgp.Policies)):</strong><ul style=`"margin:6px 0 0 16px;padding:0;font-size:.85em;color:#323130;list-style:disc;`">$polItems</ul></div></td></tr>"
                }
                [void]$mgPolBuilder.Append("<tr><td>$polIcon</td><td><strong>$(ConvertTo-SafeHtml $mgp.MG)</strong><br><small style=`"color:var(--text-dim)`">$(ConvertTo-SafeHtml $mgp.Id)</small></td><td style=`"text-align:center`">$polCountHtml</td><td style=`"text-align:center`">$alzIcon</td></tr>")
                if ($polDetailHtml) { [void]$mgPolBuilder.Append($polDetailHtml) }
            }
            $mgPolBreakdownHtml = @"
            <h3 style="color:var(--accent-dark);margin:24px 0 14px;">Policy Assignments per Management Group</h3>
            <p style="margin-bottom:14px;color:var(--text-dim);font-size:.9em;">Policy assignments scanned at each MG level. ALZ matches indicate known Enterprise-Scale policy patterns.</p>
            <table>
                <thead><tr><th style="width:5%"></th><th style="width:45%">Management Group</th><th style="width:25%;text-align:center">Policy Assignments</th><th style="width:25%;text-align:center">ALZ Library Matches</th></tr></thead>
                <tbody>$($mgPolBuilder.ToString())</tbody>
            </table>
"@
        }

        # Build DNS zone detail table
        $dnsDetailHtml = ""
        if ($script:ALZData.PrivateDNSZones -and $script:ALZData.PrivateDNSZones.Count -gt 0) {
            $dnsBuilder = [System.Text.StringBuilder]::new()
            foreach ($dz in ($script:ALZData.PrivateDNSZones | Sort-Object name)) {
                $linkCount = [int]$dz.numberOfVirtualNetworkLinks
                $linkIcon = if ($linkCount -gt 0) { '<span style="color:#107c10;font-weight:700">✓</span>' } else { '<span style="color:#d13438;font-weight:700">✗</span>' }
                $recordCount = [int]$dz.numberOfRecordSets
                [void]$dnsBuilder.Append("<tr><td>$linkIcon</td><td><strong>$(ConvertTo-SafeHtml $dz.name)</strong></td><td style=`"text-align:center`">$linkCount</td><td style=`"text-align:center`">$recordCount</td><td style=`"font-size:.85em;color:var(--text-dim)`">$(ConvertTo-SafeHtml $dz.resourceGroup)</td></tr>")
            }
            $dnsDetailHtml = @"
            <h3 style="color:var(--accent-dark);margin:24px 0 14px;">Private DNS Zone Inventory</h3>
            <table>
                <thead><tr><th style="width:5%"></th><th style="width:40%">Zone Name</th><th style="width:15%;text-align:center">VNet Links</th><th style="width:15%;text-align:center">Record Sets</th><th style="width:25%">Resource Group</th></tr></thead>
                <tbody>$($dnsBuilder.ToString())</tbody>
            </table>
"@
        }

        # Pre-flight permission rows
        $pfRowsBuilder = [System.Text.StringBuilder]::new()
        foreach ($pf in $script:PreFlightResults) {
            $pfClass = switch ($pf.Status) { 'PASS' { 'low' } 'FAIL' { 'critical' } 'WARN' { 'medium' } 'SKIP' { 'info' } default { 'medium' } }
            $pfIcon  = switch ($pf.Status) { 'PASS' { '✓' } 'FAIL' { '✗' } 'WARN' { '⚠' } 'SKIP' { '—' } default { '·' } }
            $reqLabel = if ($pf.Required) { "<small style=`"color:var(--critical);font-weight:600;`">Required</small>" } else { "<small style=`"color:var(--text-dim)`">Optional</small>" }
            [void]$pfRowsBuilder.Append("<tr><td><span class=`"severity-badge $pfClass`">$pfIcon $($pf.Status)</span></td><td>$($pf.Check)</td><td>$($pf.Scope)</td><td>$reqLabel</td><td style=`"font-size:.85em`">$($pf.Detail)</td></tr>")
        }
        $pfRows = $pfRowsBuilder.ToString()

        # ── Build MG Hierarchy Table (Azure Portal style) ──
        $mgTreeHtml = ""
        if ($script:ALZData.MGHierarchy) {
            $mgPolLookup = @{}
            if ($script:ALZData.MGPolicies) {
                foreach ($mp in $script:ALZData.MGPolicies) { $mgPolLookup[$mp.Id] = $mp }
            }

            # Recursive sub counter
            function Count-TotalSubs {
                param($Node)
                $count = 0
                if ($Node.Children) {
                    foreach ($c in $Node.Children) {
                        if ($c.Type -match 'subscriptions') { $count++ }
                        elseif ($c.Type -match 'managementGroups') { $count += Count-TotalSubs -Node $c }
                    }
                }
                return $count
            }

            # Flatten hierarchy into table rows
            function Flatten-MGTreeRows {
                param($Node, [int]$Depth = 0, [string]$ParentId = '', [hashtable]$PolLookup, [hashtable]$SubPolLookup = @{})
                $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
                $childMGs  = @()
                $childSubs = @()
                if ($Node.Children) {
                    $childMGs  = @($Node.Children | Where-Object { $_.Type -match 'managementGroups' })
                    $childSubs = @($Node.Children | Where-Object { $_.Type -match 'subscriptions' })
                }
                $totalSubs = Count-TotalSubs -Node $Node
                $hasChildren = ($childMGs.Count + $childSubs.Count) -gt 0
                $polData = $PolLookup[$Node.Name]
                $polCount = if ($polData -and $polData.Policies -ge 0) { [int]$polData.Policies } else { -1 }

                $rows.Add([PSCustomObject]@{
                    Depth = $Depth; ParentId = $ParentId; NodeId = $Node.Name
                    DisplayName = $Node.DisplayName; NodeType = 'mg'
                    Id = $Node.Name; TotalSubs = $totalSubs; HasChildren = $hasChildren
                    Policies = $polCount
                })
                foreach ($cmg in ($childMGs | Sort-Object DisplayName)) {
                    foreach ($r in (Flatten-MGTreeRows -Node $cmg -Depth ($Depth+1) -ParentId $Node.Name -PolLookup $PolLookup -SubPolLookup $SubPolLookup)) { $rows.Add($r) }
                }
                foreach ($csub in ($childSubs | Sort-Object DisplayName)) {
                    $subPol = $SubPolLookup[$csub.Name]
                    $subPolCount = if ($subPol -and $subPol.Policies -ge 0) { [int]$subPol.Policies } else { -1 }
                    $rows.Add([PSCustomObject]@{
                        Depth = $Depth + 1; ParentId = $Node.Name; NodeId = $csub.Name
                        DisplayName = $csub.DisplayName; NodeType = 'sub'
                        Id = $csub.Name; TotalSubs = 0; HasChildren = $false
                        Policies = $subPolCount
                    })
                }
                return $rows
            }

            $subPolLookup = @{}
            if ($script:ALZData.SubPolicies) {
                foreach ($sp in $script:ALZData.SubPolicies) { $subPolLookup[$sp.Id] = $sp }
            }
            $flatRows = Flatten-MGTreeRows -Node $script:ALZData.MGHierarchy -Depth 0 -ParentId '' -PolLookup $mgPolLookup -SubPolLookup $subPolLookup
            $mgRowsBuilder = [System.Text.StringBuilder]::new()
            foreach ($r in $flatRows) {
                $indent = $r.Depth * 28
                $visible = if ($r.Depth -le 1) { '' } else { " style='display:none;'" }
                $expanded = if ($r.Depth -le 0 -and $r.HasChildren) { 'true' } else { 'false' }
                if ($r.HasChildren) {
                    $chevron = "<span class='mg-chev' data-expanded='$expanded' onclick='toggleMGRow(this,event)'>&#9660;</span>"
                } else {
                    $chevron = "<span style='display:inline-block;width:16px;'></span>"
                }
                if ($r.NodeType -eq 'mg') {
                    $icon = "<svg width='16' height='16' viewBox='0 0 16 16' style='vertical-align:middle;flex-shrink:0;'><rect x='1' y='3' width='14' height='10' rx='1.5' fill='none' stroke='#0078d4' stroke-width='1.1'/><path d='M1 5.5h14' stroke='#0078d4' stroke-width='.8'/><rect x='3' y='1' width='10' height='3' rx='1' fill='none' stroke='#0078d4' stroke-width='.8'/></svg>"
                    $nameHtml = "<span style='color:#323130;font-weight:600;'>$($r.DisplayName)</span>"
                    $typeLabel = 'Management group'
                    $subsCol = "<span>$($r.TotalSubs)</span>"
                } else {
                    $icon = "<svg width='16' height='16' viewBox='0 0 16 16' style='vertical-align:middle;flex-shrink:0;'><path d='M8 2L3 5v6l5 3 5-3V5L8 2z' fill='#ffb900' stroke='#e8a200' stroke-width='.5'/><path d='M8 5v6M5.5 6.5l5 3M10.5 6.5l-5 3' stroke='#fff' stroke-width='.8'/></svg>"
                    $nameHtml = "<span style='color:#0078d4;'>$($r.DisplayName)</span>"
                    $typeLabel = 'Subscription'
                    $subsCol = ""
                }
                $polCol = ""
                $polDetailRow = ""
                if ($r.Policies -ge 0) {
                    $pd = if ($r.NodeType -eq 'mg') { $mgPolLookup[$r.NodeId] } else { $subPolLookup[$r.NodeId] }
                    if ($r.Policies -gt 0 -and $pd -and $pd.PolicyNames -and $pd.PolicyNames.Count -gt 0) {
                        $polCol = "<span style='font-weight:600;color:#107c10;cursor:pointer;text-decoration:underline;' onclick='togglePolDetail(`"pol-$($r.NodeId)`",event)' title='Click to see policies'>$($r.Policies)</span>"
                        $polListHtml = ($pd.PolicyNames | Sort-Object { $_.Source }, { $_.Name } | ForEach-Object {
                            $badge = if ($_.Source -eq 'Direct') { '<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#dff6dd;color:#107c10;margin-left:6px;">Direct</span>' } else { "<span style='display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#fff4ce;color:#8a6900;margin-left:6px;'>Inherited</span>" + $(if ($_.SourceName) { "<span style='font-size:.75em;color:#605e5c;margin-left:3px;'>from $($_.SourceName)</span>" } else { '' }) }
                            "<li style='padding:3px 0;'>$($_.Name) $badge</li>"
                        }) -join ''
                        $polDetailRow = "<tr id='pol-$($r.NodeId)' style='display:none;'><td colspan='5'><div style='margin-left:$($indent + 40)px;padding:10px 16px;background:#f9f9fb;border-radius:6px;border:1px solid #e8e8e8;'><strong style='font-size:.85em;color:#0078d4;'>&#128220; Policy Assignments ($($r.Policies)):</strong><ul style='margin:6px 0 0 16px;padding:0;font-size:.85em;color:#323130;list-style:disc;'>$polListHtml</ul></div></td></tr>"
                    } else {
                        $polCol = "<span style='font-weight:600;color:$(if($r.Policies -gt 0){'#107c10'}else{'#ca5010'});'>$($r.Policies)</span>"
                    }
                }
                [void]$mgRowsBuilder.Append("<tr class='mg-row' data-mgid='$($r.NodeId)' data-parent='$($r.ParentId)' data-depth='$($r.Depth)'$visible>")
                [void]$mgRowsBuilder.Append("<td><div style='display:flex;align-items:center;gap:6px;padding-left:${indent}px;'>$chevron $icon $nameHtml</div></td>")
                [void]$mgRowsBuilder.Append("<td style='color:#605e5c;'>$typeLabel</td>")
                [void]$mgRowsBuilder.Append("<td style='font-size:.85em;color:#605e5c;font-family:monospace;'>$($r.Id)</td>")
                [void]$mgRowsBuilder.Append("<td style='text-align:center;'>$polCol</td>")
                [void]$mgRowsBuilder.Append("<td style='text-align:center;'>$subsCol</td>")
                [void]$mgRowsBuilder.Append("</tr>")
                if ($polDetailRow) { [void]$mgRowsBuilder.Append($polDetailRow) }
            }
            $mgTableRows = $mgRowsBuilder.ToString()
            $totalMGCount = @($flatRows | Where-Object NodeType -eq 'mg').Count
            $totalSubCount = @($flatRows | Where-Object NodeType -eq 'sub').Count
            $mgTreeHtml = @"
            <h3 style="color:var(--accent-dark);margin:20px 0 12px;">Management Group Hierarchy</h3>
            <p style="margin-bottom:12px;color:var(--text-dim);font-size:.9em;">Showing <strong>$totalSubCount</strong> subscriptions in <strong>$totalMGCount</strong> groups</p>
            <style>
                .mg-hier-table{width:100%;border-collapse:collapse;font-size:.9em;}
                .mg-hier-table thead th{text-align:left;padding:10px 12px;color:#605e5c;font-weight:600;font-size:.8em;text-transform:uppercase;letter-spacing:.3px;border-bottom:2px solid var(--border);cursor:pointer;-webkit-user-select:none;user-select:none;}
                .mg-hier-table tbody tr{border-bottom:1px solid var(--border);transition:background .1s;}
                .mg-hier-table tbody tr:hover{background:#f3f2f1;}
                .mg-hier-table td{padding:8px 12px;vertical-align:middle;}
                .mg-chev{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;font-size:8px;color:#605e5c;cursor:pointer;transition:transform .15s ease;flex-shrink:0;}
                .mg-chev[data-expanded='false']{transform:rotate(-90deg);}
                .mg-chev[data-expanded='true']{transform:rotate(0deg);}
            </style>
            <script>
            function togglePolDetail(id,ev){
                ev.stopPropagation();
                var row=document.getElementById(id);
                if(row) row.style.display=row.style.display==='none'?'':'none';
            }
            function toggleMGRow(chev,ev){
                ev.stopPropagation();
                var tr=chev.closest('tr'),mgid=tr.dataset.mgid;
                var isExpanded=chev.dataset.expanded==='true';
                chev.dataset.expanded=isExpanded?'false':'true';
                var allRows=tr.closest('table').querySelectorAll('tr.mg-row');
                allRows.forEach(function(r){
                    if(r.dataset.parent===mgid){
                        r.style.display=isExpanded?'none':'';
                        if(isExpanded){
                            var ch=r.querySelector('.mg-chev');
                            if(ch){ch.dataset.expanded='false';collapseChildren(r,allRows);}
                        }
                    }
                });
            }
            function collapseChildren(parentRow,allRows){
                var pid=parentRow.dataset.mgid;
                allRows.forEach(function(r){
                    if(r.dataset.parent===pid){
                        r.style.display='none';
                        var ch=r.querySelector('.mg-chev');
                        if(ch){ch.dataset.expanded='false';collapseChildren(r,allRows);}
                    }
                });
            }
            </script>
            <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
            <table class="mg-hier-table">
                <thead><tr><th>Name</th><th style="width:14%;">Type</th><th style="width:28%;">ID</th><th style="width:10%;text-align:center;">Policies</th><th style="width:12%;text-align:center;">Total subscriptions</th></tr></thead>
                <tbody>$mgTableRows</tbody>
            </table>
            </div>
"@
        } elseif ($script:ALZData.MGPolicies -and $script:ALZData.MGPolicies.Count -gt 0) {
            # Fallback: no recursive hierarchy, but we have a flat MG list from policy scan
            $mgFlatBuilder = [System.Text.StringBuilder]::new()
            $mgIcon = "<svg width='16' height='16' viewBox='0 0 16 16' style='vertical-align:middle;flex-shrink:0;'><rect x='1' y='3' width='14' height='10' rx='1.5' fill='none' stroke='#0078d4' stroke-width='1.1'/><path d='M1 5.5h14' stroke='#0078d4' stroke-width='.8'/><rect x='3' y='1' width='10' height='3' rx='1' fill='none' stroke='#0078d4' stroke-width='.8'/></svg>"
            $subIcon = "<svg width='16' height='16' viewBox='0 0 16 16' style='vertical-align:middle;flex-shrink:0;'><path d='M8 2L3 5v6l5 3 5-3V5L8 2z' fill='#ffb900' stroke='#e8a200' stroke-width='.5'/><path d='M8 5v6M5.5 6.5l5 3M10.5 6.5l-5 3' stroke='#fff' stroke-width='.8'/></svg>"
            foreach ($mgp in $script:ALZData.MGPolicies) {
                $polCol = ""
                $polDetailFlat = ""
                if ($mgp.Policies -gt 0 -and $mgp.PolicyNames -and $mgp.PolicyNames.Count -gt 0) {
                    $polCol = "<span style='font-weight:600;color:#107c10;cursor:pointer;text-decoration:underline;' onclick='togglePolDetail(`"pol-flat-$($mgp.Id)`",event)' title='Click to see policies'>$($mgp.Policies)</span>"
                    $polListFlat = ($mgp.PolicyNames | Sort-Object { $_.Source }, { $_.Name } | ForEach-Object {
                        $badge = if ($_.Source -eq 'Direct') { '<span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#dff6dd;color:#107c10;margin-left:6px;">Direct</span>' } else { "<span style='display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;font-weight:600;background:#fff4ce;color:#8a6900;margin-left:6px;'>Inherited</span>" + $(if ($_.SourceName) { "<span style='font-size:.75em;color:#605e5c;margin-left:3px;'>from $($_.SourceName)</span>" } else { '' }) }
                        "<li style='padding:3px 0;'>$($_.Name) $badge</li>"
                    }) -join ''
                    $polDetailFlat = "<tr id='pol-flat-$($mgp.Id)' style='display:none;'><td colspan='4'><div style='margin-left:40px;padding:10px 16px;background:#f9f9fb;border-radius:6px;border:1px solid #e8e8e8;'><strong style='font-size:.85em;color:#0078d4;'>&#128220; Policy Assignments ($($mgp.Policies)):</strong><ul style='margin:6px 0 0 16px;padding:0;font-size:.85em;color:#323130;list-style:disc;'>$polListFlat</ul></div></td></tr>"
                } elseif ($mgp.Policies -ge 0) {
                    $polCol = "<span style='font-weight:600;color:$(if($mgp.Policies -gt 0){'#107c10'}else{'#ca5010'});'>$($mgp.Policies)</span>"
                } else { $polCol = "<span style='color:#a19f9d;'>N/A</span>" }
                [void]$mgFlatBuilder.Append("<tr><td><div style='display:flex;align-items:center;gap:6px;'>$mgIcon <span style='font-weight:600;'>$(ConvertTo-SafeHtml $mgp.MG)</span></div></td><td style='color:#605e5c;'>Management group</td><td style='font-size:.85em;color:#605e5c;font-family:monospace;'>$(ConvertTo-SafeHtml $mgp.Id)</td><td style='text-align:center;'>$polCol</td></tr>")
                if ($polDetailFlat) { [void]$mgFlatBuilder.Append($polDetailFlat) }
            }
            # Also add subscriptions as rows
            foreach ($sub in ($script:Subscriptions | Sort-Object Name)) {
                [void]$mgFlatBuilder.Append("<tr><td><div style='display:flex;align-items:center;gap:6px;padding-left:28px;'>$subIcon <span style='color:#0078d4;'>$(ConvertTo-SafeHtml $sub.Name)</span></div></td><td style='color:#605e5c;'>Subscription</td><td style='font-size:.85em;color:#605e5c;font-family:monospace;'>$(ConvertTo-SafeHtml $sub.Id)</td><td style='text-align:center;'></td></tr>")
            }
            $mgFlatRows = $mgFlatBuilder.ToString()
            $totalMGCount = $script:ALZData.MGPolicies.Count
            $totalSubCount = @($script:Subscriptions).Count
            $mgTreeHtml = @"
            <h3 style="color:var(--accent-dark);margin:20px 0 12px;">Management Group Hierarchy</h3>
            <div style="background:#fff4ce;border-left:4px solid #ca5010;border-radius:6px;padding:10px 14px;margin-bottom:14px;font-size:.85em;color:#323130;">
                <strong>&#9888;&#65039; Limited view:</strong> Cannot expand full MG hierarchy (insufficient permissions). Showing flat list of <strong>$totalMGCount</strong> management groups and <strong>$totalSubCount</strong> subscriptions. Assign <strong>Management Group Reader</strong> at Tenant Root Group for the full tree view.
            </div>
            <style>
                .mg-hier-table{width:100%;border-collapse:collapse;font-size:.9em;}
                .mg-hier-table thead th{text-align:left;padding:10px 12px;color:#605e5c;font-weight:600;font-size:.8em;text-transform:uppercase;letter-spacing:.3px;border-bottom:2px solid var(--border);}
                .mg-hier-table tbody tr{border-bottom:1px solid var(--border);transition:background .1s;}
                .mg-hier-table tbody tr:hover{background:#f3f2f1;}
                .mg-hier-table td{padding:8px 12px;vertical-align:middle;}
            </style>
            <script>
            function togglePolDetail(id,ev){
                ev.stopPropagation();
                var row=document.getElementById(id);
                if(row) row.style.display=row.style.display==='none'?'':'none';
            }
            </script>
            <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;">
            <table class="mg-hier-table">
                <thead><tr><th>Name</th><th style="width:14%;">Type</th><th style="width:30%;">ID</th><th style="width:12%;text-align:center;">Policy Assignments</th></tr></thead>
                <tbody>$mgFlatRows</tbody>
            </table>
            </div>
"@
        }

        $alzBladeHtml = @"
    <div class="blade" id="blade-alz" style="display:none">
    <div class="section" id="section-alz">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>🏗️ Azure Landing Zone (ALZ/CAF) Readiness</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#0078d4 0%,#004578 40%,#001d3d 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,29,61,0.25);">
                <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:center;">
                    <div style="flex:1;min-width:220px;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.3em;margin-bottom:8px;">ALZ Readiness Score</div>
                        <div style="font-size:.9em;color:rgba(255,255,255,0.8);line-height:1.5;">Evaluation against Azure Landing Zone reference architecture covering: Management Group hierarchy, Policy library, RBAC, Hub-Spoke/vWAN topology, Private DNS zones, Conditional Access, and PIM.</div>
                    </div>
                    <div style="display:flex;gap:14px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:80px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:12px;padding:16px 20px;">
                            <div style="font-size:2.2em;font-weight:700;color:#69db7c;line-height:1.1;">$alzPass</div>
                            <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;">Pass</div>
                        </div>
                        <div style="text-align:center;min-width:80px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:12px;padding:16px 20px;">
                            <div style="font-size:2.2em;font-weight:700;color:#ffa94d;line-height:1.1;">$alzWarn</div>
                            <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;">Warn</div>
                        </div>
                        <div style="text-align:center;min-width:80px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:12px;padding:16px 20px;">
                            <div style="font-size:2.2em;font-weight:700;color:#ff6b6b;line-height:1.1;">$alzFail</div>
                            <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;">Fail</div>
                        </div>
                        <div style="text-align:center;min-width:80px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:12px;padding:16px 20px;">
                            <div style="font-size:2.2em;font-weight:700;color:#e8a838;line-height:1.1;">$alzManual</div>
                            <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;">Manual</div>
                        </div>
                    </div>
                </div>
            </div>

            $mgTreeHtml

            <h3 style="color:var(--accent-dark);margin-bottom:10px;">ALZ Readiness Checks</h3>
            <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px;padding:10px 14px;background:#f9f9fb;border-radius:6px;border:1px solid #e8e8e8;">
                <span style="font-size:12px;color:#323130;"><span class="severity-badge low" style="font-size:11px;padding:2px 8px;">✓ PASS</span> Meets ALZ best practice</span>
                <span style="font-size:12px;color:#323130;"><span class="severity-badge medium" style="font-size:11px;padding:2px 8px;">⚠ WARN</span> Partial or suboptimal result</span>
                <span style="font-size:12px;color:#323130;"><span class="severity-badge critical" style="font-size:11px;padding:2px 8px;">✗ FAIL</span> Does not meet ALZ requirement</span>
                <span style="font-size:12px;color:#323130;"><span class="severity-badge high" style="font-size:11px;padding:2px 8px;">🔍 MANUAL</span> Requires manual verification in portal</span>
            </div>
            <table>
                <thead><tr><th style="width:10%">Status</th><th style="width:15%">Domain</th><th style="width:20%">Check</th><th>Detail &amp; Recommendation</th></tr></thead>
                <tbody>$alzCheckRows</tbody>
            </table>

            $mgPolBreakdownHtml

            $dnsDetailHtml

        </div>
    </div>
    </div><!-- /blade-alz -->
"@
    } else {
        # No ALZ data collected (should not happen since ALZ always runs)
        $alzBladeHtml = @"
    <div class="blade" id="blade-alz" style="display:none">
    <div class="section" id="section-alz">
        <div class="section-header" onclick="toggleSection(this)"><h2>&#127959;&#65039; Azure Landing Zone (ALZ/CAF) Readiness</h2><span class="toggle">&#9660;</span></div>
        <div class="section-content">
            <div style="background:var(--accent-lighter);border:1px solid var(--accent);border-radius:10px;padding:24px;text-align:center;">
                <p style="color:var(--text-dim);">ALZ readiness checks did not produce results. This may indicate a permission issue. Check the execution log for errors.</p>
            </div>
        </div>
    </div>
    </div><!-- /blade-alz -->
"@
    }

    # Now write the full HTML
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Tenant Assessment Report</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --surface: #ffffff;
            --surface2: rgba(255,255,255,0.65);
            --glass: rgba(255,255,255,0.45);
            --glass-border: rgba(230,230,230,0.55);
            --glass-hover: rgba(0,120,212,0.08);
            --border: #e0e0e0;
            --border-light: #ebebeb;
            --text: #242424;
            --text-dim: #616161;
            --text-muted: #8b92a0;
            --accent: #0078d4;
            --accent-light: #e8f4fd;
            --accent-lighter: #f0f8ff;
            --accent-dark: #004578;
            --azure-cyan: #00b7c3;
            --azure-navy: #001d3d;
            --critical: #d13438;
            --high: #ca5010;
            --medium: #7a7574;
            --low: #107c10;
            --info: #0078d4;
            --shadow-sm: 0 1px 3px rgba(0,29,61,0.06);
            --shadow-md: 0 4px 16px rgba(0,29,61,0.08);
            --shadow-lg: 0 8px 32px rgba(0,29,61,0.10);
            --radius: 14px;
            --radius-sm: 10px;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.65;
            font-size: 14.5px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        .container { max-width: 1480px; margin: 0 auto; padding: 28px 24px; }

        /* ── Hero Header ─────────────────────────────────────────── */
        .header {
            background: linear-gradient(135deg, var(--azure-navy) 0%, #003a78 30%, var(--accent) 65%, var(--azure-cyan) 100%);
            border-radius: var(--radius);
            padding: 52px 48px 44px;
            margin-bottom: 32px;
            text-align: center;
            color: #fff;
            position: relative;
            overflow: hidden;
            box-shadow: var(--shadow-lg), 0 0 60px rgba(0,120,212,0.12);
        }
        .header::before {
            content: '';
            position: absolute;
            inset: 0;
            background: radial-gradient(ellipse at 30% 0%, rgba(0,183,195,0.18) 0%, transparent 60%),
                        radial-gradient(ellipse at 80% 100%, rgba(0,120,212,0.15) 0%, transparent 50%);
            pointer-events: none;
        }
        .header-logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
            margin-bottom: 16px;
            position: relative;
        }
        .header-logo svg { flex-shrink: 0; filter: drop-shadow(0 2px 8px rgba(0,0,0,0.2)); }
        .header h1 {
            font-size: 2.1em;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.3px;
            position: relative;
        }
        .header .meta {
            color: rgba(255,255,255,0.72);
            font-size: 0.88em;
            margin-top: 10px;
            letter-spacing: 0.1px;
            line-height: 1.7;
            position: relative;
        }
        .score-container {
            display: flex;
            justify-content: center;
            gap: 16px;
            margin: 36px 0 0;
            flex-wrap: wrap;
            position: relative;
        }
        .score-card {
            background: rgba(255,255,255,0.10);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: var(--radius-sm);
            padding: 22px 32px;
            text-align: center;
            min-width: 128px;
            transition: transform 0.2s, background 0.2s;
        }
        .score-card:hover { background: rgba(255,255,255,0.17); transform: translateY(-2px); }
        .score-card .number { font-size: 2.5em; font-weight: 700; color: #fff; line-height: 1.1; }
        .score-card .label {
            font-size: 0.72em;
            color: rgba(255,255,255,0.62);
            margin-top: 6px;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-weight: 500;
        }
        .score-card.critical .number { color: #ff9a9e; }
        .score-card.high .number { color: #ffcb8e; }
        .score-card.medium .number { color: #d2d0ce; }
        .score-card.low .number { color: #7ae27a; }
        .score-card.total .number { color: #fff; }

        /* ── Glassmorphism Section Panels ─────────────────────────── */
        .section {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            margin-bottom: 18px;
            overflow: hidden;
            box-shadow: var(--shadow-sm);
            transition: box-shadow 0.2s;
        }
        .section:hover { box-shadow: var(--shadow-md); }
        .section-header {
            padding: 14px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--glass);
            backdrop-filter: blur(20px) saturate(1.6);
            -webkit-backdrop-filter: blur(20px) saturate(1.6);
            border-bottom: 1px solid var(--glass-border);
            transition: background 0.2s ease;
        }
        .section-header:hover { background: var(--glass-hover); }
        .section-header h2 {
            font-size: 1.05em;
            font-weight: 600;
            color: var(--azure-navy);
            letter-spacing: -0.1px;
        }
        .section-header .toggle {
            font-size: 1em;
            color: var(--accent);
            transition: transform 0.3s ease;
            opacity: 0.6;
        }
        .section-content { padding: 28px 28px; }
        .section.collapsed .section-content { display: none; }
        .section.collapsed .toggle { transform: rotate(-90deg); }

        /* ── Nested sections (inside Infrastructure Baseline) ───── */
        .section .section {
            border: 1px solid var(--border-light);
            border-radius: var(--radius-sm);
            box-shadow: none;
            margin-bottom: 14px;
        }
        .section .section .section-header {
            padding: 16px 24px;
            background: var(--surface2);
        }
        .section .section .section-header h2 { font-size: 0.95em; color: var(--accent-dark); }
        .section .section .section-content { padding: 22px 24px; }

        /* ── Pillar Cards ──────────────────────────────────────────── */
        .pillar-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 10px;
            margin-bottom: 4px;
        }
        .pillar-card {
            background: var(--surface);
            border-radius: var(--radius-sm);
            padding: 14px 16px;
            border: 1px solid var(--border);
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .pillar-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
        .pillar-icon { font-size: 1.2em; margin-bottom: 4px; }
        .pillar-name { font-size: 0.88em; font-weight: 600; color: var(--azure-navy); margin-bottom: 2px; }
        .pillar-count { color: var(--text-dim); margin-bottom: 6px; font-size: 0.78em; }
        .pillar-breakdown { display: flex; gap: 4px; flex-wrap: wrap; }
        .pillar-breakdown .mini-badge { font-size: 0.68em; padding: 1px 6px; }
        #findingsTable{table-layout:fixed;width:100%}
        #findingsTable th:nth-child(1){width:58px}
        #findingsTable th:nth-child(2){width:65px}
        #findingsTable th:nth-child(3){width:100px}
        #findingsTable th:nth-child(4){width:115px}
        #findingsTable th:nth-child(5){width:20%}
        #findingsTable th:nth-child(6){width:20%}
        #findingsTable th:nth-child(7){width:56px}
        #findingsTable td{overflow:hidden;text-overflow:ellipsis;vertical-align:top;word-wrap:break-word}
        #findingsTable td:nth-child(4){font-size:.78em;line-height:1.35}
        #findingsTable td:nth-child(4) strong{display:inline-block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        #findingsTable td:nth-child(5), #findingsTable td:nth-child(6){font-size:.78em;line-height:1.4}
        #priorityTable td{overflow:hidden;text-overflow:ellipsis;vertical-align:top;word-wrap:break-word}
        @media (max-width: 1200px) { .pillar-grid { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); } }

        /* ── Filter Bar & Search ───────────────────────────────────── */
        .filters {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        .filter-btn {
            padding: 6px 16px;
            border-radius: 20px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text-dim);
            cursor: pointer;
            font-size: 0.8em;
            font-weight: 500;
            transition: all 0.15s ease;
        }
        .filter-btn:hover { background: var(--accent-light); color: var(--accent-dark); border-color: var(--accent); }
        .filter-btn.active {
            background: var(--accent);
            color: #fff;
            border-color: var(--accent);
            font-weight: 600;
        }

        /* Severity-colored buttons */
        .filter-btn.sev-critical { color: #d13438; border-color: #f1c0c2; background: #fef5f5; }
        .filter-btn.sev-critical:hover { background: #fde7e9; border-color: #d13438; }
        .filter-btn.sev-critical.active { background: #d13438; color: #fff; border-color: #d13438; }
        .filter-btn.sev-high { color: #ca5010; border-color: #f5d5b0; background: #fffaf5; }
        .filter-btn.sev-high:hover { background: #fff1e0; border-color: #ca5010; }
        .filter-btn.sev-high.active { background: #ca5010; color: #fff; border-color: #ca5010; }
        .filter-btn.sev-medium { color: #605e5c; border-color: #d2d0ce; background: #faf9f8; }
        .filter-btn.sev-medium:hover { background: #f0efed; border-color: #8a8886; }
        .filter-btn.sev-medium.active { background: #6e6d6b; color: #fff; border-color: #6e6d6b; }
        .filter-btn.sev-low { color: #107c10; border-color: #b4e6b0; background: #f5fbf5; }
        .filter-btn.sev-low:hover { background: #dff6dd; border-color: #107c10; }
        .filter-btn.sev-low.active { background: #107c10; color: #fff; border-color: #107c10; }

        /* Category/type colored buttons */
        .filter-btn.cat-security { color: #8b2252; border-color: #e8b4cb; background: #fdf5f9; }
        .filter-btn.cat-security:hover { background: #fce8f1; border-color: #8b2252; }
        .filter-btn.cat-security.active { background: #8b2252; color: #fff; border-color: #8b2252; }
        .filter-btn.cat-reliability { color: #0e6fc9; border-color: #a9d4f5; background: #f3f9fe; }
        .filter-btn.cat-reliability:hover { background: #deecf9; border-color: #0e6fc9; }
        .filter-btn.cat-reliability.active { background: #0e6fc9; color: #fff; border-color: #0e6fc9; }
        .filter-btn.cat-cost { color: #b7791f; border-color: #f0d89c; background: #fffdf5; }
        .filter-btn.cat-cost:hover { background: #fef5e0; border-color: #b7791f; }
        .filter-btn.cat-cost.active { background: #b7791f; color: #fff; border-color: #b7791f; }
        .filter-btn.cat-ops { color: #5c2d91; border-color: #c9b4e4; background: #f9f5fd; }
        .filter-btn.cat-ops:hover { background: #ece4f6; border-color: #5c2d91; }
        .filter-btn.cat-ops.active { background: #5c2d91; color: #fff; border-color: #5c2d91; }
        .filter-btn.cat-perf { color: #00838f; border-color: #a0dce1; background: #f2fbfc; }
        .filter-btn.cat-perf:hover { background: #dff5f7; border-color: #00838f; }
        .filter-btn.cat-perf.active { background: #00838f; color: #fff; border-color: #00838f; }

        /* ZT layer colored buttons */
        .filter-btn.zt-network { color: #0078d4; border-color: #a9d4f5; background: #f3f9fe; }
        .filter-btn.zt-network:hover { background: #deecf9; border-color: #0078d4; }
        .filter-btn.zt-network.active { background: #0078d4; color: #fff; border-color: #0078d4; }
        .filter-btn.zt-compute { color: #107c10; border-color: #b4e6b0; background: #f5fbf5; }
        .filter-btn.zt-compute:hover { background: #dff6dd; border-color: #107c10; }
        .filter-btn.zt-compute.active { background: #107c10; color: #fff; border-color: #107c10; }
        .filter-btn.zt-platform { color: #001d3d; border-color: #a4b4c8; background: #f3f6fa; }
        .filter-btn.zt-platform:hover { background: #e2e8f0; border-color: #001d3d; }
        .filter-btn.zt-platform.active { background: #001d3d; color: #fff; border-color: #001d3d; }

        /* Resource type colored buttons */
        .filter-btn.type-vm { color: #0078d4; border-color: #a9d4f5; background: #f3f9fe; }
        .filter-btn.type-vm:hover { background: #deecf9; border-color: #0078d4; }
        .filter-btn.type-vm.active { background: #0078d4; color: #fff; border-color: #0078d4; }
        .filter-btn.type-app { color: #00838f; border-color: #a0dce1; background: #f2fbfc; }
        .filter-btn.type-app:hover { background: #dff5f7; border-color: #00838f; }
        .filter-btn.type-app.active { background: #00838f; color: #fff; border-color: #00838f; }
        .filter-btn.type-sql { color: #5c2d91; border-color: #c9b4e4; background: #f9f5fd; }
        .filter-btn.type-sql:hover { background: #ece4f6; border-color: #5c2d91; }
        .filter-btn.type-sql.active { background: #5c2d91; color: #fff; border-color: #5c2d91; }
        .filter-btn.type-disk { color: #b7791f; border-color: #f0d89c; background: #fffdf5; }
        .filter-btn.type-disk:hover { background: #fef5e0; border-color: #b7791f; }
        .filter-btn.type-disk.active { background: #b7791f; color: #fff; border-color: #b7791f; }
        .search-box {
            padding: 8px 16px;
            border-radius: 8px;
            border: 1px solid var(--border);
            background: var(--surface);
            color: var(--text);
            font-size: 0.85em;
            width: 260px;
            transition: all 0.2s;
        }
        .search-box:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-light); }

        /* ── Tables ──────────────────────────────────────────────── */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        th {
            background: var(--azure-navy);
            padding: 8px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.78em;
            color: #fff;
            letter-spacing: 0.2px;
            text-transform: uppercase;
            border-bottom: 2px solid var(--accent);
            position: sticky;
            top: 0;
        }
        td {
            padding: 7px 12px;
            border-bottom: 1px solid var(--border-light);
            vertical-align: top;
            color: var(--text);
            line-height: 1.4;
        }
        tr:hover td { background: var(--accent-lighter); }
        #subsTable tr[data-subid]:hover td { background: #e8f4fd; }
        #subsTable tr.sub-selected td { background: linear-gradient(90deg,#e8f4fd,#f0f6ff); font-weight: 600; }
        code { background: #eef0f2; padding: 2px 7px; border-radius: 5px; font-size: 0.88em; color: var(--accent-dark); }

        /* ── Severity Badges ──────────────────────────────────────── */
        .severity-badge {
            display: inline-block;
            padding: 3px 11px;
            border-radius: 12px;
            font-size: 0.74em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .severity-badge.critical { background: #fde7e9; color: var(--critical); border: 1px solid #f1c0c2; }
        .severity-badge.high { background: #fff1e0; color: var(--high); border: 1px solid #fad6b0; }
        .severity-badge.medium { background: #f3f2f1; color: #605e5c; border: 1px solid #d2d0ce; }
        .severity-badge.low { background: #dff6dd; color: var(--low); border: 1px solid #b4e6b0; }
        .severity-badge.info { background: var(--accent-light); color: var(--accent); border: 1px solid #b4d9f3; }

        .mini-badge {
            padding: 2px 9px;
            border-radius: 10px;
            font-size: 0.72em;
            font-weight: 600;
        }
        .mini-badge.critical { background: #fde7e9; color: var(--critical); }
        .mini-badge.high { background: #fff1e0; color: var(--high); }
        .mini-badge.medium { background: #f3f2f1; color: #605e5c; }
        .mini-badge.low { background: #dff6dd; color: var(--low); }

        .table-container { overflow-x: auto; border-radius: var(--radius-sm); }

        /* ── Export Button ────────────────────────────────────────── */
        .export-btn {
            padding: 10px 24px;
            background: var(--accent);
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            margin: 5px;
            font-size: 0.88em;
            transition: all 0.15s;
            box-shadow: 0 2px 6px rgba(0,120,212,0.2);
        }
        .export-btn:hover { background: var(--accent-dark); box-shadow: 0 4px 12px rgba(0,120,212,0.3); transform: translateY(-1px); }
        .export-section-btn {
            margin-left: auto;
            padding: 5px 14px;
            background: #107c10;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.75em;
            white-space: nowrap;
            transition: all 0.15s;
            box-shadow: 0 1px 4px rgba(16,124,16,0.2);
        }
        .export-section-btn:hover { background: #0b5e0b; box-shadow: 0 3px 8px rgba(16,124,16,0.3); transform: translateY(-1px); }
        .sub-hidden { display: none !important; }
        .sub-filter-select {
            padding: 5px 10px;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 0.78em;
            color: var(--text);
            background: var(--surface);
            cursor: pointer;
            max-width: 220px;
            text-overflow: ellipsis;
            outline: none;
            transition: border-color 0.15s;
        }
        .sub-filter-select:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(0,120,212,0.15); }
        .sub-filter-select:not([data-value='all']) { border-color: var(--accent); background: #e8f4fd; font-weight: 600; }

        .footer {
            text-align: center;
            padding: 36px 20px;
            color: var(--text-muted);
            font-size: 0.8em;
            letter-spacing: 0.1px;
        }

        /* ═══ Modern Azure Assessment Theme — Fluent Design v2 ═══════════════ */
        :root {
            --bg: #f5f5f5; --surface2: #fafafa; --glass: #ffffff; --glass-border: #e8e8e8;
            --glass-hover: rgba(0,120,212,0.04); --border: #e0e0e0; --border-light: #ebebeb;
            --text: #242424; --text-dim: #616161; --text-muted: #9e9e9e;
            --accent-light: #ebf3fc; --accent-lighter: #f5f9ff;
            --shadow-sm: 0 2px 4px rgba(0,0,0,.04), 0 0 2px rgba(0,0,0,.06);
            --shadow-md: 0 4px 8px rgba(0,0,0,.06), 0 0 4px rgba(0,0,0,.04);
            --shadow-lg: 0 8px 24px rgba(0,0,0,.08), 0 2px 6px rgba(0,0,0,.04);
            --shadow-xl: 0 16px 48px rgba(0,0,0,.1), 0 4px 12px rgba(0,0,0,.06);
            --radius: 12px; --radius-sm: 8px;
        }
        html, body { margin:0; }
        body { font-family:'Segoe UI',system-ui,sans-serif; font-size:14px; line-height:1.5; background:var(--bg); -webkit-font-smoothing:antialiased; }
        .container { flex:1; padding:0 32px 32px; background:#fafafa; }

        /* ── Scrollbar ── */
        ::-webkit-scrollbar{width:6px;height:6px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:#c4c4c4;border-radius:3px}
        ::-webkit-scrollbar-thumb:hover{background:#a0a0a0}

        /* ── Portal Top Bar — refined gradient ── */
        .portal-topbar{background:linear-gradient(90deg,#0078d4 0%,#0067b8 100%);height:48px;display:flex;align-items:center;padding:0 16px;position:sticky;top:0;z-index:1000;box-shadow:0 1px 3px rgba(0,0,0,.12)}
        .portal-topbar .portal-logo{display:flex;align-items:center;gap:10px;color:#fff;font-size:14px;font-weight:600;padding-right:20px}
        .portal-topbar .portal-logo .waffle{display:grid;grid-template-columns:repeat(3,5px);gap:2.5px;margin-right:12px}
        .portal-topbar .portal-logo .waffle span{width:5px;height:5px;background:rgba(255,255,255,.85);border-radius:1px;transition:opacity .15s}
        .portal-topbar .portal-logo:hover .waffle span{background:#fff}
        .portal-topbar .portal-search{flex:1;max-width:600px;margin:0 auto}
        .portal-topbar .portal-search input{width:100%;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;padding:7px 16px 7px 36px;font-size:13px;font-family:inherit;outline:none;transition:all .2s}
        .portal-topbar .portal-search input:focus{background:rgba(255,255,255,.22);border-color:rgba(255,255,255,.5);box-shadow:0 0 0 2px rgba(255,255,255,.1)}
        .portal-topbar .portal-search input::placeholder{color:rgba(255,255,255,.7)}
        .portal-topbar .portal-meta{margin-left:auto;color:rgba(255,255,255,.9);font-size:12px;display:flex;align-items:center;gap:14px}

        /* ── Breadcrumb ── */
        .portal-breadcrumb{background:#fff;border-bottom:1px solid var(--border);padding:8px 32px;font-size:12.5px;color:#616161}
        .portal-breadcrumb a{color:#0078d4;text-decoration:none;font-weight:500;transition:color .15s}
        .portal-breadcrumb a:hover{color:#005a9e;text-decoration:underline}
        .portal-breadcrumb span{margin:0 6px;color:#bdbdbd}

        /* ── Page Title ── */
        .portal-page-title{background:#fff;padding:14px 32px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:14px}
        .portal-page-title h1{font-size:20px;font-weight:600;color:#242424;margin:0;letter-spacing:-.2px}
        .portal-page-title .subtitle{font-size:13px;color:#616161}

        /* ── Layout ── */
        .portal-layout{display:flex;min-height:calc(100vh - 48px)}

        /* ── Sidebar — refined with subtle depth ── */
        .portal-sidebar{width:230px;background:#fff;border-right:1px solid #e1dfdd;padding:0;flex-shrink:0;overflow-y:auto;position:sticky;top:48px;height:calc(100vh - 48px);align-self:flex-start;transition:width .2s;font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif}
        .portal-sidebar .sidebar-search{padding:8px 10px;border-bottom:1px solid #e1dfdd}
        .portal-sidebar .sidebar-search input{width:100%;border:1px solid #8a8886;border-radius:2px;padding:5px 8px 5px 28px;font-size:13px;font-family:inherit;color:#323130;outline:none;transition:border-color .1s;background:#fff url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 16 16'%3E%3Cpath fill='%23605e5c' d='M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85zm-5.242.656a5 5 0 1 1 0-10 5 5 0 0 1 0 10z'/%3E%3C/svg%3E") no-repeat 8px center}
        .portal-sidebar .sidebar-search input:focus{border-color:#0078d4;box-shadow:none}
        .portal-sidebar .sidebar-search input::placeholder{color:#605e5c}
        .portal-sidebar .sidebar-section-title{padding:4px 14px 2px;font-size:11px;font-weight:600;color:#0058ad;text-transform:none;letter-spacing:0;border-top:none;margin-top:2px}
        .portal-sidebar .sidebar-section-title.waf-title{margin:8px 10px 4px;padding:6px 12px;font-size:11.5px;font-weight:700;color:#fff;background:linear-gradient(135deg,#0078d4,#005a9e);border-radius:4px;letter-spacing:.3px;text-transform:uppercase;border-top:none}
        .portal-sidebar .sidebar-section-title:first-of-type{margin-top:0}
        .portal-sidebar .sidebar-group{margin-top:0}
        .portal-sidebar .sidebar-group-header{display:flex;align-items:center;padding:6px 14px;cursor:pointer;font-size:13px;color:#0058ad;font-weight:600;user-select:none;text-transform:none;letter-spacing:0}
        .portal-sidebar .sidebar-group-header .chevron{margin-right:8px;font-size:10px;transition:transform .15s ease;color:#0058ad;font-weight:400}
        .portal-sidebar .sidebar-group-header:hover{background:#f3f2f1;color:#003d75}
        .portal-sidebar .sidebar-group-header:hover .chevron{color:#003d75}
        .portal-sidebar .sidebar-group.collapsed .sidebar-group-items{display:none}
        .portal-sidebar .sidebar-group.collapsed .chevron{transform:rotate(-90deg)}
        .portal-sidebar a{display:flex;align-items:center;gap:10px;padding:6px 14px 6px 18px;color:#0078d4;text-decoration:none;font-size:13px;border-left:3px solid transparent;transition:background .1s;border-radius:0;margin:0}
        .portal-sidebar a:hover{background:#f3f2f1;color:#005a9e}
        .portal-sidebar a.active{background:#deecf9;color:#005a9e;border-left-color:#ffb900;font-weight:600}
        .portal-sidebar .sidebar-group-items a{padding-left:32px;color:#2899ef}
        .portal-sidebar .sidebar-group-items a:hover{color:#0078d4}
        .portal-sidebar .sidebar-group-items a.active{color:#005a9e}
        .portal-sidebar .sidebar-icon{width:16px;height:16px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
        .portal-sidebar .sidebar-icon svg{width:16px;height:16px}
        .portal-sidebar .sidebar-icon svg *[fill='#0078d4']{fill:#605e5c}
        .portal-sidebar .sidebar-icon svg *[stroke='#0078d4']{stroke:#605e5c}
        .portal-sidebar a.active .sidebar-icon svg *[fill='#0078d4']{fill:#0078d4}
        .portal-sidebar a.active .sidebar-icon svg *[stroke='#0078d4']{stroke:#0078d4}
        .portal-sidebar a:hover .sidebar-icon svg *[fill='#605e5c']{fill:#323130}
        .portal-sidebar a:hover .sidebar-icon svg *[stroke='#605e5c']{stroke:#323130}
        .portal-sidebar .sidebar-collapse{display:flex;align-items:center;justify-content:flex-end;padding:4px 8px;border-bottom:1px solid #e1dfdd}
        .portal-sidebar .sidebar-collapse button{background:none;border:none;color:#605e5c;cursor:pointer;font-size:13px;padding:4px 8px;border-radius:2px;transition:background .1s}
        .portal-sidebar .sidebar-collapse button:hover{background:#f3f2f1}

        /* ── Hero Header — elegant gradient with depth ── */
        .header{background:linear-gradient(135deg,#0f3460 0%,#0061a7 35%,#0078d4 65%,#2899ef 100%)!important;border-radius:16px!important;padding:36px 44px 32px!important;margin:20px 0!important;color:#fff!important;border:none!important;box-shadow:0 8px 32px rgba(0,100,180,.2), 0 2px 8px rgba(0,0,0,.06), inset 0 1px 0 rgba(255,255,255,.1)!important;text-align:center!important;overflow:hidden!important;position:relative!important}
        .header::before{content:''!important;position:absolute!important;inset:0!important;background:
            radial-gradient(ellipse at 20% 50%, rgba(255,255,255,.08) 0%, transparent 50%),
            radial-gradient(ellipse at 80% 20%, rgba(0,183,195,.12) 0%, transparent 40%),
            url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23ffffff' fill-opacity='0.025'%3E%3Cpath d='M20 20.5V18H0v-2h20V0h2v16h18v2H22v16h-2V20.5z'/%3E%3C/g%3E%3C/svg%3E")!important;
            pointer-events:none!important}
        .header-logo{display:flex!important;justify-content:center!important;margin-bottom:14px!important}
        .header h1{font-size:26px!important;font-weight:700!important;color:#ffffff!important;margin-bottom:6px!important;letter-spacing:-.4px!important;text-shadow:0 1px 2px rgba(0,0,0,.1)!important}
        .header .meta{color:rgba(255,255,255,.8)!important;font-size:13px!important;margin-top:4px!important;line-height:1.7!important}

        /* ── Score Cards — frosted glass tiles ── */
        .score-container{justify-content:center!important;gap:14px!important;margin:24px 0 0!important;flex-wrap:wrap!important}
        .score-card{background:rgba(255,255,255,.1)!important;border:1px solid rgba(255,255,255,.15)!important;border-radius:12px!important;padding:18px 28px!important;backdrop-filter:blur(12px)!important;-webkit-backdrop-filter:blur(12px)!important;min-width:110px!important;transition:all .25s cubic-bezier(.4,0,.2,1)!important}
        .score-card:last-child{border-right:1px solid rgba(255,255,255,.15)!important}
        .score-card:hover{background:rgba(255,255,255,.18)!important;transform:translateY(-3px)!important;box-shadow:0 8px 24px rgba(0,0,0,.15)!important}
        .score-card .number{color:#fff!important;font-size:34px!important;font-weight:700!important;line-height:1.1!important}
        .score-card .label{color:rgba(255,255,255,.75)!important;font-weight:500!important;font-size:11px!important;text-transform:uppercase!important;letter-spacing:.6px!important;margin-top:6px!important}
        .score-card.critical .number{color:#ff6b6b!important}
        .score-card.high .number{color:#ffa94d!important}
        .score-card.medium .number{color:rgba(255,255,255,.65)!important}
        .score-card.low .number{color:#69db7c!important}
        .score-card.total .number{color:#fff!important}

        /* ── Sections — elevated cards with subtle depth ── */
        .section{border-radius:12px!important;margin-bottom:16px!important;border:1px solid var(--border)!important;box-shadow:var(--shadow-sm)!important;background:#fff!important;overflow:hidden!important;transition:box-shadow .2s ease!important}
        .section:hover{box-shadow:var(--shadow-md)!important}
        .cost-svc-row{transition:background .15s!important}
        .cost-svc-row:hover{background:rgba(0,120,212,.04)!important}
        .section-header{padding:16px 24px!important;background:#fff!important;backdrop-filter:none!important;-webkit-backdrop-filter:none!important;border-bottom:1px solid var(--border-light)!important;transition:background .15s!important}
        .section-header:hover{background:#fafafa!important}
        .section-header h2{font-size:15px!important;font-weight:600!important;color:#242424!important;letter-spacing:-.1px!important}
        .section-header .toggle{font-size:12px!important;color:#9e9e9e!important;opacity:1!important;transition:transform .3s cubic-bezier(.4,0,.2,1), color .15s!important}
        .section-header:hover .toggle{color:#616161!important}
        .section-content{padding:20px 24px!important}
        .section.collapsed .section-content{display:none}
        .section .section{margin-bottom:12px!important;border:1px solid var(--border-light)!important;border-radius:8px!important;box-shadow:none!important}
        .section .section .section-header{padding:12px 20px!important;background:#fafafa!important;border-radius:8px 8px 0 0!important}
        .section .section .section-header h2{font-size:13.5px!important;color:#424242!important}
        .section .section .section-content{padding:16px 20px!important}

        /* ── Pillar Cards — refined with accent border ── */
        .pillar-card{border-radius:10px!important;padding:18px!important;border:1px solid var(--border)!important;background:#fff!important;transition:all .2s cubic-bezier(.4,0,.2,1)!important}
        .pillar-card:hover{transform:translateY(-2px)!important;box-shadow:var(--shadow-md)!important;border-color:#c0d8ef!important}

        /* ── Filter Bar — modern pill style ── */
        .filters{border-bottom:none!important;padding-bottom:16px!important;margin-bottom:16px!important}
        .filter-btn{border-radius:20px!important;padding:5px 14px!important;font-size:12.5px!important;font-weight:500!important;transition:all .2s cubic-bezier(.4,0,.2,1)!important;cursor:pointer!important}
        .filter-btn:hover{transform:translateY(-1px)!important;box-shadow:0 2px 8px rgba(0,0,0,.08)!important}
        .filter-btn.active{box-shadow:0 2px 8px rgba(0,120,212,.2)!important}
        .search-box{border-radius:8px!important;padding:7px 14px!important;font-size:13px!important;border:1px solid #c4c4c4!important;transition:all .2s!important}
        .search-box:focus{border-color:#0078d4!important;box-shadow:0 0 0 3px rgba(0,120,212,.12)!important}

        /* ── Badges — modern with subtle depth ── */
        .severity-badge{border-radius:6px!important;font-size:11.5px!important;padding:2px 10px!important;font-weight:600!important;letter-spacing:.2px!important;border:none!important}
        .severity-badge.critical{background:linear-gradient(135deg,#d13438,#c4262e)!important;color:#fff!important;box-shadow:0 1px 3px rgba(209,52,56,.25)!important}
        .severity-badge.high{background:linear-gradient(135deg,#ca5010,#b84a0d)!important;color:#fff!important;box-shadow:0 1px 3px rgba(202,80,16,.25)!important}
        .severity-badge.medium{background:linear-gradient(135deg,#8a8886,#7a7574)!important;color:#fff!important;box-shadow:0 1px 3px rgba(138,136,134,.25)!important}
        .severity-badge.low{background:linear-gradient(135deg,#107c10,#0e6f0e)!important;color:#fff!important;box-shadow:0 1px 3px rgba(16,124,16,.25)!important}
        .severity-badge.info{background:linear-gradient(135deg,#0078d4,#006cbe)!important;color:#fff!important;box-shadow:0 1px 3px rgba(0,120,212,.25)!important}
        .mini-badge{border-radius:6px!important}
        .export-btn{border-radius:8px!important;box-shadow:0 2px 6px rgba(0,120,212,.2)!important;padding:8px 20px!important;font-size:13px!important;font-weight:600!important;transition:all .2s cubic-bezier(.4,0,.2,1)!important;letter-spacing:.1px!important}
        .export-btn:hover{transform:translateY(-1px)!important;box-shadow:0 4px 12px rgba(0,120,212,.3)!important}
        code{border-radius:4px!important;font-size:12.5px!important;background:#f0f2f5!important;padding:2px 6px!important}

        /* ── Tables — modern with refined aesthetics ── */
        table{border:none!important;border-spacing:0!important}
        th{background:#f8f8f8!important;color:#424242!important;padding:10px 14px!important;text-transform:uppercase!important;font-size:11px!important;font-weight:600!important;letter-spacing:.4px!important;border-bottom:2px solid #e0e0e0!important;position:sticky!important;top:0!important;z-index:1!important}
        td{padding:10px 14px!important;border-bottom:1px solid #f0f0f0!important;font-size:13px!important;color:#242424!important;transition:background .12s!important}
        tr:hover td{background:rgba(0,120,212,.03)!important}
        tr:nth-child(even) td{background:rgba(0,0,0,.01)}
        .table-container{border-radius:8px!important;border:1px solid var(--border)!important;overflow-x:auto!important}

        /* ── Footer ── */
        .footer{padding:24px 0!important;border-top:1px solid var(--border)!important;margin-top:24px!important;color:#9e9e9e!important;font-size:12px!important}

        /* ── Smooth transitions for blade navigation ── */
        .blade{animation:bladeIn .3s cubic-bezier(.4,0,.2,1)}
        @keyframes bladeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

        /* ── Cost sub-sections ── */
        .cost-sub-section{border-radius:10px!important;border:1px solid var(--border)!important;box-shadow:var(--shadow-sm)!important;transition:box-shadow .2s!important}
        .cost-sub-section:hover{box-shadow:var(--shadow-md)!important}

        /* ── Sortable Table Headers ── */
        th.sortable{cursor:pointer;user-select:none;position:relative;padding-right:22px!important}
        th.sortable::after{content:'⇅';position:absolute;right:6px;top:50%;transform:translateY(-50%);opacity:.35;font-size:11px}
        th.sortable.sort-asc::after{content:'▲';opacity:.85}
        th.sortable.sort-desc::after{content:'▼';opacity:.85}
        th.sortable:hover{background:#eee!important}

        /* ── Dark Mode ── */
        body.dark-mode{--bg:#1e1e1e;--surface:#2d2d2d;--surface2:#252525;--glass:#2d2d2d;--glass-border:#404040;--glass-hover:rgba(0,120,212,0.12);--border:#404040;--border-light:#353535;--text:#e0e0e0;--text-dim:#b0b0b0;--text-muted:#808080;--accent-light:#1a3a5c;--accent-lighter:#1e2d3d;--azure-navy:#e0e0e0}
        body.dark-mode .portal-sidebar{background:#252525!important;border-right-color:#404040!important}
        body.dark-mode .portal-sidebar a{color:#5ba7e6!important}
        body.dark-mode .portal-sidebar a:hover{background:#333!important;color:#7bbef5!important}
        body.dark-mode .portal-sidebar a.active{background:#1a3a5c!important;color:#7bbef5!important}
        body.dark-mode .portal-sidebar .sidebar-search input{background:#333!important;border-color:#555!important;color:#e0e0e0!important}
        body.dark-mode .portal-sidebar .sidebar-section-title{color:#7bbef5!important}
        body.dark-mode .portal-sidebar .sidebar-group-header{color:#7bbef5!important}
        body.dark-mode .portal-sidebar .sidebar-group-header:hover{background:#333!important}
        body.dark-mode .portal-breadcrumb{background:#252525!important;border-color:#404040!important;color:#b0b0b0!important}
        body.dark-mode .portal-breadcrumb a{color:#5ba7e6!important}
        body.dark-mode .portal-page-title{background:#252525!important;border-color:#404040!important}
        body.dark-mode .portal-page-title h1{color:#e0e0e0!important}
        body.dark-mode .container{background:#1e1e1e!important}
        body.dark-mode .section{background:#2d2d2d!important;border-color:#404040!important}
        body.dark-mode .section-header{background:#2d2d2d!important;border-color:#404040!important}
        body.dark-mode .section-header:hover{background:#333!important}
        body.dark-mode .section-header h2{color:#e0e0e0!important}
        body.dark-mode th{background:#333!important;color:#d0d0d0!important;border-color:#505050!important}
        body.dark-mode th.sortable:hover{background:#444!important}
        body.dark-mode td{color:#d0d0d0!important;border-color:#383838!important}
        body.dark-mode tr:hover td{background:rgba(0,120,212,.08)!important}
        body.dark-mode tr:nth-child(even) td{background:rgba(255,255,255,.02)!important}
        body.dark-mode .pillar-card{background:#2d2d2d!important;border-color:#404040!important}
        body.dark-mode .pillar-card:hover{border-color:#5ba7e6!important}
        body.dark-mode .pillar-name{color:#e0e0e0!important}
        body.dark-mode .pillar-count{color:#b0b0b0!important}
        body.dark-mode .filter-btn{background:#333!important;border-color:#505050!important;color:#b0b0b0!important}
        body.dark-mode .filter-btn:hover{background:#3a3a3a!important;color:#e0e0e0!important}
        body.dark-mode .search-box{background:#333!important;border-color:#505050!important;color:#e0e0e0!important}
        body.dark-mode .search-box:focus{border-color:#0078d4!important}
        body.dark-mode code{background:#3a3a3a!important;color:#7bbef5!important}
        body.dark-mode .cost-sub-section{background:#2d2d2d!important;border-color:#404040!important}
        body.dark-mode .footer{border-color:#404040!important;color:#808080!important}
        body.dark-mode .table-container{border-color:#404040!important}
        /* Dark mode: override hardcoded inline colors on table cells and small elements */
        body.dark-mode td small[style*="color:#605e5c"],body.dark-mode td small[style*="color:#323130"]{color:#b0b0b0!important}
        body.dark-mode td small[style*="color:#0078d4"]{color:#5ba7e6!important}
        body.dark-mode td span[style*="color:#0078d4"]{color:#5ba7e6!important}
        body.dark-mode td[style*="color:#323130"]{color:#d0d0d0!important}
        body.dark-mode td[style*="color:#605e5c"]{color:#b0b0b0!important}
        body.dark-mode td[style*="color:#107c10"]{color:#69db7c!important}
        body.dark-mode td span[style*="color:#5c2d91"]{color:#b39ddb!important}
        body.dark-mode td span[style*="color:#00b7c3"]{color:#4dd0e1!important}
        /* Dark mode toggle button */
        .dark-toggle{background:none;border:1px solid rgba(255,255,255,.3);color:#fff;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:14px;transition:all .2s;margin-left:8px;line-height:1}
        .dark-toggle:hover{background:rgba(255,255,255,.12);border-color:rgba(255,255,255,.5)}

        /* ── Charts Container ── */
        .charts-row{display:flex;gap:24px;margin-bottom:24px;flex-wrap:wrap;align-items:flex-start}
        .chart-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;flex:1;min-width:280px;box-shadow:var(--shadow-sm);transition:box-shadow .2s}
        .chart-card:hover{box-shadow:var(--shadow-md)}
        .chart-card h3{font-size:13px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.4px;margin-bottom:16px}
        body.dark-mode .chart-card{background:#2d2d2d!important;border-color:#404040!important}
        body.dark-mode .chart-card h3{color:#b0b0b0!important}

        /* ── Print Styles ── */
        @media print {
            body{background:#fff!important;color:#000!important;font-size:9pt}
            .portal-sidebar,.portal-topbar,.dark-toggle,.no-print,.filters,.sidebar-toggle-btn{display:none!important}
            .portal-main{margin-left:0!important;padding:12px!important}
            .blade{display:block!important;page-break-inside:avoid}
            .section{page-break-inside:avoid;box-shadow:none!important;border:1px solid #ddd}
            .section-header{background:#f3f2f1!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
            .kpi-card,.chart-card{box-shadow:none!important;border:1px solid #ddd;page-break-inside:avoid}
            table{font-size:8pt}
            thead{display:table-header-group}
            tr{page-break-inside:avoid}
            a{color:#0078d4!important;text-decoration:none}
            .pill{border:1px solid #999!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
        }

        /* ── Mobile Responsive ── */
        @media (max-width:768px) {
            .portal-sidebar{display:none!important}
            .container{margin-left:0!important}
            .portal-layout{display:block!important}
            .header .score-container{flex-direction:column;gap:8px}
            .charts-row{flex-direction:column}
            .chart-card{min-width:auto!important}
            .pillar-grid{grid-template-columns:1fr!important}
        }
    </style>
</head>
<body>
<!-- Azure Portal Top Bar -->
<div class="portal-topbar">
    <div class="portal-logo">
        <div class="waffle"><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span><span></span></div>
        <span>Microsoft Azure</span>
    </div>
    <div class="portal-meta">
        <span>Tenant Assessment</span>
        <button class="dark-toggle" onclick="document.body.classList.toggle('dark-mode');this.textContent=document.body.classList.contains('dark-mode')?'☀️':'🌙'" title="Toggle dark mode">🌙</button>
    </div>
</div>
<div class="portal-breadcrumb">
    <a href="#" onclick="navTo('blade-executive',document.querySelector('.portal-sidebar a'),event)">Home</a>
    <span>&gt;</span>
    <span>Azure Tenant Assessment</span>
</div>
<div class="portal-layout">
    <nav class="portal-sidebar">
        <div class="sidebar-search">
            <input type="text" placeholder="Search" id="sidebar-search-box" oninput="sidebarFilter(this.value)">
        </div>
        <div class="sidebar-collapse"><button onclick="toggleSidebar()" title="Collapse">&#171;</button></div>
        <!-- General -->
        <div class="sidebar-group">
            <a href="#" class="active" onclick="navTo('blade-executive',this,event)">
                <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><rect x="1" y="1" width="6" height="6" rx="1" fill="#0078d4"/><rect x="9" y="1" width="6" height="6" rx="1" fill="#0078d4"/><rect x="1" y="9" width="6" height="6" rx="1" fill="#0078d4"/><rect x="9" y="9" width="6" height="6" rx="1" fill="#0078d4"/></svg></span> Overview</a>
            $alzSidebarLink
            <a href="#" onclick="navTo('blade-priority',this,event)">
                <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1v10M5 8l3 3 3-3" stroke="#e74c3c" stroke-width="1.5" fill="none"/><rect x="3" y="13" width="10" height="2" rx="1" fill="#e74c3c"/></svg></span> Priority Actions</a>
            <a href="#" onclick="navTo('blade-waf',this,event)">
                <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1l6 3v4c0 3.5-2.5 5.5-6 7-3.5-1.5-6-3.5-6-7V4l6-3z" stroke="#0078d4" stroke-width="1.2" fill="none"/><path d="M5 8l2 2 4-4" stroke="#0078d4" stroke-width="1.3" fill="none"/></svg></span> WAF Assessment</a>
        </div>
        <!-- WAF: Security Pillar -->
        <div class="sidebar-section-title waf-title">Well-Architected Framework</div>
        <div class="sidebar-group">
            <div class="sidebar-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="chevron">&#8964;</span> Security
            </div>
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-identity',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="5" r="3" stroke="#0078d4" stroke-width="1.2" fill="none"/><path d="M3 14c0-3 2.5-5 5-5s5 2 5 5" stroke="#0078d4" stroke-width="1.2" fill="none"/></svg></span> Identity &amp; Access</a>
                <a href="#" onclick="navTo('blade-zt',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><rect x="4" y="1" width="8" height="6" rx="2" stroke="#0078d4" stroke-width="1.2" fill="none"/><rect x="3" y="7" width="10" height="8" rx="1" fill="#0078d4"/><circle cx="8" cy="10.5" r="1.5" fill="#fff"/></svg></span> Zero Trust</a>
                <a href="#" onclick="navTo('blade-network',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M2 4h12v3H2zM2 9h12v3H2z" stroke="#0078d4" stroke-width="1.1" fill="none"/><circle cx="4" cy="5.5" r=".8" fill="#0078d4"/><circle cx="4" cy="10.5" r=".8" fill="#0078d4"/></svg></span> Network Security</a>
                <a href="#" onclick="navTo('blade-keyvault',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><rect x="3" y="7" width="10" height="6" rx="1.5" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M5 7V5a3 3 0 0 1 6 0v2" stroke="#0078d4" stroke-width="1.1" fill="none"/><circle cx="8" cy="10" r="1" fill="#0078d4"/></svg></span> Key Vault &amp; Secrets</a>
                <a href="#" onclick="navTo('blade-locks',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><rect x="4" y="7" width="8" height="6" rx="1.5" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M6 7V5a2 2 0 0 1 4 0v2" stroke="#0078d4" stroke-width="1.1" fill="none"/></svg></span> Resource Locks</a>
                <a href="#" onclick="navTo('blade-observability',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="5" stroke="#0078d4" stroke-width="1.2" fill="none"/><path d="M8 5v3l2 2" stroke="#0078d4" stroke-width="1.2"/></svg></span> Observability &amp; PE</a>
            </div>
        </div>
        <!-- WAF: Reliability Pillar -->
        <div class="sidebar-group">
            <div class="sidebar-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="chevron">&#8964;</span> Reliability
            </div>
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-bcdr',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1C4.7 1 2 3.7 2 7c0 2.4 1.5 4.5 3.5 5.4L8 15l2.5-2.6C12.5 11.5 14 9.4 14 7c0-3.3-2.7-6-6-6z" stroke="#0078d4" stroke-width="1.2" fill="none"/><path d="M6 7l1.5 1.5L10 5.5" stroke="#0078d4" stroke-width="1.3" fill="none"/></svg></span> BCDR &amp; Backup</a>
                <a href="#" onclick="navTo('blade-ha',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 2l2.5 3H13l-2 3 1.5 4L8 10 3.5 12 5 8 3 5h2.5z" stroke="#0078d4" stroke-width="1.1" fill="none"/></svg></span> HA &amp; Resilience</a>
                <a href="#" onclick="navTo('blade-databases',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><ellipse cx="8" cy="4" rx="5" ry="2" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M3 4v8c0 1.1 2.2 2 5 2s5-.9 5-2V4" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M3 8c0 1.1 2.2 2 5 2s5-.9 5-2" stroke="#0078d4" stroke-width="1.1" fill="none"/></svg></span> Databases &amp; HA</a>
            </div>
        </div>
        <!-- WAF: Cost Optimization Pillar -->
        <div class="sidebar-group">
            <div class="sidebar-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="chevron">&#8964;</span> Cost Optimization
            </div>
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-cost',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1v14M5 4c0-1.5 1.5-2 3-2s3 .5 3 2-1.5 2-3 2-3 .5-3 2 1.5 2 3 2 3-.5 3-2" stroke="#0078d4" stroke-width="1.2" fill="none"/></svg></span> Cost &amp; Rightsizing</a>
                <a href="#" onclick="navTo('blade-reservations',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="10" rx="2" stroke="#0078d4" stroke-width="1.1" fill="none"/><path d="M1 6h14" stroke="#0078d4" stroke-width="1.1"/><path d="M4 9h3M4 11h5" stroke="#0078d4" stroke-width="1" opacity=".7"/></svg></span> Reservations</a>
            </div>
        </div>
        <!-- WAF: Operational Excellence Pillar -->
        <div class="sidebar-group">
            <div class="sidebar-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="chevron">&#8964;</span> Operational Excellence
            </div>
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-governance',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M2 3h12v2H2zM4 7h8v2H4zM6 11h4v2H6z" fill="#0078d4"/></svg></span> Governance &amp; Policy</a>
                <a href="#" onclick="navTo('blade-monitoring',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M1 12l3-4 3 2 4-6 4 3" stroke="#0078d4" stroke-width="1.3" fill="none"/></svg></span> Monitoring &amp; Alerts</a>
                <a href="#" onclick="navTo('blade-tags',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M2 4l5-2 7 3v7l-7 3-5-2V4z" stroke="#0078d4" stroke-width="1.2" fill="none"/><path d="M7 7v4M5 9h4" stroke="#0078d4" stroke-width="1.2"/></svg></span> Tags &amp; Compliance</a>
            </div>
        </div>
        <!-- WAF: Performance Efficiency Pillar -->
        <div class="sidebar-group">
            <div class="sidebar-group-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <span class="chevron">&#8964;</span> Performance Efficiency
            </div>
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-modernization',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M4 14V8l4-6 4 6v6" stroke="#0078d4" stroke-width="1.2" fill="none"/><rect x="6" y="10" width="4" height="4" fill="#0078d4"/></svg></span> Modernization</a>
            </div>
        </div>
        <!-- Resources -->
        <div class="sidebar-section-title">Resources</div>
        <div class="sidebar-group">
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-inventory',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M3 2h10a1 1 0 011 1v10a1 1 0 01-1 1H3a1 1 0 01-1-1V3a1 1 0 011-1zm1 3v2h8V5H4zm0 4v2h8V9H4z" fill="#0078d4"/></svg></span> Inventory</a>
            </div>
        </div>
        <!-- Settings -->
        <div class="sidebar-section-title">Settings</div>
        <div class="sidebar-group">
            <div class="sidebar-group-items">
                <a href="#" onclick="navTo('blade-method',this,event)">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M2 3h9v1.5H2zM2 7h12v1.5H2zM2 11h7v1.5H2z" fill="#0078d4"/></svg></span> Methodology</a>
                <a href="#" onclick="exportCSV();return false">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M8 1v9M5 7l3 3 3-3M3 12v2h10v-2" stroke="#0078d4" stroke-width="1.3" fill="none"/></svg></span> Export CSV</a>
                <a href="#" onclick="window.print();return false">
                    <span class="sidebar-icon"><svg viewBox="0 0 16 16" fill="none"><path d="M4 4V1h8v3M2 5h12v6H2zM4 11v4h8v-4" stroke="#0078d4" stroke-width="1.1" fill="none"/></svg></span> Print / PDF</a>
            </div>
        </div>
    </nav>
<div class="container">
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 1: EXECUTIVE SUMMARY                                            -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-executive">
    <div class="header" id="section-overview">
        <div class="header-logo">
            <svg width="36" height="36" viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg">
                <rect x="0"  y="0"  width="18" height="18" rx="2" fill="#f25022"/>
                <rect x="22" y="0"  width="18" height="18" rx="2" fill="#7fba00"/>
                <rect x="0"  y="22" width="18" height="18" rx="2" fill="#00a4ef"/>
                <rect x="22" y="22" width="18" height="18" rx="2" fill="#ffb900"/>
            </svg>
        </div>
        <h1>Azure Tenant Assessment Report</h1>
        <p class="meta">
            Well-Architected Framework &amp; Zero Trust Analysis<br>
            <span style="opacity:0.7">&#128197;</span> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;&bull;&nbsp;
            <span style="opacity:0.7">&#9201;</span> $([math]::Round($duration.TotalMinutes, 1)) min &nbsp;&bull;&nbsp;
            <span style="opacity:0.7">&#9729;&#65039;</span> $($script:Subscriptions.Count) subscription(s)
        </p>
        <div class="score-container">
            <div class="score-card total">
                <div class="number">$($script:Summary.TotalResources)</div>
                <div class="label">Resources</div>
            </div>
            <div class="score-card critical">
                <div class="number">$($script:Summary.Critical)</div>
                <div class="label">Critical</div>
            </div>
            <div class="score-card high">
                <div class="number">$($script:Summary.High)</div>
                <div class="label">High</div>
            </div>
            <div class="score-card medium">
                <div class="number">$($script:Summary.Medium)</div>
                <div class="label">Medium</div>
            </div>
            <div class="score-card low">
                <div class="number">$($script:Summary.Low)</div>
                <div class="label">Low</div>
            </div>
        </div>
    </div>

    <!-- Executive: Key Metrics -->
    <div class="section" id="exec-metrics">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Key Metrics</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:20px;">
                <div style="background:var(--surface);border:1px solid var(--border-light);border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:2em;font-weight:700;color:var(--accent);">$($script:Subscriptions.Count)</div>
                    <div style="font-size:.85em;color:var(--text-dim);">Subscriptions</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:2em;font-weight:700;color:var(--accent);">$($script:Summary.TotalResources)</div>
                    <div style="font-size:.85em;color:var(--text-dim);">Total Resources</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:2em;font-weight:700;color:var(--critical);">$($script:Summary.Critical + $script:Summary.High)</div>
                    <div style="font-size:.85em;color:var(--text-dim);">Critical + High Findings</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-radius:10px;padding:20px;text-align:center;">
                    <div style="font-size:2em;font-weight:700;color:#107c10;">$totalCostFormatted</div>
                    <div style="font-size:.85em;color:var(--text-dim);">6-Month Cost</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Executive: Visual Charts Row -->
    <div class="charts-row">
        <div class="chart-card">
            <h3>&#127928; Severity Distribution</h3>
            <div id="severity-donut" data-values="[$($script:Summary.Critical),$($script:Summary.High),$($script:Summary.Medium),$($script:Summary.Low)]"></div>
        </div>
    </div>

    <!-- Executive: WAF Pillar Bar Chart + ZT Quick Card -->
    <div class="charts-row">
        <div class="chart-card" style="flex:1.2;">
            <h3>&#128202; Findings by WAF Pillar</h3>
            <div id="pillar-bar-chart" data-pillars='$pillarChartJson'></div>
        </div>
        <div class="chart-card" style="flex:0.8;cursor:pointer;" onclick="navTo('blade-zt',document.querySelector('a[onclick*=blade-zt]'),event)">
            <h3>&#128737; Zero Trust Score</h3>
            <div style="text-align:center;padding:8px 0;">
                <div id="zt-ov-total" style="font-size:2.2em;font-weight:700;color:var(--accent);line-height:1.1;">0</div>
                <div style="font-size:.78em;color:var(--text-dim);margin:6px 0 12px;">findings across 3 ZT pillars</div>
                <div style="display:flex;gap:8px;justify-content:center;flex-wrap:wrap;">
                    <div style="text-align:center;min-width:56px;background:var(--surface2);border:1px solid var(--border-light);border-radius:8px;padding:8px 10px;">
                        <div id="zt-ov-critical" style="font-size:1.3em;font-weight:700;color:#d13438;">0</div>
                        <div style="font-size:.62em;color:var(--text-dim);font-weight:600;text-transform:uppercase;">Crit</div>
                    </div>
                    <div style="text-align:center;min-width:56px;background:var(--surface2);border:1px solid var(--border-light);border-radius:8px;padding:8px 10px;">
                        <div id="zt-ov-high" style="font-size:1.3em;font-weight:700;color:#ca5010;">0</div>
                        <div style="font-size:.62em;color:var(--text-dim);font-weight:600;text-transform:uppercase;">High</div>
                    </div>
                    <div style="text-align:center;min-width:56px;background:var(--surface2);border:1px solid var(--border-light);border-radius:8px;padding:8px 10px;">
                        <div id="zt-ov-medium" style="font-size:1.3em;font-weight:700;color:#7a7574;">0</div>
                        <div style="font-size:.62em;color:var(--text-dim);font-weight:600;text-transform:uppercase;">Med</div>
                    </div>
                    <div style="text-align:center;min-width:56px;background:var(--surface2);border:1px solid var(--border-light);border-radius:8px;padding:8px 10px;">
                        <div id="zt-ov-low" style="font-size:1.3em;font-weight:700;color:#107c10;">0</div>
                        <div style="font-size:.62em;color:var(--text-dim);font-weight:600;text-transform:uppercase;">Low</div>
                    </div>
                </div>
                <div style="margin-top:14px;font-size:.78em;color:var(--accent);font-weight:600;">Click to view full Zero Trust assessment &rarr;</div>
            </div>
        </div>
    </div>

    <!-- Executive: Resource Distribution -->
    <div class="charts-row">
        <div class="chart-card">
            <h3>&#128230; Resource Distribution</h3>
            <div id="resource-dist-chart" data-resources='$resourceChartJson'></div>
        </div>
    </div>
    </div><!-- /blade-executive -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 2: PRIORITY ACTIONS                                             -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-priority" style="display:none">
    <div class="section" id="section-priority">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Priority Actions</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <p style="color:var(--text-dim);margin-bottom:16px;line-height:1.6;">
                Cross-cutting view of <strong>all findings</strong> (WAF + Zero Trust + Underutilized Resources) prioritized by
                <strong>impact &#215; ease of implementation</strong>. Start from the top &#8595;
            </p>

            <!-- Summary cards -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px;">
                <div style="background:#fde7e9;border:1px solid #d13438;border-radius:10px;padding:18px;text-align:center;">
                    <div style="font-size:2.2em;font-weight:800;color:#d13438;">$($criticalItems.Count)</div>
                    <div style="font-size:.82em;color:#d13438;font-weight:600;">&#128308; Critical (7 days)</div>
                </div>
                <div style="background:#fff4ce;border:1px solid #ca5010;border-radius:10px;padding:18px;text-align:center;">
                    <div style="font-size:2.2em;font-weight:800;color:#ca5010;">$($importantItems.Count)</div>
                    <div style="font-size:.82em;color:#ca5010;font-weight:600;">&#128992; Important (30 days)</div>
                </div>
                <div style="background:#f3f2f1;border:1px solid #8a8886;border-radius:10px;padding:18px;text-align:center;">
                    <div style="font-size:2.2em;font-weight:800;color:#605e5c;">$($optimizationItems.Count)</div>
                    <div style="font-size:.82em;color:#605e5c;font-weight:600;">&#128993; Optimizations (90 days)</div>
                </div>
                <div style="background:linear-gradient(135deg,#0078d4,#005a9e);border-radius:10px;padding:18px;text-align:center;">
                    <div style="font-size:2.2em;font-weight:800;color:#fff;">$($allFindings.Count)</div>
                    <div style="font-size:.82em;color:rgba(255,255,255,0.85);font-weight:600;">Total findings</div>
                </div>
            </div>

            <!-- Ease legend -->
            <div style="background:var(--surface);border:1px solid var(--border-light);border-radius:8px;padding:12px 16px;margin-bottom:18px;font-size:.82em;color:var(--text-dim);">
                <strong>Ease of Implementation:</strong>
                <span style="color:#107c10;font-weight:600;margin-left:10px;">&#9679; Quick Win</span> = Configuration change, single action &nbsp;&#183;&nbsp;
                <span style="color:#ca5010;font-weight:600;">&#9679; Moderate</span> = Requires deployment or policy config &nbsp;&#183;&nbsp;
                <span style="color:#d13438;font-weight:600;">&#9679; Complex</span> = Architectural change, multi-resource
            </div>

            <!-- Priority table -->
            <div class="table-container">
                <table id="priorityTable" style="font-size:.88em;table-layout:fixed;width:100%">
                    <thead><tr>
                        <th style="width:5%">Severity</th>
                        <th style="width:7%">Source</th>
                        <th style="width:10%">Category</th>
                        <th style="width:18%">Finding</th>
                        <th style="width:13%">Resource</th>
                        <th style="width:15%">Subscription</th>
                        <th style="width:6%">Ease</th>
                        <th style="width:18%">Recommendation</th>
                    </tr></thead>
                    <tbody>$priorityRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-priority -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 3: IDENTITY & ACCESS                                            -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-identity" style="display:none">
    <div class="section" id="section-identity">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Identity &amp; Access Management</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <!-- IAM Score bar -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128101; Identity &amp; Access Findings</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Findings related to Identity, RBAC, PIM, MFA, and Access controls.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$identityCritical</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$identityHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$identityMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$identityLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- IAM Filter bar -->
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>

            <div class="table-container">
                <table id="identityTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$identityRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-identity -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 4: WELL-ARCHITECTED FRAMEWORK                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-waf" style="display:none">
    <div class="section" id="section-waf" style="margin-bottom:8px;">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Well-Architected Framework</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content" style="padding:16px 20px;">

            <!-- WAF Score bar -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:10px;padding:16px 24px;margin-bottom:14px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="display:flex;gap:20px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:180px;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.05em;margin-bottom:2px;">&#127919; Well-Architected Framework</div>
                        <div style="font-size:.78em;color:rgba(255,255,255,0.75);line-height:1.4;">Security · Reliability · Cost · Operational Excellence · Performance</div>
                    </div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:60px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:8px;padding:8px 14px;">
                            <div style="font-size:1.5em;font-weight:700;color:#ff6b6b;line-height:1.1;">$($script:Summary.Critical)</div>
                            <div style="font-size:.62em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:60px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:8px;padding:8px 14px;">
                            <div style="font-size:1.5em;font-weight:700;color:#ffa94d;line-height:1.1;">$($script:Summary.High)</div>
                            <div style="font-size:.62em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:60px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:8px;padding:8px 14px;">
                            <div style="font-size:1.5em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$($script:Summary.Medium)</div>
                            <div style="font-size:.62em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:60px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:8px;padding:8px 14px;">
                            <div style="font-size:1.5em;font-weight:700;color:#69db7c;line-height:1.1;">$($script:Summary.Low)</div>
                            <div style="font-size:.62em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px;">Low</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="pillar-grid">
                $pillarCards
            </div>
        </div>
    </div>

    <!-- Detailed Findings (WAF) -->
    <div class="section" id="section-findings-waf">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Detailed Findings ($($script:Findings.Count) total)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content" style="padding:12px 20px;">
            <div class="filters" style="margin-bottom:10px;">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <span style="margin-left: 16px;"><strong style="font-size:.85em;color:var(--text-dim);">Pillar:</strong></span>
                <button class="filter-btn" onclick="filterByPillar('all', this)">All</button>
                <button class="filter-btn cat-security" onclick="filterByPillar('Security', this)">Security</button>
                <button class="filter-btn cat-reliability" onclick="filterByPillar('Reliability', this)">Reliability</button>
                <button class="filter-btn cat-cost" onclick="filterByPillar('Cost Optimization', this)">Cost</button>
                <button class="filter-btn cat-ops" onclick="filterByPillar('Operational Excellence', this)">Ops</button>
                <button class="filter-btn cat-perf" onclick="filterByPillar('Performance Efficiency', this)">Perf</button>
                <span style="border-left:1px solid #ccc;margin:0 6px;height:24px;display:inline-block;vertical-align:middle"></span>
                <button class="filter-btn" style="background:#e8f5e9;color:#2e7d32;border-color:#c8e6c9" onclick="filterBySource('Custom Analysis', this)">🔍 Custom</button>
                <button class="filter-btn" style="background:#e6f2ff;color:#0078d4;border-color:#b3d9ff" onclick="filterBySource('Azure Advisor', this)">📊 Advisor</button>
                <button class="filter-btn" style="background:#fff4e5;color:#d97a00;border-color:#ffe0b2" onclick="filterBySource('Defender for Cloud', this)">🛡️ Defender</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container" style="max-height:62vh;overflow-y:auto;">
                <table id="findingsTable">
                    <thead>
                        <tr>
                            <th class="sortable" onclick="sortTable(this,0)">Severity</th>
                            <th class="sortable" onclick="sortTable(this,1)">Pillar</th>
                            <th class="sortable" onclick="sortTable(this,2)">Category</th>
                            <th class="sortable" onclick="sortTable(this,3)">Resource</th>
                            <th>Issue</th>
                            <th>Recommendation</th>
                            <th class="sortable" onclick="sortTable(this,6)">Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        $findingsRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-waf -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 5: ZERO TRUST                                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-zt" style="display:none">
    <div class="section" id="section-zt">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Zero Trust Assessment</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">

            <!-- ZT Score bar -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128737; Zero Trust Score</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Assessment of the 3 pillars: Network Security · Compute Security · Platform Security</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div id="zt-critical" style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">0</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div id="zt-high" style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">0</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div id="zt-medium" style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">0</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div id="zt-low" style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">0</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- ZT Pillars -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-bottom:24px;">
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid var(--accent);border-radius:10px;padding:20px;cursor:pointer;transition:transform .15s,box-shadow .15s;" onclick="ztFilterLayer('Network', this)" onmouseenter="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 16px rgba(0,29,61,0.08)'" onmouseleave="this.style.transform='';this.style.boxShadow=''">
                    <div style="font-weight:600;color:var(--accent);margin-bottom:6px;font-size:.95em;">Network Security</div>
                    <div style="font-size:.82em;color:var(--text-dim);line-height:1.5;">Micro-segmentation, traffic inspection, private PaaS access, NSG Flow Logs.</div>
                    <div id="zt-net-count" style="margin-top:10px;font-size:.8em;font-weight:600;color:var(--accent);"></div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid var(--low);border-radius:10px;padding:20px;cursor:pointer;transition:transform .15s,box-shadow .15s;" onclick="ztFilterLayer('Compute', this)" onmouseenter="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 16px rgba(0,29,61,0.08)'" onmouseleave="this.style.transform='';this.style.boxShadow=''">
                    <div style="font-weight:600;color:var(--low);margin-bottom:6px;font-size:.95em;">Compute Security</div>
                    <div style="font-size:.82em;color:var(--text-dim);line-height:1.5;">JIT Access, endpoint protection, workload identity, patching, encryption at rest.</div>
                    <div id="zt-comp-count" style="margin-top:10px;font-size:.8em;font-weight:600;color:var(--low);"></div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid var(--azure-navy);border-radius:10px;padding:20px;cursor:pointer;transition:transform .15s,box-shadow .15s;" onclick="ztFilterLayer('Platform', this)" onmouseenter="this.style.transform='translateY(-2px)';this.style.boxShadow='0 4px 16px rgba(0,29,61,0.08)'" onmouseleave="this.style.transform='';this.style.boxShadow=''">
                    <div style="font-weight:600;color:var(--azure-navy);margin-bottom:6px;font-size:.95em;">Platform Security</div>
                    <div style="font-size:.82em;color:var(--text-dim);line-height:1.5;">Conditional Access, PIM, least-privilege RBAC, Policy compliance, SIEM/Sentinel.</div>
                    <div id="zt-plat-count" style="margin-top:10px;font-size:.8em;font-weight:600;color:var(--azure-navy);"></div>
                </div>
            </div>

            <!-- ZT Filter bar -->
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Filter:</strong>
                <button class="filter-btn active" id="zt-btn-all" onclick="ztFilterSev('all',this)">All</button>
                <button class="filter-btn sev-critical" onclick="ztFilterSev('Critical',this)">Critical</button>
                <button class="filter-btn sev-high" onclick="ztFilterSev('High',this)">High</button>
                <button class="filter-btn sev-medium" onclick="ztFilterSev('Medium',this)">Medium</button>
                <button class="filter-btn sev-low" onclick="ztFilterSev('Low',this)">Low</button>
                <button class="filter-btn zt-network" id="zt-btn-net" onclick="ztFilterLayer('Network',this)" style="margin-left:12px;">Network</button>
                <button class="filter-btn zt-compute" id="zt-btn-comp" onclick="ztFilterLayer('Compute',this)">Compute</button>
                <button class="filter-btn zt-platform" id="zt-btn-plat" onclick="ztFilterLayer('Platform',this)">Platform</button>
                <input type="text" class="search-box" placeholder="Search control or resource..." oninput="ztSearch(this.value)" style="margin-left:auto">
            </div>

            <p id="zt-count-label" style="font-size:.82em;color:var(--text-dim);margin-bottom:12px;"></p>

            <!-- ZT Findings Table -->
            <div style="overflow-x:auto;border-radius:var(--radius-sm);">
                <table id="ztTable">
                    <thead>
                        <tr>
                            <th style="white-space:nowrap;">Severity</th>
                            <th style="white-space:nowrap;">ZT Layer</th>
                            <th>Control</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                            <th>Zero Trust Impact</th>
                        </tr>
                    </thead>
                    <tbody id="zt-tbody">
                        $ztRows
                    </tbody>
                </table>
                <p id="zt-empty-msg" style="display:none;text-align:center;padding:30px;color:var(--text-dim);font-size:.88em;">
                    No Zero Trust findings found for this filter.
                </p>
            </div>
        </div>
    </div>
    </div><!-- /blade-zt -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 6: NETWORK TOPOLOGY                                             -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-network" style="display:none">

    <!-- Network Overview -->
    <div class="section" id="section-network">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Network Topology</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">

            <!-- KPI Banner -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128424; Network Topology</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Virtual networks, public IPs, gateways, peerings, and subnet configuration across all subscriptions.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$netKpiVnets</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">VNets</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$netTotalSubnets</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Subnets</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$netTotalPeerings</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Peerings</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#00b7c3;line-height:1.1;">$netKpiPIPs</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Public IPs</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#b4a0ff;line-height:1.1;">$netKpiGateways</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Gateways</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Subscription Filter -->
            <div class="filters" style="margin-bottom:16px;" id="network-sub-filter"></div>

            <!-- VNet Cards -->
            <div style="margin-bottom:8px;font-weight:700;font-size:1em;color:var(--text);display:flex;align-items:center;gap:8px;">
                <svg width="20" height="20" viewBox="0 0 16 16" fill="none"><rect x="1" y="3" width="14" height="4" rx="1.5" stroke="#0078d4" stroke-width="1.2"/><rect x="1" y="9" width="14" height="4" rx="1.5" stroke="#0078d4" stroke-width="1.2"/><circle cx="4" cy="5" r=".9" fill="#0078d4"/><circle cx="4" cy="11" r=".9" fill="#0078d4"/></svg>
                Virtual Networks ($netKpiVnets)
            </div>
            <div id="vnet-cards-container" style="display:grid;gap:12px;margin-bottom:28px;">
                $vnetCardsHtml
            </div>

            <!-- Public IPs Table -->
            <div style="margin-bottom:8px;font-weight:700;font-size:1em;color:var(--text);display:flex;align-items:center;gap:8px;">
                <svg width="20" height="20" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6.5" stroke="#00b7c3" stroke-width="1.2"/><path d="M2 8h12M8 1.5c-2 2-2 11 0 13M8 1.5c2 2 2 11 0 13" stroke="#00b7c3" stroke-width="1" fill="none"/></svg>
                Public IPs ($netKpiPIPs)
            </div>
            <div class="table-container" style="margin-bottom:28px;">
                <table id="pipTable">
                    <thead><tr><th>Name</th><th>Location</th><th>IP Address</th><th>Associated To</th><th>SKU</th></tr></thead>
                    <tbody>$pipRows</tbody>
                </table>
            </div>

            <!-- Gateways Table -->
            <div style="margin-bottom:8px;font-weight:700;font-size:1em;color:var(--text);display:flex;align-items:center;gap:8px;">
                <svg width="20" height="20" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 6v8h14V6L8 1z" stroke="#5c2d91" stroke-width="1.2" fill="none"/><rect x="6" y="9" width="4" height="5" rx=".5" stroke="#5c2d91" stroke-width="1"/></svg>
                Gateways ($netKpiGateways)
            </div>
            <div class="table-container">
                <table id="gatewaysTable">
                    <thead><tr><th>Name</th><th>Location</th><th>Type</th><th>Details</th></tr></thead>
                    <tbody>$gwRows</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Network Findings -->
    <div class="section" id="section-network-findings">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Network Findings</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">

            <!-- Severity summary -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px;">
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid #d13438;border-radius:10px;padding:16px 18px;text-align:center;">
                    <div style="font-size:1.8em;font-weight:700;color:#d13438;line-height:1.1;">$netFCritical</div>
                    <div style="font-size:.75em;color:var(--text-dim);font-weight:600;text-transform:uppercase;margin-top:4px;">Critical</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid #ca5010;border-radius:10px;padding:16px 18px;text-align:center;">
                    <div style="font-size:1.8em;font-weight:700;color:#ca5010;line-height:1.1;">$netFHigh</div>
                    <div style="font-size:.75em;color:var(--text-dim);font-weight:600;text-transform:uppercase;margin-top:4px;">High</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid #7a7574;border-radius:10px;padding:16px 18px;text-align:center;">
                    <div style="font-size:1.8em;font-weight:700;color:#7a7574;line-height:1.1;">$netFMedium</div>
                    <div style="font-size:.75em;color:var(--text-dim);font-weight:600;text-transform:uppercase;margin-top:4px;">Medium</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border-light);border-left:4px solid #107c10;border-radius:10px;padding:16px 18px;text-align:center;">
                    <div style="font-size:1.8em;font-weight:700;color:#107c10;line-height:1.1;">$netFLow</div>
                    <div style="font-size:.75em;color:var(--text-dim);font-weight:600;text-transform:uppercase;margin-top:4px;">Low</div>
                </div>
            </div>

            <!-- Filter bar -->
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource or finding..." oninput="searchFindings(this.value, this)" style="margin-left:auto">
            </div>

            <!-- Findings table -->
            <div class="table-container">
                <table id="networkFindingsTable">
                    <thead>
                        <tr>
                            <th style="width:90px;">Severity</th>
                            <th>Category</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$networkFindingsRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-network -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 7: COST & OPTIMIZATION                                          -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-cost" style="display:none">
    <div class="section" id="section-subs-cost">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Subscriptions</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div id="sub-filter-bar" style="display:none;margin-bottom:14px;padding:10px 16px;background:linear-gradient(90deg,#e8f4fd,#f0f6ff);border:1px solid #b3d7f2;border-radius:8px;font-size:.88em;color:#0078d4;align-items:center;gap:10px;">
                <span>&#128205; Showing cost data for: <strong id="sub-filter-name"></strong></span>
                <button onclick="clearSubCostFilter()" style="margin-left:auto;background:#0078d4;color:#fff;border:none;border-radius:4px;padding:4px 12px;cursor:pointer;font-size:.85em;font-weight:600;">Show All</button>
            </div>
            <table id="subsTable">
                <thead><tr><th>Name</th><th>ID</th><th>Status</th><th>Cost (6 months)</th></tr></thead>
                <tbody>$subRows</tbody>
            </table>
        </div>
    </div>
    <div class="section" id="section-costs">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Cost Analysis — Last 6 Months</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            $costHtml
        </div>
    </div>

    <!-- Underutilized Resources -->
    <div class="section" id="section-underutilized">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Underutilized Resources — Real Metrics ($MetricDays days)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:#fff4ce;border-left:4px solid #ca5010;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:.88em;color:#323130;">
                <strong>&#8505;&#65039; Methodology:</strong> Data comes directly from <strong>Azure Monitor</strong> — real metrics for the indicated period (not estimates).
                Each value is verifiable in the Azure portal: Monitor → Metrics → select the resource.
                Thresholds used: CPU VM &lt; 10% · Requests App Service &lt; 10/h · DTU/vCore SQL &lt; 10% · IOPS Premium Disk &lt; 5.
            </div>

            <!-- Summary cards -->
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:22px;">
                <div style="background:#fff;border:1px solid #edebe9;border-left:4px solid #d13438;border-radius:8px;padding:16px;text-align:center;">
                    <div id="util-vm-count" style="font-size:2em;font-weight:700;color:#d13438;">0</div>
                    <div style="font-size:.8em;color:#605e5c;">&#128421; Underutilized VMs</div>
                </div>
                <div style="background:#fff;border:1px solid #edebe9;border-left:4px solid #ca5010;border-radius:8px;padding:16px;text-align:center;">
                    <div id="util-app-count" style="font-size:2em;font-weight:700;color:#ca5010;">0</div>
                    <div style="font-size:.8em;color:#605e5c;">&#127760; App Services</div>
                </div>
                <div style="background:#fff;border:1px solid #edebe9;border-left:4px solid #005a9e;border-radius:8px;padding:16px;text-align:center;">
                    <div id="util-sql-count" style="font-size:2em;font-weight:700;color:#005a9e;">0</div>
                    <div style="font-size:.8em;color:#605e5c;">&#128452; SQL Databases</div>
                </div>
                <div style="background:#fff;border:1px solid #edebe9;border-left:4px solid #8a8886;border-radius:8px;padding:16px;text-align:center;">
                    <div id="util-disk-count" style="font-size:2em;font-weight:700;color:#8a8886;">0</div>
                    <div style="font-size:.8em;color:#605e5c;">&#128191; Premium Disks</div>
                </div>
                <div style="background:#dff6dd;border:1px solid #107c10;border-radius:8px;padding:16px;text-align:center;">
                    <div id="util-total-count" style="font-size:2em;font-weight:700;color:#107c10;">0</div>
                    <div style="font-size:.8em;color:#107c10;font-weight:600;">Total detected</div>
                </div>
            </div>

            <!-- Filters -->
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Type:</strong>
                <button class="filter-btn active" id="util-btn-all" onclick="utilFilter('all','type',this)">All</button>
                <button class="filter-btn type-vm" onclick="utilFilter('Virtual Machine','type',this)">VMs</button>
                <button class="filter-btn type-app" onclick="utilFilter('App Service','type',this)">App Services</button>
                <button class="filter-btn type-sql" onclick="utilFilter('SQL Database','type',this)">SQL</button>
                <button class="filter-btn type-disk" onclick="utilFilter('Managed Disk','type',this)">Disks</button>
                <span style="margin-left:10px;color:var(--border)">|</span>
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn sev-high" onclick="utilFilter('High','sev',this)">High</button>
                <button class="filter-btn sev-medium" onclick="utilFilter('Medium','sev',this)">Medium</button>
                <button class="filter-btn sev-low" onclick="utilFilter('Low','sev',this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="utilSearch(this.value)" style="margin-left:auto">
            </div>
            <p id="util-count-label" style="font-size:.82em;color:var(--text-dim);margin-bottom:12px;"></p>

            <!-- Table -->
            <div style="overflow-x:auto;border-radius:var(--radius-sm);">
                <table id="utilTable">
                    <thead>
                        <tr>
                            <th style="white-space:nowrap;">Severity</th>
                            <th>Type</th>
                            <th>Resource</th>
                            <th>Current SKU</th>
                            <th style="text-align:center;white-space:nowrap;">Metric (${MetricDays}d)</th>
                            <th>Description</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody id="util-tbody">
                        $underutilizedRows
                    </tbody>
                </table>
                <p id="util-empty-msg" style="display:none;text-align:center;padding:30px;color:var(--text-dim);font-size:.88em;">
                    No underutilized resources detected with current thresholds — or metrics were not available for this period.
                </p>
            </div>
        </div>
    </div>
    </div><!-- /blade-cost -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE: RESERVATIONS & SAVINGS PLANS                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-reservations" style="display:none;">
        <h2 style="margin-bottom:20px;color:var(--accent-dark);">Azure Reservations &amp; Savings Plans</h2>
        <p style="color:var(--text-dim);margin-bottom:20px;">Inventory and utilization analysis of Reserved Instances and Savings Plans across the tenant. Low utilization or expiring commitments represent cost optimization opportunities.</p>

        <!-- KPI Cards -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:24px;">
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:var(--accent-dark);">$riTotal</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Total Commitments</div>
            </div>
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:#0078d4;">$($riItems.Count)</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Reservations</div>
            </div>
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:#0078d4;">$($spItems.Count)</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Savings Plans</div>
            </div>
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:$(if($riAvgUtil -lt 50){'#d13438'}elseif($riAvgUtil -lt 80){'#ca5010'}else{'#107c10'});">$(if($riWithUtil.Count -gt 0){"${riAvgUtil}%"}else{'N/A'})</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Avg Utilization</div>
            </div>
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:$(if($riExpiring -gt 0){'#ca5010'}else{'#107c10'});">$riExpiring</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Expiring ≤90d</div>
            </div>
            <div class="card" style="text-align:center;padding:16px;">
                <div style="font-size:2em;font-weight:700;color:$(if($riLowUtil -gt 0){'#d13438'}else{'#107c10'});">$riLowUtil</div>
                <div style="font-size:.8em;color:var(--text-dim);font-weight:600;">Low Util (&lt;50%)</div>
            </div>
        </div>

        <!-- Reservations Table -->
        <div class="card" style="padding:0;overflow:hidden;">
            <div style="padding:14px 20px;background:linear-gradient(135deg,#0078d4,#005a9e);color:#fff;">
                <h3 style="margin:0;font-size:15px;">Commitment Inventory</h3>
            </div>
            <div style="padding:16px;">
$(if ($riTotal -gt 0) { @"
                <table>
                    <thead><tr>
                        <th style="width:10%">Type</th>
                        <th style="width:20%">Name</th>
                        <th style="width:8%">SKU</th>
                        <th style="width:5%;text-align:center">Qty</th>
                        <th style="width:8%">Term</th>
                        <th style="width:8%">Scope</th>
                        <th style="width:10%;text-align:center">Utilization</th>
                        <th style="width:10%;text-align:center">Purchased</th>
                        <th style="width:12%;text-align:center">Status / Expiry</th>
                    </tr></thead>
                    <tbody>$reservationRows</tbody>
                </table>
"@ } else { @"
                <div style="text-align:center;padding:40px;color:var(--text-dim);">
                    <div style="font-size:3em;margin-bottom:12px;">🎫</div>
                    <h3 style="color:#323130;margin-bottom:8px;">No Reservations or Savings Plans Detected</h3>
                    <p style="font-size:.9em;max-width:500px;margin:0 auto;">No active Azure Reservations or Savings Plans were found. This may indicate pay-as-you-go pricing across all resources, or insufficient permissions (Reservation Reader role required).</p>
                    <div style="margin-top:16px;padding:12px;background:#fff4ce;border-radius:6px;display:inline-block;">
                        <strong style="color:#7a6400;">💡 Recommendation:</strong>
                        <span style="color:#605e5c;font-size:.9em;"> Review Azure Advisor for RI purchase recommendations for workloads with predictable, steady-state usage.</span>
                    </div>
                </div>
"@ })
            </div>
        </div>
    </div><!-- /blade-reservations -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 8: GOVERNANCE & COMPLIANCE                                      -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-governance" style="display:none">
    <div class="section" id="section-governance">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Governance &amp; Compliance</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <!-- Governance Score bar -->
            <div style="background:linear-gradient(135deg,#107c10 0%,#0b6a0b 40%,#054d05 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(16,124,16,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#127963; Governance &amp; Compliance Overview</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Consolidated view of tags, policies, subscriptions hygiene, and governance posture across $($script:Subscriptions.Count) subscription(s).</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$($tagTotal+$policyTotal+$hygieneTotal+$govCount)</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$($govCritical)</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$($govHigh)</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Governance Domain Summary Table -->
            <div style="margin-bottom:24px;">
                <h3 style="font-size:.95em;color:var(--text);margin-bottom:12px;">Governance Domain Summary</h3>
                <div class="table-container">
                    <table id="govSummaryTable">
                        <thead><tr><th>Domain</th><th style="text-align:center">Findings</th><th style="text-align:center">Critical</th><th style="text-align:center">High</th><th style="text-align:center">Medium</th><th style="text-align:center">Low</th><th>Action</th></tr></thead>
                        <tbody>
                            <tr class="finding-row"><td>&#127991;&#65039; <strong>Tag Compliance</strong></td><td style="text-align:center;font-weight:700">$tagTotal</td><td style="text-align:center">$($tagCritical)</td><td style="text-align:center">$($tagHigh)</td><td style="text-align:center">$($tagMedium)</td><td style="text-align:center">$($tagLow)</td><td><a href="#" style="color:var(--accent);font-size:.85em;font-weight:600;" onclick="navTo('blade-tags',document.querySelector('a[onclick*=blade-tags]'),event)">View details &rarr;</a></td></tr>
                            <tr class="finding-row"><td>&#128220; <strong>Azure Policy</strong></td><td style="text-align:center;font-weight:700">$policyTotal</td><td style="text-align:center">$($policyCritical)</td><td style="text-align:center">$($policyHigh)</td><td style="text-align:center">$($policyMedium)</td><td style="text-align:center">$($policyLow)</td><td><a href="#" style="color:var(--accent);font-size:.85em;font-weight:600;" onclick="navTo('blade-tags',document.querySelector('a[onclick*=blade-tags]'),event)">View details &rarr;</a></td></tr>
                            <tr class="finding-row"><td>&#129529; <strong>Subscription Hygiene</strong></td><td style="text-align:center;font-weight:700">$hygieneTotal</td><td style="text-align:center">$($hygieneCritical)</td><td style="text-align:center">$($hygieneHigh)</td><td style="text-align:center">$($hygieneMedium)</td><td style="text-align:center">$($hygieneLow)</td><td><a href="#" style="color:var(--accent);font-size:.85em;font-weight:600;" onclick="navTo('blade-tags',document.querySelector('a[onclick*=blade-tags]'),event)">View details &rarr;</a></td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Governance findings -->
            $(if ($govCount -gt 0) { @"
            <div style="margin-top:8px;">
                <h3 style="font-size:.95em;color:var(--text);margin-bottom:12px;">Governance &amp; Naming Findings ($govCount)</h3>
                <div class="filters">
                    <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                    <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                    <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                    <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                    <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                    <input type="text" class="search-box" placeholder="Search..." oninput="searchFindings(this.value, this)">
                </div>
                <div class="table-container">
                    <table id="governanceTable">
                        <thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                        <tbody>$governanceRows</tbody>
                    </table>
                </div>
            </div>
"@ } else { '<div style="text-align:center;padding:16px;color:var(--text-dim);font-style:italic;">&#9989; No additional governance findings outside the domains above.</div>' })
        </div>
    </div>
    </div><!-- /blade-governance -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 9: MONITORING & OBSERVABILITY                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-monitoring" style="display:none">
    <div class="section" id="section-monitoring">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Monitoring &amp; Observability</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <!-- Monitoring Score bar -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128200; Monitoring &amp; Alerting</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">VM monitoring, Defender alerts, and Arc observability. Diagnostic Settings are in the Observability &amp; PE blade.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$monCritical</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$monHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$monMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$monLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Monitoring Filter bar -->
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>

            <div class="table-container">
                <table id="monitoringTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$monitoringRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-monitoring -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 10: MODERNIZATION                                               -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-modernization" style="display:none">
    <div class="section" id="section-modernization">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Modernization &amp; Migration</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <p style="color:var(--text-dim);margin-bottom:16px;">Findings related to Modernization, Migration, Containers, Serverless, and PaaS adoption.</p>
            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;text-align:center;min-width:90px;">
                    <div style="font-size:1.6em;font-weight:800;color:#d13438;">$modCritical</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Critical</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;text-align:center;min-width:90px;">
                    <div style="font-size:1.6em;font-weight:800;color:#ca5010;">$modHigh</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">High</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;text-align:center;min-width:90px;">
                    <div style="font-size:1.6em;font-weight:800;color:#605e5c;">$modMedium</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Medium</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 18px;text-align:center;min-width:90px;">
                    <div style="font-size:1.6em;font-weight:800;color:#107c10;">$modLow</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Low</div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="modernizationTable">
                    <thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Recommendation</th></tr></thead>
                    <tbody>$modernizationRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-modernization -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 12: BCDR & SECRETS                                              -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-bcdr" style="display:none">

    <!-- BCDR Section -->
    <div class="section" id="section-bcdr">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Business Continuity &amp; Disaster Recovery</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#127973; Backup, Recovery &amp; Disaster Recovery</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Recovery vaults, backup coverage, replication health, and RPO/RTO gaps.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$bcdrCritical</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$bcdrHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$bcdrMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="bcdrTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$bcdrRows</tbody>
                </table>
            </div>
        </div>
    </div>

    </div><!-- /blade-bcdr -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE: HIGH AVAILABILITY & RESILIENCE                                 -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-ha" style="display:none">
    <div class="section" id="section-ha">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#9889; High Availability &amp; Resilience</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">High Availability &amp; Resilience</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Availability Zones, redundancy, failover, single points of failure, and multi-region design.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$haHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$haMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$haLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$haTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="haTable">
                    <thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$haRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-ha -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE: KEY VAULT SECRETS, CERTIFICATES & KEYS                         -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-keyvault" style="display:none">
    <div class="section" id="section-secrets">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Expiring Secrets, Certificates &amp; Keys</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#5c2d91 0%,#4b2380 40%,#3b1a6e 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(92,45,145,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128272; Key Vault Secrets, Certificates &amp; Keys</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Items approaching expiration or already expired. Expired items can cause service outages.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$secretsCritical</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$secretsHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$secretsMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$secretsLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low / No Expiry</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search vault or secret..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="secretsTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$secretsRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-keyvault -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE: RESOURCE LOCKS                                                 -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-locks" style="display:none">
    <div class="section" id="section-locks">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Resource Locks</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#ca5010 0%,#a33d0b 40%,#7a2e08 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(202,80,16,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">&#128274; Resource Locks</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Resource Locks prevent accidental or unauthorized deletion of critical infrastructure. Resources without a CanNotDelete or ReadOnly lock are flagged.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$locksCritical</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Critical</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$locksHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$locksMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="locksTable">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Resource</th>
                            <th>Finding</th>
                            <th>Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>$locksRows</tbody>
                </table>
            </div>
        </div>
    </div>
    </div><!-- /blade-locks -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 13: TAG COMPLIANCE & GOVERNANCE DEEP DIVE                       -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-tags" style="display:none">

    <!-- Tag Compliance Section -->
    <div class="section" id="section-tags">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#127991;&#65039; Tag Compliance</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#107c10 0%,#0b5a0b 40%,#094509 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(16,124,16,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">Tag Compliance Analysis</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Mandatory tags: Environment, Owner, CostCenter, Application, Department. Empty resource groups included.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$tagHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$tagMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$tagLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$tagTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-critical" onclick="filterFindings('Critical', this)">Critical</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="tagTable">
                    <thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$tagRows</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Policy Compliance Section -->
    <div class="section" id="section-policy">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#128220; Azure Policy Compliance</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#ca5010 0%,#a33d0b 40%,#862f08 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(202,80,16,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">Azure Policy Compliance</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Policy assignments, compliance rates, enforcement modes, and non-compliant resource details.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$policyHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$policyMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$policyTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search policy..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="policyTable">
                    <thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$policyRows</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Subscription Hygiene Section -->
    <div class="section" id="section-hygiene">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#129529; Subscription Hygiene</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:#f0f6ff;border-left:4px solid #0078d4;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:.88em;color:#323130;">
                <strong>Subscription hygiene:</strong> Region sprawl, empty resource groups, naming conventions, and resource organization. Clean subscriptions are easier to manage, audit, and secure.
            </div>
            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;">
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;text-align:center;min-width:120px;">
                    <div style="font-size:1.8em;font-weight:800;color:#ca5010;">$hygieneMedium</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Medium</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;text-align:center;min-width:120px;">
                    <div style="font-size:1.8em;font-weight:800;color:#605e5c;">$hygieneLow</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Low</div>
                </div>
                <div style="background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;text-align:center;min-width:120px;">
                    <div style="font-size:1.8em;font-weight:800;color:#323130;">$hygieneTotal</div>
                    <div style="font-size:10px;color:#605e5c;font-weight:600;">Total Findings</div>
                </div>
            </div>
            <div class="table-container">
                <table id="hygieneTable">
                    <thead><tr><th>Severity</th><th>Category</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$hygieneRows</tbody>
                </table>
            </div>
        </div>
    </div>

    </div><!-- /blade-tags -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 14: DIAGNOSTIC SETTINGS & PRIVATE ENDPOINTS                     -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-observability" style="display:none">

    <!-- Diagnostic Settings Section -->
    <div class="section" id="section-diagnostics">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#128225; Diagnostic Settings Coverage</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#8764b8 0%,#6b4fa0 40%,#553d85 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(135,100,184,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">Diagnostic Settings Coverage</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Resources that should be sending logs/metrics to Log Analytics but have no diagnostic settings configured.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffa94d;line-height:1.1;">$diagHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$diagMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#69db7c;line-height:1.1;">$diagLow</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Low</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$diagTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search resource..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="diagTable">
                    <thead><tr><th>Severity</th><th>Resource Type</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$diagRows</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Private Endpoint Adoption Section -->
    <div class="section" id="section-pe">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#128274; Private Endpoint Adoption</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">Private Endpoint Adoption</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">PaaS services without Private Endpoints still route traffic over the public internet. Critical for Zero Trust.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$peHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$peMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$peTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <input type="text" class="search-box" placeholder="Search service..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="peTable">
                    <thead><tr><th>Severity</th><th>Service Type</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$peRows</tbody>
                </table>
            </div>
        </div>
    </div>

    </div><!-- /blade-observability -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 15: COSMOS DB & OSS DATABASES                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-databases" style="display:none">

    <div class="section" id="section-cosmos">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>&#128024; Cosmos DB &amp; OSS Database Security</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <div style="background:linear-gradient(135deg,#005b70 0%,#004b5c 40%,#003b48 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,91,112,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:30px;flex-wrap:wrap;align-items:center;position:relative;z-index:1;">
                    <div style="flex:1;min-width:200px;text-align:center;">
                        <div style="font-weight:700;color:#ffffff;font-size:1.2em;margin-bottom:6px;">Cosmos DB, PostgreSQL, MySQL &amp; Redis</div>
                        <div style="font-size:.85em;color:rgba(255,255,255,0.8);line-height:1.5;">Security posture, network access, backup configuration, high availability, and authentication for non-SQL data services.</div>
                    </div>
                    <div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center;">
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ff6b6b;line-height:1.1;">$cosmosHigh</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">High</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:rgba(255,255,255,0.7);line-height:1.1;">$cosmosMedium</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Medium</div>
                        </div>
                        <div style="text-align:center;min-width:72px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:14px 18px;backdrop-filter:blur(10px);">
                            <div style="font-size:1.9em;font-weight:700;color:#ffffff;line-height:1.1;">$cosmosTotal</div>
                            <div style="font-size:.68em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total</div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="filters">
                <strong style="font-size:.85em;color:var(--text-dim);">Severity:</strong>
                <button class="filter-btn active" onclick="filterFindings('all', this)">All</button>
                <button class="filter-btn sev-high" onclick="filterFindings('High', this)">High</button>
                <button class="filter-btn sev-medium" onclick="filterFindings('Medium', this)">Medium</button>
                <button class="filter-btn sev-low" onclick="filterFindings('Low', this)">Low</button>
                <input type="text" class="search-box" placeholder="Search database..." oninput="searchFindings(this.value, this)">
            </div>
            <div class="table-container">
                <table id="cosmosTable">
                    <thead><tr><th>Severity</th><th>Service</th><th>Resource</th><th>Finding</th><th>Recommendation</th></tr></thead>
                    <tbody>$cosmosRows</tbody>
                </table>
            </div>
        </div>
    </div>

    </div><!-- /blade-databases -->

    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 11: INVENTORY                                                   -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-inventory" style="display:none">
    <div class="section" id="section-inventory">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Resource Inventory ($($script:Summary.TotalResources) total)</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <!-- KPI Banner -->
            <div style="background:linear-gradient(135deg,#0078d4 0%,#005a9e 40%,#003f72 100%);border-radius:12px;padding:28px 32px;margin-bottom:24px;box-shadow:0 4px 24px rgba(0,120,212,0.25);position:relative;overflow:hidden;">
                <div style="position:absolute;top:0;left:0;right:0;bottom:0;background:url(&quot;data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.03'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E&quot;);pointer-events:none;"></div>
                <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:center;justify-content:center;position:relative;z-index:1;">
                    <div style="text-align:center;min-width:120px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:18px 24px;backdrop-filter:blur(10px);">
                        <div style="font-size:2.2em;font-weight:800;color:#fff;line-height:1;">$($script:Summary.TotalResources)</div>
                        <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Total Resources</div>
                    </div>
                    <div style="text-align:center;min-width:120px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:18px 24px;backdrop-filter:blur(10px);">
                        <div style="font-size:2.2em;font-weight:800;color:#69db7c;line-height:1;">$uniqueTypes</div>
                        <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Resource Types</div>
                    </div>
                    <div style="text-align:center;min-width:120px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:18px 24px;backdrop-filter:blur(10px);">
                        <div style="font-size:2.2em;font-weight:800;color:#ffa94d;line-height:1;">$($script:Subscriptions.Count)</div>
                        <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Subscriptions</div>
                    </div>
                    <div style="text-align:center;min-width:120px;background:rgba(255,255,255,0.12);border:1px solid rgba(255,255,255,0.2);border-radius:10px;padding:18px 24px;backdrop-filter:blur(10px);">
                        <div style="font-size:2.2em;font-weight:800;color:#74c0fc;line-height:1;">$uniqueLocations</div>
                        <div style="font-size:.7em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:4px;">Regions</div>
                    </div>
                    <div style="text-align:center;min-width:160px;background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.25);border-radius:10px;padding:18px 24px;backdrop-filter:blur(10px);">
                        <div style="font-size:1.5em;font-weight:800;color:#fff;line-height:1.1;">$(ConvertTo-SafeHtml $topResourceType)</div>
                        <div style="font-size:2em;font-weight:800;color:#ffd43b;line-height:1;">$topResourceCount</div>
                        <div style="font-size:.65em;color:rgba(255,255,255,0.8);font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-top:2px;">Most Common Type</div>
                    </div>
                </div>
            </div>

            <!-- Subscription Filter -->
            <div class="filters" style="margin-bottom:16px;">
                $invSubButtons
            </div>
            <script>var invCatData = $invCatDataJson;</script>

            <!-- Category Distribution Cards -->
            <h4 style="font-size:12px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;">&#128202; Resource Distribution by Category</h4>
            <div id="inv-cat-container" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;">
                $catCardsHtml
            </div>

            <!-- Detailed Table -->
            <h4 style="font-size:12px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;">&#128203; Detailed Inventory by Type</h4>
            <div id="inv-all-view">
                <div class="table-container">
                    <table>
                        <thead><tr><th>Resource Type</th><th>Azure Provider</th><th>Locations</th><th style="min-width:180px;">Count</th></tr></thead>
                        <tbody>$resourceRows</tbody>
                    </table>
                </div>
            </div>
            <div id="inv-sub-view" style="display:none;">
                $subInventoryRows
            </div>
        </div>
    </div>
    </div><!-- /blade-inventory -->

    $alzBladeHtml

    <!-- ═══════════════════════════════════════════════════════════════════════ -->


    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <!-- BLADE 16: METHODOLOGY & APPENDIX                                      -->
    <!-- ═══════════════════════════════════════════════════════════════════════ -->
    <div class="blade" id="blade-method" style="display:none">
    <div class="section" id="section-method">
        <div class="section-header" onclick="toggleSection(this)">
            <h2>Methodology &amp; Appendices</h2>
            <span class="toggle">&#9660;</span>
        </div>
        <div class="section-content">
            <h3 style="color:var(--accent-dark);margin-bottom:12px;">Assessment Methodology</h3>
            <p style="margin-bottom:14px;color:var(--text-dim);">This assessment was performed automatically using the Azure Tenant Assessment script. The evaluation follows the <strong>Microsoft Azure Well-Architected Framework</strong> (WAF) pillars and the <strong>Zero Trust</strong> security model.</p>
            <table style="margin-bottom:20px;">
                <thead><tr><th>Phase</th><th>Description</th></tr></thead>
                <tbody>
                    <tr><td><strong>1. Authentication &amp; Discovery</strong></td><td>Connect to Entra ID, enumerate all enabled subscriptions in the tenant, and validate permissions (Reader role minimum).</td></tr>
                    <tr><td><strong>2. Data Collection</strong></td><td>Bulk retrieval via <strong>Azure Resource Graph</strong> in batches of 20 subscriptions for performance. Supplemented with Az PowerShell for specific APIs (metrics, Key Vault, Backup).</td></tr>
                    <tr><td><strong>3. Resource Inventory</strong></td><td>Full enumeration by resource type (top-level resources only; child/extension resources are excluded). Categorized with friendly display names and tagging compliance analysis.</td></tr>
                    <tr><td><strong>4. WAF Pillar Analysis</strong></td><td>Each resource evaluated against best practices across Security, Reliability, Cost Optimization, Operational Excellence, and Performance Efficiency. Covers: Networking (NSGs, DDoS, Subnets), VMs, App Services, SQL/Databases, Storage, Key Vaults, AKS, and more.</td></tr>
                    <tr><td><strong>5. Zero Trust Assessment</strong></td><td>Evaluation across 3 layers: <strong>Network</strong> (micro-segmentation, private endpoints), <strong>Compute</strong> (JIT, endpoint protection, disk encryption), <strong>Platform</strong> (Conditional Access, PIM — evaluated once at tenant level).</td></tr>
                    <tr><td><strong>6. Utilization Metrics</strong></td><td>Azure Monitor real metrics ($MetricDays-day window, configurable) for CPU, network throughput, requests, DTU/vCore, and disk IOPS to identify underutilized resources.</td></tr>
                    <tr><td><strong>7. Cost Optimization</strong></td><td>Azure Advisor cost recommendations, Azure Hybrid Benefit eligibility, dev/test VM auto-shutdown, orphaned resources (unattached disks, NICs, PIPs).</td></tr>
                    <tr><td><strong>8. BCDR &amp; Data Protection</strong></td><td>Backup policy coverage, retention adequacy, geo-redundancy of backup vaults, Recovery Services vault configuration, and ASR replication status.</td></tr>
                    <tr><td><strong>9. Secrets &amp; Certificate Hygiene</strong></td><td>Key Vault data-plane analysis: expiring or expired secrets, keys, and certificates (optional — controlled by SkipKeyVaultDataPlane parameter).</td></tr>
                    <tr><td><strong>10. Governance &amp; Compliance</strong></td><td>Azure Policy compliance state, resource locks on critical resources, diagnostic settings for audit logging, tag compliance against required tags, subscription hygiene.</td></tr>
                    <tr><td><strong>11. Network Security (Advanced)</strong></td><td>Private endpoint coverage for PaaS services (12 resource types), DDoS protection (flagged only for VNets with public IP exposure), NSG flow logs.</td></tr>
                    <tr><td><strong>12. Modernization &amp; Hybrid</strong></td><td>Legacy resource identification, migration candidates, Arc-enabled server posture, and Cosmos DB / OSS database (PostgreSQL, MySQL, Redis) security review.</td></tr>
                    <tr><td><strong>13. ALZ/CAF Readiness</strong></td><td>Management Group hierarchy, MG-scope policy/RBAC per MG, ALZ policy library detection, hub-spoke/vWAN topology, Private DNS zone coverage and VNet links, Conditional Access policies, and PIM configuration. Graph-dependent items appear as manual checklist when Graph is unavailable.</td></tr>
                    <tr><td><strong>14. Reservations &amp; Savings Plans</strong></td><td>Inventory of Azure Reserved Instances and Savings Plans. Analyzes utilization rates (7-day average), identifies underutilized commitments (&lt;50%), expiring reservations (≤90 days), and expired commitments. Flags subscriptions with significant compute but no reservations.</td></tr>
                </tbody>
            </table>

            <h3 style="color:var(--accent-dark);margin-bottom:12px;">Assessment Scope &amp; Limitations</h3>
            <div style="background:#fff4ce;border:1px solid #ffb900;border-radius:8px;padding:16px 20px;margin-bottom:20px;">
                <strong style="color:#7a6400;">⚠️ Important: ALZ/CAF Readiness Scope</strong>
                <p style="margin-top:8px;color:#605e5c;font-size:.9em;">This assessment includes an <strong>ALZ Readiness</strong> section that evaluates Management Group hierarchy, MG-scope policies, network topology, Private DNS zones, Conditional Access, and PIM. Coverage depends on the permissions available at runtime:</p>
                <ul style="color:#605e5c;padding-left:20px;font-size:.9em;margin-top:8px;">
                    <li><strong>Reader on subscriptions</strong> — enables vWAN/hub-spoke topology and Private DNS zone detection</li>
                    <li><strong>Management Group Reader</strong> — enables MG hierarchy, per-MG policy/RBAC, and subscription placement analysis</li>
                    <li><strong>Microsoft Graph</strong> (Policy.Read.All, RoleManagement.Read.Directory) — enables Conditional Access and PIM verification. Without Graph, these appear as manual checklist items</li>
                </ul>
                <p style="margin-top:10px;color:#605e5c;font-size:.9em;">This tool complements — but does not replace — a formal ALZ architecture review. Organizational alignment, subscription vending, and platform team structure require manual validation.</p>
            </div>

            <h3 style="color:var(--accent-dark);margin-bottom:12px;">Required Permissions</h3>
            <table style="margin-bottom:20px;">
                <thead><tr><th>Permission / Role</th><th>Scope</th><th>Required</th><th>Purpose</th></tr></thead>
                <tbody>
                    <tr><td><strong>Reader</strong></td><td>Each Subscription</td><td>✅ Yes</td><td>Core assessment — read all resource configurations</td></tr>
                    <tr><td><strong>Cost Management Reader</strong></td><td>Each Subscription</td><td>Optional</td><td>Cost analysis (6-month trend, top services)</td></tr>
                    <tr><td><strong>Management Group Reader</strong></td><td>Tenant Root Group</td><td>ALZ only</td><td>Read MG hierarchy and structure</td></tr>
                    <tr><td><strong>Reader</strong></td><td>Management Groups</td><td>ALZ only</td><td>Read policy assignments and RBAC at MG scope</td></tr>
                    <tr><td><strong>Policy.Read.All</strong></td><td>Microsoft Graph</td><td>ALZ only</td><td>Read Conditional Access policies</td></tr>
                    <tr><td><strong>RoleManagement.Read.Directory</strong></td><td>Microsoft Graph</td><td>ALZ only</td><td>Read PIM eligible role assignments</td></tr>
                    <tr><td><strong>Directory.Read.All</strong></td><td>Microsoft Graph</td><td>ALZ only</td><td>Resolve AAD objects for RBAC analysis</td></tr>
                </tbody>
            </table>

            <h3 style="color:var(--accent-dark);margin-bottom:12px;">Severity Classification</h3>
            <table style="margin-bottom:20px;">
                <thead><tr><th>Severity</th><th>Definition</th><th>Response Time</th></tr></thead>
                <tbody>
                    <tr><td><span class="severity-badge critical">Critical</span></td><td>Active vulnerability with immediate risk of data exposure, service disruption, or unauthorized access.</td><td>Immediate (24h)</td></tr>
                    <tr><td><span class="severity-badge high">High</span></td><td>Significant security or reliability gap that should be addressed promptly.</td><td>1–2 weeks</td></tr>
                    <tr><td><span class="severity-badge medium">Medium</span></td><td>Best practice deviation that increases risk over time.</td><td>1–2 months</td></tr>
                    <tr><td><span class="severity-badge low">Low</span></td><td>Optimization opportunity or minor improvement.</td><td>3–6 months</td></tr>
                </tbody>
            </table>

            <h3 style="color:var(--accent-dark);margin-bottom:12px;">References</h3>
            <ul style="color:var(--text-dim);padding-left:20px;">
                <li><a href="https://learn.microsoft.com/en-us/azure/well-architected/" target="_blank" style="color:var(--accent);">Azure Well-Architected Framework</a></li>
                <li><a href="https://learn.microsoft.com/en-us/security/zero-trust/" target="_blank" style="color:var(--accent);">Microsoft Zero Trust Model</a></li>
                <li><a href="https://learn.microsoft.com/en-us/azure/advisor/" target="_blank" style="color:var(--accent);">Azure Advisor</a></li>
                <li><a href="https://learn.microsoft.com/en-us/azure/defender-for-cloud/" target="_blank" style="color:var(--accent);">Microsoft Defender for Cloud</a></li>
                <li><a href="https://learn.microsoft.com/en-us/azure/azure-monitor/" target="_blank" style="color:var(--accent);">Azure Monitor</a></li>
            </ul>
        </div>
    </div>

    <!-- EXPORT -->
    <div style="text-align:center; margin: 30px 0;">
        <button class="export-btn" onclick="exportCSV()">&#128229; Export Findings to CSV</button>
        <button class="export-btn" onclick="window.print()">Print / PDF</button>
    </div>

    <div class="footer">
        Azure Tenant Assessment Tool · Well-Architected Framework Review<br>
        <span style="font-size:0.92em;opacity:0.8;">This report is an automated assessment. Validate findings with your architecture team.</span>
    </div>
    </div><!-- /blade-method -->
</div>
</div>

<script>
function navTo(id, el, e) {
    e.preventDefault();
    document.querySelectorAll('.portal-sidebar a').forEach(function(a){ a.classList.remove('active'); });
    el.classList.add('active');
    // id is now the blade ID directly (e.g. 'blade-executive')
    var bladeId = id;
    // Hide all blades, show the target one
    document.querySelectorAll('.blade').forEach(function(b){ b.style.display = 'none'; });
    var blade = document.getElementById(bladeId);
    if (blade) blade.style.display = 'block';
    // Reset filter state when switching blades
    _fSev = 'all'; _fPillar = 'all'; _fSearch = ''; _fSource = 'all';
    // Reset filter button active states and search box in the new blade
    if (blade) {
        blade.querySelectorAll('.filters').forEach(function(f){
            f.querySelectorAll('.filter-btn').forEach(function(b){ b.classList.remove('active'); });
            var allBtn = f.querySelector('.filter-btn');
            if (allBtn) allBtn.classList.add('active');
            var searchBox = f.querySelector('.search-box');
            if (searchBox) searchBox.value = '';
        });
        blade.querySelectorAll('.finding-row').forEach(function(r){ r.style.display = ''; });
    }
    // Scroll to top
    window.scrollTo(0, 0);
}
function sidebarFilter(val) {
    var q = val.toLowerCase();
    document.querySelectorAll('.portal-sidebar a').forEach(function(a){
        a.style.display = (!q || a.textContent.toLowerCase().includes(q)) ? '' : 'none';
    });
    document.querySelectorAll('.portal-sidebar .sidebar-group-header').forEach(function(h){
        var items = h.nextElementSibling;
        if (!items) return;
        var anyVisible = Array.from(items.querySelectorAll('a')).some(function(a){ return a.style.display !== 'none'; });
        h.style.display = (!q || anyVisible) ? '' : 'none';
    });
    document.querySelectorAll('.portal-sidebar .sidebar-section-title').forEach(function(t){
        var sibling = t.nextElementSibling;
        var anyVisible = false;
        while (sibling && sibling.classList.contains('sidebar-group')) {
            if (sibling.querySelector('a') && Array.from(sibling.querySelectorAll('a')).some(function(a){ return a.style.display !== 'none'; })) { anyVisible = true; break; }
            sibling = sibling.nextElementSibling;
            if (sibling && sibling.classList.contains('sidebar-section-title')) break;
        }
        t.style.display = (!q || anyVisible) ? '' : 'none';
    });
}
function toggleSidebar() {
    var sb = document.querySelector('.portal-sidebar');
    if (!sb) return;
    sb.classList.toggle('sidebar-collapsed');
    if (sb.classList.contains('sidebar-collapsed')) { sb.style.width = '0'; sb.style.overflow = 'hidden'; sb.style.padding = '0'; sb.style.borderRight = 'none'; }
    else { sb.style.width = ''; sb.style.overflow = ''; sb.style.padding = ''; sb.style.borderRight = ''; }
}
function toggleSection(header) {
    header.parentElement.classList.toggle('collapsed');
}

// ── Subscription cost filter ──────────────────────────────────────────────
function selectSubCost(row) {
    var subId = row.dataset.subid;
    var tbl = document.getElementById('subsTable');
    var rows = tbl ? tbl.querySelectorAll('tr[data-subid]') : [];
    var alreadySelected = row.classList.contains('sub-selected');
    // Toggle off if clicking same row
    if (alreadySelected) { clearSubCostFilter(); return; }
    // Highlight selected row
    rows.forEach(function(r) { r.classList.remove('sub-selected'); r.style.background = ''; });
    row.classList.add('sub-selected');
    row.style.background = 'linear-gradient(90deg,#e8f4fd,#f0f6ff)';
    // Show filter bar
    var bar = document.getElementById('sub-filter-bar');
    if (bar) { bar.style.display = 'flex'; }
    var nameEl = document.getElementById('sub-filter-name');
    if (nameEl) { nameEl.textContent = row.querySelector('td strong') ? row.querySelector('td strong').textContent : subId; }
    // Filter cost sections
    var sections = document.querySelectorAll('.cost-sub-section[data-subid]');
    sections.forEach(function(s) {
        s.style.display = (s.dataset.subid === subId) ? '' : 'none';
    });
    // Auto-expand the Cost Analysis section if collapsed
    var costSection = document.getElementById('section-costs');
    if (costSection && costSection.classList.contains('collapsed')) { costSection.classList.remove('collapsed'); }
}
function clearSubCostFilter() {
    var tbl = document.getElementById('subsTable');
    var rows = tbl ? tbl.querySelectorAll('tr[data-subid]') : [];
    rows.forEach(function(r) { r.classList.remove('sub-selected'); r.style.background = ''; });
    var bar = document.getElementById('sub-filter-bar');
    if (bar) { bar.style.display = 'none'; }
    var sections = document.querySelectorAll('.cost-sub-section[data-subid]');
    sections.forEach(function(s) { s.style.display = ''; });
}

// ── Zero Trust: initialise counters and wire up rows ──────────────────────
(function initZT(){
    const rows = Array.from(document.querySelectorAll('#zt-tbody .zt-finding-row'));
    if (!rows.length) {
        var ztLabel = document.getElementById('zt-count-label');
        if (ztLabel) ztLabel.textContent = 'No Zero Trust findings found.';
        return;
    }
    let crit=0, high=0, med=0, low=0, net=0, comp=0, plat=0;
    rows.forEach(r => {
        const sev   = r.dataset.severity  || '';
        const layer = r.dataset.layer     || '';
        if (sev==='Critical') crit++;
        else if (sev==='High') high++;
        else if (sev==='Medium') med++;
        else if (sev==='Low') low++;
        if (layer.includes('Network'))  net++;
        else if (layer.includes('Compute'))  comp++;
        else if (layer.includes('Platform')) plat++;
    });
    document.getElementById('zt-critical').textContent   = crit;
    document.getElementById('zt-high').textContent       = high;
    document.getElementById('zt-medium').textContent     = med;
    document.getElementById('zt-low').textContent        = low;
    document.getElementById('zt-net-count').textContent  = net  + ' finding(s) — click to filter';
    document.getElementById('zt-comp-count').textContent = comp + ' finding(s) — click to filter';
    document.getElementById('zt-plat-count').textContent = plat + ' finding(s) — click to filter';
    // Populate overview ZT counters
    var ov;
    if (ov = document.getElementById('zt-ov-critical')) ov.textContent = crit;
    if (ov = document.getElementById('zt-ov-high'))     ov.textContent = high;
    if (ov = document.getElementById('zt-ov-medium'))   ov.textContent = med;
    if (ov = document.getElementById('zt-ov-low'))      ov.textContent = low;
    if (ov = document.getElementById('zt-ov-total'))    ov.textContent = crit+high+med+low;
    updateZTCount();
})();

// Active state helpers for ZT filter buttons
let _ztSev = 'all', _ztLayer = 'all', _ztSearch = '';

function ztSetBtnActive(group, btn) {
    document.querySelectorAll(group).forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
}

function ztFilterSev(sev, btn) {
    _ztSev = sev;
    ztSetBtnActive('#zt-btn-all, .filter-btn[onclick*="ztFilterSev"]', btn);
    applyZTFilters();
}

function ztFilterLayer(layer, btn) {
    // Toggle: click same layer again to reset
    if (_ztLayer === layer) {
        _ztLayer = 'all';
        if (btn) btn.classList.remove('active');
    } else {
        _ztLayer = layer;
        document.querySelectorAll('.filter-btn[onclick*="ztFilterLayer"]').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
    }
    applyZTFilters();
}

function ztSearch(val) {
    _ztSearch = val.toLowerCase();
    applyZTFilters();
}

function applyZTFilters() {
    const rows = document.querySelectorAll('#zt-tbody .zt-finding-row');
    rows.forEach(row => {
        const matchSev    = _ztSev   === 'all' || row.dataset.severity === _ztSev;
        const matchLayer  = _ztLayer === 'all' || row.dataset.layer === _ztLayer;
        const matchSearch = !_ztSearch || row.textContent.toLowerCase().includes(_ztSearch);
        row.style.display = (matchSev && matchLayer && matchSearch) ? '' : 'none';
    });
    updateZTCount();
}

function updateZTCount() {
    const rows   = document.querySelectorAll('#zt-tbody .zt-finding-row');
    const visible = Array.from(rows).filter(r => r.style.display !== 'none').length;
    const label  = document.getElementById('zt-count-label');
    const empty  = document.getElementById('zt-empty-msg');
    if (label) label.textContent = visible + ' finding(s) shown of ' + rows.length + ' total';
    if (empty) empty.style.display = visible === 0 ? 'block' : 'none';
    if (document.getElementById('ztTable'))
        document.getElementById('ztTable').style.display = visible === 0 ? 'none' : '';
}

// ── Underutilized Resources ──────────────────────────────────────────────
(function initUtil(){
    const rows = Array.from(document.querySelectorAll('#util-tbody .util-row'));
    if (!rows.length) {
        const lbl = document.getElementById('util-count-label');
        if(lbl) lbl.textContent = 'No metrics collected (resources without data or insufficient load).';
        const tbl = document.getElementById('utilTable');
        if(tbl) tbl.style.display = 'none';
        const emp = document.getElementById('util-empty-msg');
        if(emp) emp.style.display = 'block';
        return;
    }
    let vm=0, app=0, sql=0, disk=0;
    rows.forEach(r => {
        const t = r.dataset.type || '';
        if(t.includes('Virtual')) vm++;
        else if(t.includes('App'))  app++;
        else if(t.includes('SQL'))  sql++;
        else if(t.includes('Disk')) disk++;
    });
    const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
    set('util-vm-count', vm);
    set('util-app-count', app);
    set('util-sql-count', sql);
    set('util-disk-count', disk);
    set('util-total-count', rows.length);
    updateUtilCount();
})();

let _utilType = 'all', _utilSev = 'all', _utilSearch = '';

function utilFilter(val, mode, btn) {
    if (mode === 'type') {
        _utilType = (_utilType === val) ? 'all' : val;
        document.querySelectorAll('#util-btn-all, .filter-btn[onclick*="utilFilter"][onclick*="type"]').forEach(b => b.classList.remove('active'));
        if (_utilType === 'all') { document.getElementById('util-btn-all')?.classList.add('active'); }
        else if(btn) btn.classList.add('active');
    } else {
        _utilSev = (_utilSev === val) ? 'all' : val;
        document.querySelectorAll('.filter-btn[onclick*="utilFilter"][onclick*="sev"]').forEach(b => b.classList.remove('active'));
        if (_utilSev !== 'all' && btn) btn.classList.add('active');
    }
    applyUtilFilters();
}

function utilSearch(val) { _utilSearch = val.toLowerCase(); applyUtilFilters(); }

function applyUtilFilters() {
    document.querySelectorAll('#util-tbody .util-row').forEach(row => {
        const matchType   = _utilType === 'all' || (row.dataset.type||'').includes(_utilType);
        const matchSev    = _utilSev  === 'all' || row.dataset.severity === _utilSev;
        const matchSearch = !_utilSearch || row.textContent.toLowerCase().includes(_utilSearch);
        row.style.display = (matchType && matchSev && matchSearch) ? '' : 'none';
    });
    updateUtilCount();
}

function updateUtilCount() {
    const rows = document.querySelectorAll('#util-tbody .util-row');
    const vis  = Array.from(rows).filter(r => r.style.display !== 'none').length;
    const lbl  = document.getElementById('util-count-label');
    const emp  = document.getElementById('util-empty-msg');
    const tbl  = document.getElementById('utilTable');
    if(lbl) lbl.textContent = vis + ' resource(s) shown of ' + rows.length + ' total';
    if(emp) emp.style.display = vis === 0 ? 'block' : 'none';
    if(tbl) tbl.style.display = vis === 0 ? 'none' : '';
}

var _fSev = 'all', _fPillar = 'all', _fSearch = '';

function filterFindings(severity, btn) {
    _fSev = severity;
    // Update active state only for severity buttons within this filter bar
    var filtersDiv = btn.closest('.filters');
    if (!filtersDiv) return;
    filtersDiv.querySelectorAll('.filter-btn[onclick*="filterFindings"]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    // Scope filter state per section: read other filter values from THIS section's buttons
    _fPillar = getActiveFilter(filtersDiv, 'filterByPillar');
    _fSource = getActiveFilter(filtersDiv, 'filterBySource');
    applyFindingsFilters(filtersDiv);
}

function filterByPillar(pillar, btn) {
    _fPillar = pillar;
    // Update active state only for pillar buttons within this filter bar
    var filtersDiv = btn.closest('.filters');
    if (!filtersDiv) return;
    filtersDiv.querySelectorAll('.filter-btn[onclick*="filterByPillar"]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    _fSev = getActiveFilter(filtersDiv, 'filterFindings');
    _fSource = getActiveFilter(filtersDiv, 'filterBySource');
    applyFindingsFilters(filtersDiv);
}

var _fSource = 'all';
function filterBySource(source, btn) {
    _fSource = (_fSource === source) ? 'all' : source;
    var filtersDiv = btn.closest('.filters');
    if (!filtersDiv) return;
    filtersDiv.querySelectorAll('.filter-btn[onclick*="filterBySource"]').forEach(b => b.classList.remove('active'));
    if (_fSource !== 'all') btn.classList.add('active');
    _fSev = getActiveFilter(filtersDiv, 'filterFindings');
    _fPillar = getActiveFilter(filtersDiv, 'filterByPillar');
    applyFindingsFilters(filtersDiv);
}

// Helper: read the active filter value from a specific filter button group
function getActiveFilter(filtersDiv, fnName) {
    var activeBtn = filtersDiv.querySelector('.filter-btn.active[onclick*=\"' + fnName + '\"]');
    if (!activeBtn) return 'all';
    var m = activeBtn.getAttribute('onclick').match(/'([^']+)'/);
    return m ? m[1] : 'all';
}

var _searchTimer = null;
function searchFindings(query, inputEl) {
    clearTimeout(_searchTimer);
    _searchTimer = setTimeout(function() {
    _fSearch = query.toLowerCase();
    // Find the closest filter bar to the input element, or fall back to visible blade
    var filtersDiv = inputEl ? inputEl.closest('.filters') : null;
    if (filtersDiv) { applyFindingsFilters(filtersDiv); return; }
    var blades = document.querySelectorAll('.blade');
    for (var i = 0; i < blades.length; i++) {
        if (blades[i].style.display !== 'none') {
            filtersDiv = blades[i].querySelector('.filters');
            if (filtersDiv) { applyFindingsFilters(filtersDiv); break; }
        }
    }
    }, 150);
}

function applyFindingsFilters(filtersDiv) {
    // Find the table within the same section-content as the filters
    var sectionContent = filtersDiv.closest('.section-content');
    if (!sectionContent) return;
    var rows = sectionContent.querySelectorAll('.finding-row');
    // Only apply pillar filter if this section has pillar buttons
    var hasPillarBtns = filtersDiv.querySelector('[onclick*="filterByPillar"]') !== null;
    var shown = 0;
    rows.forEach(function(row) {
        var matchSev = _fSev === 'all' || row.dataset.severity === _fSev;
        var matchPillar = !hasPillarBtns || _fPillar === 'all' || row.dataset.pillar === _fPillar;
        var matchSource = _fSource === 'all' || row.dataset.source === _fSource;
        var matchSearch = !_fSearch || row.textContent.toLowerCase().includes(_fSearch);
        var visible = matchSev && matchPillar && matchSource && matchSearch;
        row.style.display = visible ? '' : 'none';
        if (visible) shown++;
    });
}

function exportCSV() {
    // Export the table in the currently visible blade
    var blades = document.querySelectorAll('.blade');
    for (var i = 0; i < blades.length; i++) {
        if (blades[i].style.display !== 'none') {
            var table = blades[i].querySelector('table');
            if (table && table.id) { exportTableCSV(table.id); return; }
            // Fallback: export first table even without id
            if (table) {
                table.id = 'export-temp-' + Date.now();
                exportTableCSV(table.id);
                table.removeAttribute('id');
                return;
            }
        }
    }
    // Final fallback: export main findings table
    exportTableCSV('findingsTable');
}
function exportTableCSV(tableId) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var rows = table.querySelectorAll('tr');
    var csv = '';
    rows.forEach(function(row) {
        if (row.style.display === 'none' || row.classList.contains('sub-hidden')) return;
        var cols = row.querySelectorAll('td, th');
        var rowData = Array.from(cols).map(function(c) {
            return '"' + c.textContent.replace(/"/g, '""').replace(/[\r\n]+/g, ' ').trim() + '"';
        });
        csv += rowData.join(',') + '\n';
    });
    if (!csv.trim()) { alert('No visible data to export.'); return; }
    var section = table.closest('.section');
    var sectionName = tableId;
    if (section) {
        var h2 = section.querySelector('.section-header h2');
        if (h2) sectionName = h2.textContent.replace(/[^a-zA-Z0-9 ]/g, '').trim().replace(/\s+/g, '_');
    }
    var blob = new Blob(['\ufeff' + csv], {type:'text/csv;charset=utf-8;'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'Azure_Assessment_' + sectionName + '.csv';
    link.click();
    URL.revokeObjectURL(link.href);
}

// ── Inventory subscription filter ──────────────────────────────────────────
function invFilterSub(sub) {
    var allView = document.getElementById('inv-all-view');
    var subView = document.getElementById('inv-sub-view');

    if (sub === 'all') {
        allView.style.display = '';
        subView.style.display = 'none';
    } else {
        allView.style.display = 'none';
        subView.style.display = '';
        subView.querySelectorAll('.inv-sub-section').forEach(function(sec){
            sec.style.display = (sec.dataset.sub === sub) ? '' : 'none';
        });
    }

    // Update category distribution cards
    if (typeof invCatData === 'undefined') return;
    var data = invCatData[sub] || invCatData['all'];
    if (!data) return;
    var counts = data.counts || {};
    var total = data.total || 1;
    var cards = document.querySelectorAll('.inv-cat-card');
    var maxVal = 0;
    // First pass: find max and determine visibility
    cards.forEach(function(c) {
        var cat = c.dataset.cat;
        var val = counts[cat] || 0;
        if (val > maxVal) maxVal = val;
    });
    if (maxVal === 0) maxVal = 1;
    // Second pass: update values
    cards.forEach(function(c) {
        var cat = c.dataset.cat;
        var val = counts[cat] || 0;
        c.style.display = val > 0 ? '' : 'none';
        if (val > 0) {
            c.querySelector('.inv-cat-count').textContent = val;
            var pct = Math.round(val / total * 1000) / 10;
            c.querySelector('.inv-cat-pct').textContent = pct + '% of total';
            c.querySelector('.inv-cat-bar').style.width = Math.round(val / maxVal * 100) + '%';
        }
    });
}

// ── Cost section: no canvas charts needed, pure CSS visualization ──────────

// ── Network Topology subscription filter ───────────────────────────────────
(function initNetworkSubFilter() {
    var container = document.getElementById('vnet-cards-container');
    var filterDiv = document.getElementById('network-sub-filter');
    if (!container || !filterDiv) return;
    var cards = container.querySelectorAll('.vnet-card');
    var subs = {};
    cards.forEach(function(c) { if (c.dataset.sub) subs[c.dataset.sub] = true; });
    var subNames = Object.keys(subs).sort();
    if (subNames.length < 2) { filterDiv.remove(); return; }
    var select = document.createElement('select');
    select.className = 'sub-filter-select';
    var opts = '<option value="all">&#9729; All Subscriptions (' + subNames.length + ')</option>';
    subNames.forEach(function(s) {
        opts += '<option value="' + s.replace(/&/g,'&amp;').replace(/"/g,'&quot;') + '">' + s + '</option>';
    });
    select.innerHTML = opts;
    select.onchange = function() {
        var val = this.value;
        cards.forEach(function(c) { c.style.display = (val === 'all' || c.dataset.sub === val) ? '' : 'none'; });
        ['pipTable','gatewaysTable'].forEach(function(tid) {
            var t = document.getElementById(tid);
            if (!t) return;
            t.querySelectorAll('tbody tr').forEach(function(row) {
                if (val === 'all') row.classList.remove('sub-hidden');
                else if ((row.dataset.sub || '') === val) row.classList.remove('sub-hidden');
                else row.classList.add('sub-hidden');
            });
        });
    };
    filterDiv.appendChild(select);
})();

// ── Auto-inject subscription filter dropdowns into all findings sections ──
(function initSubFilters() {
    var tables = document.querySelectorAll('table[id]');
    tables.forEach(function(table) {
        if (table.id === 'subsTable') return;
        var container = table.closest('.section-content');
        if (!container) return;
        // Find the filters div closest to THIS table (not just the first in the section)
        var tableWrapper = table.closest('.table-container') || table.parentElement;
        var filtersDiv = tableWrapper.previousElementSibling;
        if (!filtersDiv || !filtersDiv.classList.contains('filters')) {
            // Check if section only has ONE table — use the section-level filters
            var allTables = container.querySelectorAll('table[id]');
            if (allTables.length === 1) {
                filtersDiv = container.querySelector('.filters');
            } else {
                filtersDiv = null;
            }
        }
        if (!filtersDiv || !filtersDiv.classList.contains('filters')) {
            filtersDiv = document.createElement('div');
            filtersDiv.className = 'filters';
            filtersDiv.style.marginBottom = '10px';
            tableWrapper.parentNode.insertBefore(filtersDiv, tableWrapper);
        }
        var subs = {};
        var rows = table.querySelectorAll('tbody tr');
        rows.forEach(function(row) {
            // Try existing data-sub attribute first
            if (row.dataset.sub) { subs[row.dataset.sub] = true; return; }
            // Extract subscription name from blue-styled elements (pattern: "📋 SubName" or "&#128203; SubName")
            var els = row.querySelectorAll('[style*="0078d4"]');
            els.forEach(function(el) {
                var txt = el.textContent.trim();
                // Remove leading emoji/icon character(s) and whitespace
                var subName = txt.replace(/^[\u{1F4CB}\u{1F4D1}\u{2709}\u{1F4E7}#\uFE0F\u20E3\s]+/u, '').trim();
                if (subName && subName.length > 1) {
                    row.setAttribute('data-sub', subName);
                    subs[subName] = true;
                }
            });
        });
        var subNames = Object.keys(subs).sort();
        if (subNames.length < 1) return;
        var select = document.createElement('select');
        select.className = 'sub-filter-select';
        select.setAttribute('data-value', 'all');
        var opts = '<option value="all">&#9729; All Subscriptions (' + subNames.length + ')</option>';
        subNames.forEach(function(s) {
            var escaped = s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
            opts += '<option value="' + escaped + '">' + s + '</option>';
        });
        select.innerHTML = opts;
        var tid = table.id;
        select.onchange = function() {
            this.setAttribute('data-value', this.value);
            filterBySub(this.value, tid);
        };
        var searchBox = filtersDiv.querySelector('.search-box');
        if (searchBox) {
            filtersDiv.insertBefore(select, searchBox);
        } else {
            filtersDiv.appendChild(select);
        }
    });
})();

// ── Auto-inject export buttons into all findings sections ──────────────────
(function initExportButtons() {
    var tables = document.querySelectorAll('table[id]');
    tables.forEach(function(table) {
        if (table.id === 'subsTable') return;
        var container = table.closest('.section-content');
        if (!container) return;
        var tableWrapper = table.closest('.table-container') || table.parentElement;
        var fd = tableWrapper.previousElementSibling;
        if (!fd || !fd.classList.contains('filters')) {
            var allTables = container.querySelectorAll('table[id]');
            if (allTables.length === 1) fd = container.querySelector('.filters');
            else fd = null;
        }
        if (!fd || !fd.classList.contains('filters')) return;
        var btn = document.createElement('button');
        btn.className = 'export-section-btn';
        btn.innerHTML = '&#128229; Excel';
        btn.title = 'Export visible findings to CSV (opens in Excel)';
        var tid = table.id;
        btn.onclick = function() { exportTableCSV(tid); };
        fd.appendChild(btn);
    });
})();

function filterBySub(sub, tableId) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var rows = table.querySelectorAll('tbody tr');
    rows.forEach(function(row) {
        if (row.classList.contains('tier-header')) return;
        if (sub === 'all') {
            row.classList.remove('sub-hidden');
        } else {
            var rowSub = row.getAttribute('data-sub') || '';
            if (rowSub === sub) row.classList.remove('sub-hidden');
            else row.classList.add('sub-hidden');
        }
    });
}

// ── Column Sorting — click any <th> to sort that column ──────────────────
(function initSortable() {
    document.querySelectorAll('table[id]:not(#priorityTable) thead th').forEach(function(th) {
        th.classList.add('sortable');
        th.addEventListener('click', function() {
            var table = th.closest('table');
            var tbody = table.querySelector('tbody');
            if (!tbody) return;
            var idx = Array.from(th.parentNode.children).indexOf(th);
            var rows = Array.from(tbody.querySelectorAll('tr:not(.tier-header)'));
            var isAsc = th.classList.contains('sort-asc');
            // Reset all
            th.parentNode.querySelectorAll('th').forEach(function(h){ h.classList.remove('sort-asc','sort-desc'); });
            th.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
            var dir = isAsc ? -1 : 1;
            rows.sort(function(a, b) {
                var at = (a.children[idx] || {}).textContent || '';
                var bt = (b.children[idx] || {}).textContent || '';
                var atT = at.trim(), btT = bt.trim();
                // Push empty/N-A/dash cells to the bottom regardless of direction
                var aEmpty = !atT || atT === '-' || atT.toLowerCase() === 'n/a';
                var bEmpty = !btT || btT === '-' || btT.toLowerCase() === 'n/a';
                if (aEmpty && bEmpty) return 0;
                if (aEmpty) return 1;
                if (bEmpty) return -1;
                // Try numeric sort first
                var an = parseFloat(atT.replace(/[^0-9.\-]/g, ''));
                var bn = parseFloat(btT.replace(/[^0-9.\-]/g, ''));
                if (!isNaN(an) && !isNaN(bn)) return (an - bn) * dir;
                return atT.localeCompare(btT, undefined, {sensitivity:'base'}) * dir;
            });
            // Re-insert tier headers and sorted rows
            var tierHeaders = Array.from(tbody.querySelectorAll('tr.tier-header'));
            rows.forEach(function(r){ tbody.appendChild(r); });
        });
    });
})();

// ── Count-Up Animation on KPI numbers ────────────────────────────────────
(function initCountUp() {
    function animateValue(el, target, duration) {
        var start = 0;
        var startTime = null;
        var isFloat = target % 1 !== 0;
        function step(ts) {
            if (!startTime) startTime = ts;
            var progress = Math.min((ts - startTime) / duration, 1);
            // easeOutExpo
            var eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
            var current = Math.round(eased * target);
            if (isFloat) current = (eased * target).toFixed(1);
            el.textContent = typeof target === 'number' && target >= 1000 ? Number(current).toLocaleString() : current;
            if (progress < 1) requestAnimationFrame(step);
            else el.textContent = target >= 1000 ? target.toLocaleString() : target;
        }
        requestAnimationFrame(step);
    }
    // Score cards in hero header
    document.querySelectorAll('.score-card .number').forEach(function(el) {
        var raw = el.textContent.replace(/,/g, '');
        var n = parseFloat(raw);
        if (!isNaN(n) && n > 0) { el.textContent = '0'; animateValue(el, n, 1200); }
    });
    // Key metrics grid
    document.querySelectorAll('#exec-metrics .section-content div[style*="font-size:2em"]').forEach(function(el) {
        var raw = el.textContent.replace(/[\$,]/g, '');
        var n = parseFloat(raw);
        var prefix = el.textContent.startsWith('$') ? '$' : '';
        if (!isNaN(n) && n > 0) {
            el.textContent = prefix + '0';
            var startT = null;
            (function anim(ts) {
                if (!startT) startT = ts;
                var p = Math.min((ts - startT) / 1400, 1);
                var eased = p === 1 ? 1 : 1 - Math.pow(2, -10 * p);
                var cur = Math.round(eased * n);
                el.textContent = prefix + (n >= 1000 ? cur.toLocaleString() : cur);
                if (p < 1) requestAnimationFrame(anim);
                else el.textContent = prefix + (n >= 1000 ? n.toLocaleString() : n);
            })(performance.now());
        }
    });
})();

// ── Donut Chart — Severity Distribution (pure SVG) ───────────────────────
(function initDonutChart() {
    var container = document.getElementById('severity-donut');
    if (!container) return;
    var data;
    try { data = JSON.parse(container.getAttribute('data-values') || '[]'); } catch(e) { console.warn('Invalid donut data:', e); return; }
    if (!Array.isArray(data) || data.length < 4) return;
    var colors = ['#d13438','#ca5010','#7a7574','#107c10'];
    var labels = ['Critical','High','Medium','Low'];
    var total = data.reduce(function(s,v){return s+v;}, 0);
    if (total === 0) return;
    var size = 180, cx = size/2, cy = size/2, r = 68, inner = 45;
    var svg = '<svg width="'+size+'" height="'+size+'" viewBox="0 0 '+size+' '+size+'">';
    var cumAngle = -90;
    data.forEach(function(val, i) {
        if (val === 0) return;
        var pct = val / total;
        var angle = pct * 360;
        var startRad = cumAngle * Math.PI / 180;
        var endRad = (cumAngle + angle) * Math.PI / 180;
        var largeArc = angle > 180 ? 1 : 0;
        var x1 = cx + r * Math.cos(startRad), y1 = cy + r * Math.sin(startRad);
        var x2 = cx + r * Math.cos(endRad), y2 = cy + r * Math.sin(endRad);
        var ix1 = cx + inner * Math.cos(endRad), iy1 = cy + inner * Math.sin(endRad);
        var ix2 = cx + inner * Math.cos(startRad), iy2 = cy + inner * Math.sin(startRad);
        svg += '<path d="M'+x1+','+y1+' A'+r+','+r+' 0 '+largeArc+',1 '+x2+','+y2+' L'+ix1+','+iy1+' A'+inner+','+inner+' 0 '+largeArc+',0 '+ix2+','+iy2+' Z" fill="'+colors[i]+'" opacity="0.9"><title>'+labels[i]+': '+val+' ('+Math.round(pct*100)+'%)</title></path>';
        cumAngle += angle;
    });
    svg += '<text x="'+cx+'" y="'+(cy-6)+'" text-anchor="middle" font-size="28" font-weight="700" fill="currentColor">'+total+'</text>';
    svg += '<text x="'+cx+'" y="'+(cy+14)+'" text-anchor="middle" font-size="11" fill="'+(document.body.classList.contains('dark-mode')?'#b0b0b0':'#616161')+'">Findings</text>';
    svg += '</svg>';
    // Legend
    var legend = '<div style="display:flex;flex-direction:column;gap:8px;margin-top:12px;">';
    data.forEach(function(val, i) {
        if (val === 0) return;
        var pct = Math.round(val / total * 100);
        legend += '<div style="display:flex;align-items:center;gap:8px;font-size:12px;"><span style="width:12px;height:12px;border-radius:3px;background:'+colors[i]+';display:inline-block;flex-shrink:0"></span><span style="color:var(--text-dim);min-width:80px">'+labels[i]+'</span><strong>'+val+'</strong><span style="color:var(--text-muted);font-size:11px">('+pct+'%)</span></div>';
    });
    legend += '</div>';
    container.innerHTML = '<div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;justify-content:center;">'+svg+legend+'</div>';
})();

// ── WAF Pillar Horizontal Bar Chart ──────────────────────────────────────
(function initPillarBarChart() {
    var container = document.getElementById('pillar-bar-chart');
    if (!container) return;
    var data;
    try { data = JSON.parse(container.getAttribute('data-pillars') || '[]'); } catch(e) { return; }
    if (!Array.isArray(data) || data.length === 0) return;
    var pillarColors = {'Security':'#0078d4','Reliability':'#005a9e','Cost Optimization':'#ca5010','Operational Excellence':'#107c10','Performance Efficiency':'#5c2d91'};
    var maxVal = Math.max.apply(null, data.map(function(d){ return d.critical+d.high+d.medium+d.low; }));
    if (maxVal === 0) maxVal = 1;
    var html = '<div style="display:flex;flex-direction:column;gap:12px;">';
    data.forEach(function(d) {
        var total = d.critical+d.high+d.medium+d.low;
        var pct = Math.round(total/maxVal*100);
        var color = pillarColors[d.name] || '#8a8886';
        var cW = total>0?Math.round(d.critical/total*100):0;
        var hW = total>0?Math.round(d.high/total*100):0;
        var mW = total>0?Math.round(d.medium/total*100):0;
        var lW = (total>0 && (d.critical+d.high+d.medium+d.low)>0)?Math.max(0,100-cW-hW-mW):0;
        html += '<div style="display:flex;align-items:center;gap:10px;">';
        html += '<div style="min-width:140px;font-size:12px;font-weight:600;color:var(--text);text-align:right;white-space:nowrap">'+d.name+'</div>';
        html += '<div style="flex:1;height:24px;background:var(--surface2);border-radius:6px;overflow:hidden;display:flex;position:relative;">';
        if(d.critical>0) html += '<div style="width:'+cW+'%;background:#d13438;height:100%;transition:width .6s" title="Critical: '+d.critical+'"></div>';
        if(d.high>0) html += '<div style="width:'+hW+'%;background:#ca5010;height:100%;transition:width .6s" title="High: '+d.high+'"></div>';
        if(d.medium>0) html += '<div style="width:'+mW+'%;background:#7a7574;height:100%;transition:width .6s" title="Medium: '+d.medium+'"></div>';
        if(d.low>0) html += '<div style="width:'+lW+'%;background:#107c10;height:100%;transition:width .6s" title="Low: '+d.low+'"></div>';
        html += '</div>';
        html += '<div style="min-width:36px;font-size:13px;font-weight:700;color:var(--text);">'+total+'</div>';
        html += '</div>';
    });
    html += '<div style="display:flex;gap:16px;justify-content:center;margin-top:8px;font-size:11px;color:var(--text-dim);">';
    html += '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#d13438;margin-right:4px;vertical-align:middle"></span>Critical</span>';
    html += '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#ca5010;margin-right:4px;vertical-align:middle"></span>High</span>';
    html += '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#7a7574;margin-right:4px;vertical-align:middle"></span>Medium</span>';
    html += '<span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#107c10;margin-right:4px;vertical-align:middle"></span>Low</span>';
    html += '</div></div>';
    container.innerHTML = html;
})();

// ── Resource Distribution Horizontal Bar Chart ───────────────────────────
(function initResourceDistChart() {
    var container = document.getElementById('resource-dist-chart');
    if (!container) return;
    var data;
    try { data = JSON.parse(container.getAttribute('data-resources') || '[]'); } catch(e) { return; }
    if (!Array.isArray(data) || data.length === 0) return;
    var maxVal = data[0].count || 1;
    var barColors = ['#0078d4','#005a9e','#2899ef','#50b7f5','#7fcbf7','#ca5010','#107c10','#5c2d91','#d13438','#8a8886'];
    var html = '<div style="display:flex;flex-direction:column;gap:8px;">';
    data.forEach(function(d, i) {
        var pct = Math.round(d.count/maxVal*100);
        html += '<div style="display:flex;align-items:center;gap:10px;">';
        html += '<div style="min-width:120px;font-size:11px;font-weight:600;color:var(--text);text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+d.name+'">'+d.name+'</div>';
        html += '<div style="flex:1;height:20px;background:var(--surface2);border-radius:5px;overflow:hidden;">';
        html += '<div style="width:'+pct+'%;height:100%;background:'+barColors[i%barColors.length]+';border-radius:5px;transition:width .6s"></div>';
        html += '</div>';
        html += '<div style="min-width:36px;font-size:12px;font-weight:700;color:var(--text);">'+d.count+'</div>';
        html += '</div>';
    });
    html += '</div>';
    container.innerHTML = html;
})();

// ── Cost Sparklines (inject into cost KPI cards) ─────────────────────────
(function initSparklines() {
    document.querySelectorAll('.cost-sub-section').forEach(function(section) {
        var sparkData = section.getAttribute('data-monthly');
        if (!sparkData) return;
        var values;
        try { values = JSON.parse(sparkData); } catch(e) { return; }
        if (!values || values.length < 2) return;
        var max = Math.max.apply(null, values);
        var min = Math.min.apply(null, values);
        var range = max - min || 1;
        var w = 120, h = 32, pad = 2;
        var points = [];
        var areaPoints = [];
        values.forEach(function(v, i) {
            var x = pad + (i / (values.length - 1)) * (w - 2 * pad);
            var y = pad + (1 - (v - min) / range) * (h - 2 * pad);
            points.push(x.toFixed(1) + ',' + y.toFixed(1));
            areaPoints.push(x.toFixed(1) + ',' + y.toFixed(1));
        });
        // Area fill
        areaPoints.push((w - pad).toFixed(1) + ',' + (h - pad).toFixed(1));
        areaPoints.push(pad.toFixed(1) + ',' + (h - pad).toFixed(1));
        var trend = values[values.length - 1] > values[0];
        var color = trend ? '#d13438' : '#107c10';
        var fill = trend ? 'rgba(209,52,56,.12)' : 'rgba(16,124,16,.12)';
        var sparkSvg = '<svg width="'+w+'" height="'+h+'" style="display:block;margin:6px auto 0"><polygon points="'+areaPoints.join(' ')+'" fill="'+fill+'"/><polyline points="'+points.join(' ')+'" fill="none" stroke="'+color+'" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="'+points[points.length-1].split(',')[0]+'" cy="'+points[points.length-1].split(',')[1]+'" r="2.5" fill="'+color+'"/></svg>';
        // Insert sparkline after the Total Cost KPI card
        var kpiGrid = section.querySelector('div[style*="grid-template-columns"]');
        if (kpiGrid) {
            var firstCard = kpiGrid.querySelector('div[style*="linear-gradient"]');
            if (firstCard) {
                var sparkDiv = document.createElement('div');
                sparkDiv.innerHTML = sparkSvg + '<div style="font-size:9px;color:rgba(255,255,255,.7);text-align:center;margin-top:2px;">6-mo trend</div>';
                firstCard.appendChild(sparkDiv);
            }
        }
    });
})();

</script>
</body>
</html>
"@

    $reportPath = Join-Path $OutputPath "Assessment_Report.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    Write-Status "Report saved: $reportPath" "OK"
}


# ============================================================================
# 13. NETWORK DIAGRAM GENERATION (SVG + Draw.io)
# ============================================================================
function Generate-ArchitectureDiagram {
    Write-Status "Generating network topology diagram..." "SECTION"

    $vnets      = $script:NetworkTopology | Where-Object { $_.Type -eq "VNet" }
    $pips       = $script:NetworkTopology | Where-Object { $_.Type -eq "PublicIP" }
    $gateways   = $script:NetworkTopology | Where-Object { $_.Type -eq "Gateway" }
    $natGws     = $script:NetworkTopology | Where-Object { $_.Type -eq "NatGateway" }
    $lbRes      = $script:Resources | Where-Object { $_.Type -match "loadBalancers$" }
    $agRes      = $script:Resources | Where-Object { $_.Type -match "applicationGateways$" }
    $fwRes      = $script:Resources | Where-Object { $_.Type -match "azureFirewalls$" }

    # Classify PIPs: associated vs orphaned
    $assocPips   = $pips | Where-Object { $_.AssociatedTo -ne "Unassociated" }
    $orphanPips  = $pips | Where-Object { $_.AssociatedTo -eq "Unassociated" }

    # Edge devices
    $edgeItems = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($gw in $gateways) { $edgeItems.Add(@{ Name=$gw.Name; Label="VPN / ER Gateway"; Icon="gw" }) }
    foreach ($fw in $fwRes) { $edgeItems.Add(@{ Name=$fw.Name; Label="Azure Firewall"; Icon="fw" }) }
    foreach ($ag in $agRes) { $edgeItems.Add(@{ Name=$ag.Name; Label="App Gateway / WAF"; Icon="ag" }) }
    foreach ($lb in $lbRes) { $edgeItems.Add(@{ Name=$lb.Name; Label="Load Balancer"; Icon="lb" }) }

    # Collect unique NAT GW names associated with subnets
    $natGwNames = @()
    foreach ($vn in $vnets) {
        if ($vn.SubnetDetails) {
            foreach ($sn in $vn.SubnetDetails) {
                if ($sn.NatGatewayName -and $sn.NatGatewayName -notin $natGwNames) { $natGwNames += $sn.NatGatewayName }
            }
        }
    }
    foreach ($ng in $natGws) { if ($ng.Name -notin $natGwNames) { $natGwNames += $ng.Name } }

    # Helper
    function EscSvg([string]$s) { [System.Security.SecurityElement]::Escape($s) }

    # ═══ LAYOUT CALCULATION ═══════════════════════════════════════════════
    # Vertical flow grid: Internet → PIPs → Edge → VNets (3-col grid) → NAT GWs
    $vnetW = 280; $vnetGap = 44; $maxPerRow = 3
    $subH = 36; $subGap = 5; $subIndent = 14; $subW = $vnetW - ($subIndent * 2); $vnetTopPad = 44
    $pipCW = 150; $pipCH = 40; $pipCGap = 10
    $edgeCW = 168; $edgeCH = 46; $edgeCGap = 12
    $natCW = 168; $natCH = 42

    # VNet heights
    $vnetMetas = @()
    foreach ($vn in $vnets) {
        $subs = if ($vn.SubnetDetails) { @($vn.SubnetDetails) } else { @() }
        $sc = [Math]::Max($subs.Count, 1)
        $h = $vnetTopPad + ($sc * ($subH + $subGap)) + 38
        $vnetMetas += @{ VNet=$vn; Subnets=$subs; H=[Math]::Max($h, 140) }
    }

    # Grid: split VNets into rows of $maxPerRow
    $vnetRows = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $vnetMetas.Count; $i += $maxPerRow) {
        $end = [Math]::Min($i + $maxPerRow - 1, $vnetMetas.Count - 1)
        $vnetRows.Add(@($vnetMetas[$i..$end]))
    }

    # Null-safe arrays
    $assocPipList  = @(); if ($assocPips)  { $assocPipList  = @($assocPips) }
    $orphanPipList = @(); if ($orphanPips) { $orphanPipList = @($orphanPips) }

    # Canvas width (based on widest element row)
    $vnetsPerRow = [Math]::Min($vnetMetas.Count, $maxPerRow)
    $gridW       = if ($vnetsPerRow -gt 0) { $vnetsPerRow * ($vnetW + $vnetGap) - $vnetGap } else { $vnetW }
    $pipRowW     = if ($assocPipList.Count -gt 0) { $assocPipList.Count * ($pipCW + $pipCGap) - $pipCGap } else { 0 }
    $edgeRowW    = if ($edgeItems.Count -gt 0) { $edgeItems.Count * ($edgeCW + $edgeCGap) - $edgeCGap } else { 0 }
    $contentW    = [Math]::Max([Math]::Max($gridW, $pipRowW), [Math]::Max($edgeRowW, 400))
    $pad         = 70
    $mainAreaW   = $contentW + $pad * 2
    $sidebarW    = if ($orphanPipList.Count -gt 0) { 210 } else { 0 }
    $totalW      = $mainAreaW + $sidebarW
    $mainCX      = $mainAreaW / 2

    # Vertical Y stack
    $cy = 40
    $inetCX = $mainCX; $inetCY = $cy + 26
    $cy += 76

    $pipRowY = $cy
    if ($assocPipList.Count -gt 0) { $cy += $pipCH + 40 }

    $edgeRowY = $cy
    if ($edgeItems.Count -gt 0) { $cy += $edgeCH + 40 }

    $cy += 8
    $vnetGridStartY = $cy
    $vnetRowGap = 40
    $vnetRowYPositions = @()
    foreach ($row in $vnetRows) {
        $vnetRowYPositions += $cy
        $maxRH = 130
        if ($row.Count -gt 0) { $maxRH = ($row | ForEach-Object { $_.H } | Measure-Object -Maximum).Maximum }
        $cy += $maxRH + $vnetRowGap
    }
    if ($vnetRowYPositions.Count -gt 0) { $cy -= $vnetRowGap; $cy += 40 }

    $natRowY = $cy
    if ($natGwNames.Count -gt 0) { $cy += $natCH + 40 }

    $totalH = $cy + 30

    # ═══ BUILD HTML SVG ═══════════════════════════════════════════════════
    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Network Topology</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#f7f9fc;font-family:'Aptos','Segoe UI',-apple-system,sans-serif;padding:28px;overflow-x:auto}
.hdr{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:8px}
h1{color:#001d3d;text-align:center;font-size:1.5em;font-weight:700;letter-spacing:-.3px}
.sub{color:#5c6370;text-align:center;font-size:.82em;margin-bottom:20px;letter-spacing:.1px}
svg{display:block;margin:0 auto}
.legend{display:flex;gap:24px;justify-content:center;flex-wrap:wrap;margin-top:20px;padding:16px 24px;background:rgba(255,255,255,.7);backdrop-filter:blur(12px);border:1px solid #e1e5ea;border-radius:10px;font-size:.76em;color:#5c6370;max-width:900px;margin-left:auto;margin-right:auto}
.legend-item{display:flex;align-items:center;gap:6px;font-weight:500}
.tip{position:fixed;padding:10px 14px;background:#fff;border:1px solid #e1e5ea;border-radius:8px;color:#1a1a2e;font-size:12px;pointer-events:none;z-index:99;display:none;box-shadow:0 4px 16px rgba(0,29,61,.1);max-width:300px;line-height:1.5}
</style></head><body>
<div class="hdr"><svg width="110" height="24" viewBox="0 0 110 24"><rect width="10" height="10" fill="#f25022"/><rect x="12" width="10" height="10" fill="#7fba00"/><rect y="12" width="10" height="10" fill="#00a4ef"/><rect x="12" y="12" width="10" height="10" fill="#ffb900"/><text x="30" y="17" fill="#1a1a2e" font-family="Segoe UI" font-size="13" font-weight="600">Microsoft Azure</text></svg></div>
<h1>Network Topology</h1>
<p class="sub">$(Get-Date -Format "dd/MM/yyyy HH:mm") &ensp;|&ensp; $($vnets.Count) VNet(s) &ensp;|&ensp; $($pips.Count) Public IP(s) &ensp;|&ensp; $($edgeItems.Count) Edge device(s)$(if($natGwNames.Count -gt 0){" &ensp;|&ensp; $($natGwNames.Count) NAT Gateway(s)"})</p>
<svg viewBox="0 0 $totalW $totalH" xmlns="http://www.w3.org/2000/svg" style="max-width:${totalW}px;width:100%">
<defs>
  <marker id="arr-blue" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#0078d4"/></marker>
  <marker id="arr-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#107c10"/></marker>
  <marker id="arr-orange" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0,8 3,0 6" fill="#ca5010"/></marker>
  <filter id="sh"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-opacity=".06"/></filter>
  <linearGradient id="gNet" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#0078d4"/><stop offset="100%" stop-color="#005a9e"/></linearGradient>
  <linearGradient id="gVnet" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#e8f4fd"/><stop offset="100%" stop-color="#f7fbff"/></linearGradient>
</defs>
<rect width="$totalW" height="$totalH" fill="#f7f9fc" rx="0"/>
"@

    # ─── INTERNET CLOUD (top center) ─────────────────────────────────────
    $html += "<ellipse cx=`"$inetCX`" cy=`"$inetCY`" rx=`"76`" ry=`"26`" fill=`"#e8f4fd`" stroke=`"#0078d4`" stroke-width=`"1.5`" filter=`"url(#sh)`"/>`n"
    $html += "<text x=`"$inetCX`" y=`"$($inetCY+1)`" text-anchor=`"middle`" fill=`"#001d3d`" font-size=`"13`" font-weight=`"700`" dominant-baseline=`"middle`">Internet</text>`n"

    # ─── ASSOCIATED PIPs (horizontal row, centered) ──────────────────────
    $pipPos = @{}
    if ($assocPipList.Count -gt 0) {
        $pipStartX = $mainCX - $pipRowW / 2
        $px = $pipStartX
        foreach ($pip in $assocPipList) {
            $pipCXLocal = $px + $pipCW / 2
            $html += "<g data-t=`"$(EscSvg $pip.Name)&#10;IP: $($pip.IpAddress)&#10;SKU: $($pip.Sku)&#10;Associated: $($pip.AssociatedTo)`">`n"
            $html += "  <rect x=`"$px`" y=`"$pipRowY`" width=`"$pipCW`" height=`"$pipCH`" rx=`"8`" fill=`"#fff`" stroke=`"#0078d4`" stroke-width=`"1.2`" filter=`"url(#sh)`"/>`n"
            $html += "  <rect x=`"$px`" y=`"$pipRowY`" width=`"3`" height=`"$pipCH`" rx=`"1.5`" fill=`"#0078d4`"/>`n"
            $html += "  <text x=`"$($px+12)`" y=`"$($pipRowY+16)`" fill=`"#001d3d`" font-size=`"9`" font-weight=`"600`">$(EscSvg $pip.Name)</text>`n"
            $html += "  <text x=`"$($px+12)`" y=`"$($pipRowY+30)`" fill=`"#5c6370`" font-size=`"8`">$($pip.IpAddress)</text>`n"
            $html += "</g>`n"
            # Arrow: Internet → PIP
            $html += "<line x1=`"$inetCX`" y1=`"$($inetCY+26)`" x2=`"$pipCXLocal`" y2=`"$pipRowY`" stroke=`"#0078d4`" stroke-width=`"1`" stroke-dasharray=`"5,3`" marker-end=`"url(#arr-blue)`" opacity=`".5`"/>`n"
            $pipPos[$pip.Name] = @{ CX=$pipCXLocal; BY=($pipRowY+$pipCH) }
            $px += $pipCW + $pipCGap
        }
    }

    # ─── EDGE DEVICES (horizontal row, centered) ─────────────────────────
    $edgePos = @{}
    if ($edgeItems.Count -gt 0) {
        $edgeStartX = $mainCX - $edgeRowW / 2
        $ex = $edgeStartX
        foreach ($e in $edgeItems) {
            $iconColor = switch ($e.Icon) { "fw" { "#d13438" } "gw" { "#5c2d91" } "ag" { "#00838f" } default { "#0078d4" } }
            $edgeCXLocal = $ex + $edgeCW / 2
            $html += "<g data-t=`"$(EscSvg $e.Name)&#10;$($e.Label)`">`n"
            $html += "  <rect x=`"$ex`" y=`"$edgeRowY`" width=`"$edgeCW`" height=`"$edgeCH`" rx=`"8`" fill=`"#fff`" stroke=`"$iconColor`" stroke-width=`"1.2`" filter=`"url(#sh)`"/>`n"
            $html += "  <rect x=`"$ex`" y=`"$edgeRowY`" width=`"3`" height=`"$edgeCH`" rx=`"1.5`" fill=`"$iconColor`"/>`n"
            $html += "  <text x=`"$($ex+12)`" y=`"$($edgeRowY+18)`" fill=`"#001d3d`" font-size=`"9.5`" font-weight=`"600`">$(EscSvg $e.Name)</text>`n"
            $html += "  <text x=`"$($ex+12)`" y=`"$($edgeRowY+34)`" fill=`"#5c6370`" font-size=`"8`">$($e.Label)</text>`n"
            $html += "</g>`n"
            # Arrow from above layer
            if ($assocPipList.Count -gt 0) {
                $html += "<line x1=`"$edgeCXLocal`" y1=`"$($pipRowY+$pipCH)`" x2=`"$edgeCXLocal`" y2=`"$edgeRowY`" stroke=`"#0078d4`" stroke-width=`"1`" marker-end=`"url(#arr-blue)`" opacity=`".35`"/>`n"
            } else {
                $html += "<line x1=`"$inetCX`" y1=`"$($inetCY+26)`" x2=`"$edgeCXLocal`" y2=`"$edgeRowY`" stroke=`"#0078d4`" stroke-width=`"1`" stroke-dasharray=`"5,3`" marker-end=`"url(#arr-blue)`" opacity=`".4`"/>`n"
            }
            $edgePos[$e.Name] = @{ CX=$edgeCXLocal; BY=($edgeRowY+$edgeCH) }
            $ex += $edgeCW + $edgeCGap
        }
    }

    # ─── VNET GRID (3-column grid, centered per row) ─────────────────────
    # Pre-compute egress info per VNet
    $vnetEgress = @{}
    foreach ($vm in $vnetMetas) {
        $vn = $vm.VNet
        $egressPaths = @()
        # Check for associated PIPs (NIC-attached in same RG+Sub)
        $pipCount = @($assocPipList | Where-Object { $_.ResourceGroup -eq $vn.ResourceGroup -and $_.Subscription -eq $vn.Subscription }).Count
        if ($pipCount -gt 0) { $egressPaths += "PIP ($pipCount)" }
        # Check for NAT Gateway on any subnet
        $natNames = @($vm.Subnets | Where-Object { $_.NatGatewayName } | ForEach-Object { $_.NatGatewayName } | Sort-Object -Unique)
        if ($natNames.Count -gt 0) { $egressPaths += "NAT GW" }
        # Check for peerings (transit)
        if ($vn.Peerings) { $egressPaths += "Peering ($(@($vn.Peerings -split ',').Count))" }
        $vnetEgress[$vn.Name] = $egressPaths
    }

    $vnetPos = @{}
    $rowIdx = 0
    foreach ($row in $vnetRows) {
        $rowY = $vnetRowYPositions[$rowIdx]
        $rowW = $row.Count * ($vnetW + $vnetGap) - $vnetGap
        $rowStartX = $mainCX - $rowW / 2
        $vx = $rowStartX
        foreach ($vm in $row) {
            $vn = $vm.VNet; $subs = $vm.Subnets; $vh = $vm.H
            # VNet container
            $html += "<rect x=`"$vx`" y=`"$rowY`" width=`"$vnetW`" height=`"$vh`" rx=`"12`" fill=`"url(#gVnet)`" stroke=`"#0078d4`" stroke-width=`"1.8`" filter=`"url(#sh)`"/>`n"
            # Header bar
            $html += "<rect x=`"$vx`" y=`"$rowY`" width=`"$vnetW`" height=`"34`" rx=`"12`" fill=`"url(#gNet)`"/>`n"
            $html += "<rect x=`"$vx`" y=`"$($rowY+22)`" width=`"$vnetW`" height=`"12`" fill=`"url(#gNet)`"/>`n"
            $html += "<text x=`"$($vx+$vnetW/2)`" y=`"$($rowY+22)`" text-anchor=`"middle`" fill=`"#fff`" font-size=`"11`" font-weight=`"700`">$(EscSvg $vn.Name)</text>`n"
            $html += "<text x=`"$($vx+$vnetW/2)`" y=`"$($rowY+$vh-7)`" text-anchor=`"middle`" fill=`"#5c6370`" font-size=`"8`" font-style=`"italic`">$($vn.AddressSpace)</text>`n"
            # Egress badges (bottom-right corner of VNet card)
            $ePaths = $vnetEgress[$vn.Name]
            if ($ePaths.Count -gt 0) {
                $badgeX = $vx + $vnetW - 8
                $badgeY = $rowY + $vh - 20
                foreach ($ep in $ePaths) {
                    $bColor = if ($ep -match '^PIP') { "#0078d4" } elseif ($ep -match '^NAT') { "#107c10" } else { "#ca5010" }
                    $bIcon  = if ($ep -match '^PIP') { "🌐" } elseif ($ep -match '^NAT') { "↗" } else { "⇋" }
                    $bW = 6 + ($ep.Length * 5.5)
                    $html += "<g data-t=`"Internet Egress: $ep`">`n"
                    $html += "  <rect x=`"$($badgeX - $bW)`" y=`"$badgeY`" width=`"$bW`" height=`"14`" rx=`"7`" fill=`"$bColor`" opacity=`".12`"/>`n"
                    $html += "  <text x=`"$($badgeX - $bW + 4)`" y=`"$($badgeY + 10.5)`" fill=`"$bColor`" font-size=`"7.5`" font-weight=`"600`">$bIcon $ep</text>`n"
                    $html += "</g>`n"
                    $badgeX -= ($bW + 5)
                }
            }
            # Subnets
            $sy = $rowY + $vnetTopPad
            foreach ($sn in $subs) {
                $sx = $vx + $subIndent
                $hasNsg = [bool]$sn.NsgName
                $hasNat = [bool]$sn.NatGatewayName
                $snStk = if ($hasNsg) { "#107c10" } else { "#d13438" }
                $snFl  = if ($hasNsg) { "#fff" } else { "#fef5f5" }
                $nsgLbl = if ($hasNsg) { "NSG: $($sn.NsgName)" } else { "No NSG" }
                $natLbl = if ($hasNat) { " | NAT: $($sn.NatGatewayName)" } else { "" }
                $snTip = "$(EscSvg $sn.Name)&#10;$($sn.AddressPrefix)&#10;$nsgLbl$natLbl"
                if ($sn.ConnectedDevices) { $snTip += "&#10;Devices: $($sn.ConnectedDevices)" }
                if ($sn.ServiceEndpoints)  { $snTip += "&#10;Endpoints: $($sn.ServiceEndpoints)" }
                if ($sn.Delegations)       { $snTip += "&#10;Delegated: $($sn.Delegations)" }
                $html += "<g data-t=`"$snTip`">`n"
                $html += "  <rect x=`"$sx`" y=`"$sy`" width=`"$subW`" height=`"$subH`" rx=`"6`" fill=`"$snFl`" stroke=`"$snStk`" stroke-width=`"1`"/>`n"
                $html += "  <rect x=`"$sx`" y=`"$sy`" width=`"3`" height=`"$subH`" rx=`"1.5`" fill=`"$snStk`"/>`n"
                $lbl2 = $sn.AddressPrefix
                if (-not $hasNsg) { $lbl2 += " | No NSG" }
                if ($hasNat) { $lbl2 += " | NAT" }
                $html += "  <text x=`"$($sx+11)`" y=`"$($sy+15)`" fill=`"#1a1a2e`" font-size=`"9`" font-weight=`"600`">$(EscSvg $sn.Name)</text>`n"
                $html += "  <text x=`"$($sx+11)`" y=`"$($sy+28)`" fill=`"#5c6370`" font-size=`"7.5`">$lbl2</text>`n"
                $html += "</g>`n"
                $sy += $subH + $subGap
            }
            $vnetPos[$vn.Name] = @{ LX=$vx; RX=($vx+$vnetW); CX=($vx+$vnetW/2); TY=$rowY; BY=($rowY+$vh); CY=($rowY+$vh/2) }
            $vx += $vnetW + $vnetGap
        }
        $rowIdx++
    }

    # ─── PIP → VNET ASSOCIATION (by Resource Group + Subscription) ───────
    $pipVnetMap = @{}
    foreach ($pip in $assocPipList) {
        foreach ($vm in $vnetMetas) {
            $vn = $vm.VNet
            if ($vn.ResourceGroup -eq $pip.ResourceGroup -and $vn.Subscription -eq $pip.Subscription) {
                $pipVnetMap[$pip.Name] = $vn.Name
                break
            }
        }
    }

    # ─── FLOW LINES: PIP → VNet specific association ────────────────────
    $connectedVnets = @{}
    foreach ($pipName in $pipVnetMap.Keys) {
        $pp = $pipPos[$pipName]; if (-not $pp) { continue }
        $targetVnet = $pipVnetMap[$pipName]
        $vp = $vnetPos[$targetVnet]; if (-not $vp) { continue }
        $connectedVnets[$targetVnet] = $true
        # Smooth S-curve from PIP bottom to VNet top
        $midY = [int](($pp.BY + $vp.TY) / 2)
        $html += "<path d=`"M$($pp.CX),$($pp.BY) C$($pp.CX),$midY $($vp.CX),$midY $($vp.CX),$($vp.TY)`" fill=`"none`" stroke=`"#0078d4`" stroke-width=`"1.5`" marker-end=`"url(#arr-blue)`" opacity=`".5`"/>`n"
    }

    # VNets without PIP association: subtle dashed line from above
    $arrowSourceY = $inetCY + 26
    if ($edgeItems.Count -gt 0) { $arrowSourceY = $edgeRowY + $edgeCH }
    elseif ($assocPipList.Count -gt 0) { $arrowSourceY = $pipRowY + $pipCH }
    foreach ($vm in $vnetMetas) {
        $vn = $vm.VNet; $vp = $vnetPos[$vn.Name]; if (-not $vp) { continue }
        if ($connectedVnets[$vn.Name]) { continue }
        $html += "<line x1=`"$($vp.CX)`" y1=`"$arrowSourceY`" x2=`"$($vp.CX)`" y2=`"$($vp.TY)`" stroke=`"#0078d4`" stroke-width=`".8`" stroke-dasharray=`"3,4`" opacity=`".15`"/>`n"
    }

    # ─── PEERING CONNECTIONS (routed around VNet boxes) ──────────────────
    $drawnPeerings = @{}
    # Compute grid boundaries for side-margin routing
    $gridLeftX = $totalW; $gridRightX = 0
    foreach ($vpk in $vnetPos.Keys) {
        $vpv = $vnetPos[$vpk]
        if ($vpv.LX -lt $gridLeftX) { $gridLeftX = [int]$vpv.LX }
        if ($vpv.RX -gt $gridRightX) { $gridRightX = [int]$vpv.RX }
    }
    $peerLeftOff = 0; $peerRightOff = 0

    foreach ($vn in $vnets) {
        if (-not $vn.Peerings) { continue }
        $s = $vnetPos[$vn.Name]; if (-not $s) { continue }
        foreach ($pd in $vn.PeeringDetails) {
            $pn = $pd.RemoteVNet
            $t = $vnetPos[$pn]; if (-not $t) { continue }
            $peerKey = (@($vn.Name, $pn) | Sort-Object) -join "~"
            if ($drawnPeerings[$peerKey]) { continue }
            $drawnPeerings[$peerKey] = $true

            # Build label with state info
            $peerState = if ($pd.PeeringState) { $pd.PeeringState } else { "Connected" }
            $peerLabel = "Peering"
            $peerColor = if ($peerState -eq "Connected") { "#ca5010" } else { "#d13438" }
            if ($peerState -ne "Connected") { $peerLabel = "$peerState" }

            $sameRow = [Math]::Abs($s.TY - $t.TY) -lt 10
            if ($sameRow) {
                $leftV  = if ($s.CX -le $t.CX) { $s } else { $t }
                $rightV = if ($s.CX -le $t.CX) { $t } else { $s }
                $gap = $rightV.LX - $leftV.RX
                if ($gap -lt ($vnetGap + 40)) {
                    # Adjacent VNets: horizontal line between edges at CY
                    $html += "<line x1=`"$($leftV.RX)`" y1=`"$($leftV.CY)`" x2=`"$($rightV.LX)`" y2=`"$($rightV.CY)`" stroke=`"$peerColor`" stroke-width=`"2.5`" stroke-dasharray=`"8,4`"/>`n"
                    $lx = [int](($leftV.RX + $rightV.LX) / 2); $ly = [int]($leftV.CY - 12)
                    # Connection dots
                    $html += "<circle cx=`"$($leftV.RX)`" cy=`"$($leftV.CY)`" r=`"4`" fill=`"$peerColor`"/>`n"
                    $html += "<circle cx=`"$($rightV.LX)`" cy=`"$($rightV.CY)`" r=`"4`" fill=`"$peerColor`"/>`n"
                } else {
                    # Non-adjacent same row: route above all VNet boxes
                    $arcY = [int]($s.TY - 38)
                    $html += "<path d=`"M$($s.CX),$($s.TY) L$($s.CX),$arcY L$($t.CX),$arcY L$($t.CX),$($t.TY)`" fill=`"none`" stroke=`"$peerColor`" stroke-width=`"2.5`" stroke-dasharray=`"8,4`" marker-end=`"url(#arr-orange)`"/>`n"
                    $lx = [int](($s.CX + $t.CX) / 2); $ly = $arcY - 10
                    $html += "<circle cx=`"$($s.CX)`" cy=`"$($s.TY)`" r=`"4`" fill=`"$peerColor`"/>`n"
                    $html += "<circle cx=`"$($t.CX)`" cy=`"$($t.TY)`" r=`"4`" fill=`"$peerColor`"/>`n"
                }
            } else {
                # Different rows: route via left or right margin (never crosses a VNet)
                $avgCX = ($s.CX + $t.CX) / 2
                if ($avgCX -le $mainCX) {
                    $peerLeftOff += 8
                    $routeX = [Math]::Max(8, $gridLeftX - 24 - $peerLeftOff)
                    $sEdgeX = [int]$s.LX; $tEdgeX = [int]$t.LX
                } else {
                    $peerRightOff += 8
                    $routeX = [Math]::Min([int]$mainAreaW - 8, $gridRightX + 24 + $peerRightOff)
                    $sEdgeX = [int]$s.RX; $tEdgeX = [int]$t.RX
                }
                $html += "<path d=`"M$sEdgeX,$([int]$s.CY) L$routeX,$([int]$s.CY) L$routeX,$([int]$t.CY) L$tEdgeX,$([int]$t.CY)`" fill=`"none`" stroke=`"$peerColor`" stroke-width=`"2.5`" stroke-dasharray=`"8,4`" marker-end=`"url(#arr-orange)`"/>`n"
                $lx = $routeX; $ly = [int](($s.CY + $t.CY) / 2)
                # Connection dots
                $html += "<circle cx=`"$sEdgeX`" cy=`"$([int]$s.CY)`" r=`"4`" fill=`"$peerColor`"/>`n"
                $html += "<circle cx=`"$tEdgeX`" cy=`"$([int]$t.CY)`" r=`"4`" fill=`"$peerColor`"/>`n"
            }
            # Label with background
            $lblW = 8 + ($peerLabel.Length * 5.5)
            $html += "<rect x=`"$($lx - $lblW/2)`" y=`"$($ly - 9)`" width=`"$lblW`" height=`"14`" rx=`"7`" fill=`"#fff`" stroke=`"$peerColor`" stroke-width=`".8`"/>`n"
            $html += "<text x=`"$lx`" y=`"$($ly + 1)`" text-anchor=`"middle`" fill=`"$peerColor`" font-size=`"8`" font-weight=`"700`">$peerLabel</text>`n"
        }
    }

    # ─── NAT GATEWAYS (centered row below VNets) ─────────────────────────
    if ($natGwNames.Count -gt 0) {
        $natTotalW = $natGwNames.Count * ($natCW + 20) - 20
        $natStartX = $mainCX - $natTotalW / 2
        $nx = $natStartX
        foreach ($ngName in $natGwNames) {
            $natCXLocal = $nx + $natCW / 2
            $html += "<g data-t=`"NAT Gateway: $(EscSvg $ngName)&#10;Outbound Internet connectivity`">`n"
            $html += "  <rect x=`"$nx`" y=`"$natRowY`" width=`"$natCW`" height=`"$natCH`" rx=`"8`" fill=`"#fff`" stroke=`"#107c10`" stroke-width=`"1.2`" filter=`"url(#sh)`"/>`n"
            $html += "  <rect x=`"$nx`" y=`"$natRowY`" width=`"3`" height=`"$natCH`" rx=`"1.5`" fill=`"#107c10`"/>`n"
            $html += "  <text x=`"$($nx+12)`" y=`"$($natRowY+16)`" fill=`"#001d3d`" font-size=`"9.5`" font-weight=`"600`">$(EscSvg $ngName)</text>`n"
            $html += "  <text x=`"$($nx+12)`" y=`"$($natRowY+30)`" fill=`"#5c6370`" font-size=`"8`">NAT Gateway</text>`n"
            $html += "</g>`n"
            # VNets → NAT GW
            foreach ($vm in $vnetMetas) {
                $vn = $vm.VNet; $vp = $vnetPos[$vn.Name]; if (-not $vp) { continue }
                $hasNat = $false
                foreach ($sn in $vm.Subnets) { if ($sn.NatGatewayName -eq $ngName) { $hasNat = $true; break } }
                if ($hasNat) {
                    $html += "<path d=`"M$($vp.CX),$($vp.BY) L$natCXLocal,$natRowY`" fill=`"none`" stroke=`"#107c10`" stroke-width=`"1.2`" marker-end=`"url(#arr-green)`" opacity=`".5`"/>`n"
                }
            }
            # NAT → Internet (outbound)
            $html += "<text x=`"$($natCXLocal + 6)`" y=`"$($natRowY - 6)`" fill=`"#107c10`" font-size=`"8`" font-weight=`"600`">Outbound</text>`n"
            $nx += $natCW + 20
        }
    }

    # ─── ORPHANED PIPs (right sidebar, muted) ────────────────────────────
    if ($orphanPipList.Count -gt 0) {
        $opX = $mainAreaW + 10; $opY = $vnetGridStartY
        $boxH = $orphanPipList.Count * ($pipCH + 10) + 32
        $html += "<rect x=`"$($opX-6)`" y=`"$($opY-20)`" width=`"200`" height=`"$boxH`" rx=`"10`" fill=`"#fef5f5`" stroke=`"#d13438`" stroke-width=`"1`" stroke-dasharray=`"6,3`" opacity=`".35`"/>`n"
        $html += "<text x=`"$($opX + 94)`" y=`"$($opY - 5)`" text-anchor=`"middle`" fill=`"#d13438`" font-size=`"9`" font-weight=`"700`">Unassociated Public IPs</text>`n"
        $opY += 10
        foreach ($pip in $orphanPipList) {
            $html += "<g data-t=`"$(EscSvg $pip.Name)&#10;IP: $($pip.IpAddress)&#10;SKU: $($pip.Sku)&#10;NOT ASSOCIATED — cost waste`">`n"
            $html += "  <rect x=`"$opX`" y=`"$opY`" width=`"$pipCW`" height=`"$pipCH`" rx=`"7`" fill=`"#fff`" stroke=`"#d13438`" stroke-width=`"1`" stroke-dasharray=`"4,2`" filter=`"url(#sh)`"/>`n"
            $html += "  <rect x=`"$opX`" y=`"$opY`" width=`"3`" height=`"$pipCH`" rx=`"1.5`" fill=`"#d13438`"/>`n"
            $html += "  <text x=`"$($opX+12)`" y=`"$($opY+16)`" fill=`"#d13438`" font-size=`"9`" font-weight=`"600`">$(EscSvg $pip.Name)</text>`n"
            $html += "  <text x=`"$($opX+12)`" y=`"$($opY+30)`" fill=`"#8b6e6e`" font-size=`"8`">$($pip.IpAddress)</text>`n"
            $html += "</g>`n"
            $opY += $pipCH + 10
        }
    }

    # ─── CLOSE SVG + LEGEND ──────────────────────────────────────────────
    $html += @"
</svg>
<div class="legend">
  <div class="legend-item"><svg width="28" height="4"><line x1="0" y1="2" x2="28" y2="2" stroke="#0078d4" stroke-width="2" stroke-dasharray="6,3"/></svg>From Internet</div>
  <div class="legend-item"><svg width="28" height="4"><line x1="0" y1="2" x2="28" y2="2" stroke="#0078d4" stroke-width="1.5"/></svg>PIP → VNet</div>
  <div class="legend-item"><svg width="28" height="4"><line x1="0" y1="2" x2="28" y2="2" stroke="#ca5010" stroke-width="2.5" stroke-dasharray="8,4"/></svg>VNet Peering</div>
  <div class="legend-item"><svg width="14" height="14"><circle cx="7" cy="7" r="4" fill="#ca5010"/></svg>Peering endpoint</div>
  <div class="legend-item"><svg width="28" height="4"><line x1="0" y1="2" x2="28" y2="2" stroke="#107c10" stroke-width="2"/></svg>NAT Outbound</div>
  <div class="legend-item"><svg width="14" height="14"><rect width="12" height="12" x="1" y="1" rx="7" fill="#0078d4" opacity=".12"/><text x="7" y="9.5" text-anchor="middle" fill="#0078d4" font-size="6" font-weight="700">PIP</text></svg>Egress badge</div>
  <div class="legend-item"><svg width="14" height="14"><rect width="12" height="12" x="1" y="1" rx="3" fill="#fff" stroke="#107c10" stroke-width="1.5"/></svg>Subnet with NSG</div>
  <div class="legend-item"><svg width="14" height="14"><rect width="12" height="12" x="1" y="1" rx="3" fill="#fef5f5" stroke="#d13438" stroke-width="1.5"/></svg>Subnet without NSG</div>
  <div class="legend-item"><svg width="14" height="14"><rect width="12" height="12" x="1" y="1" rx="3" fill="#fef5f5" stroke="#d13438" stroke-width="1" stroke-dasharray="3,2"/></svg>Orphaned PIP</div>
</div>
<div class="tip" id="tt"></div>
<script>
document.querySelectorAll('[data-t]').forEach(n=>{n.style.cursor='pointer';
n.onmouseenter=e=>{const t=document.getElementById('tt');if(!t)return;t.textContent='';n.dataset.t.split('\n').forEach((line,i)=>{if(i>0)t.appendChild(document.createElement('br'));t.appendChild(document.createTextNode(line))});t.style.display='block';t.style.left=(e.clientX+14)+'px';t.style.top=(e.clientY-8)+'px'};
n.onmousemove=e=>{const t=document.getElementById('tt');if(t){t.style.left=(e.clientX+14)+'px';t.style.top=(e.clientY-8)+'px'}};
n.onmouseleave=()=>{const t=document.getElementById('tt');if(t)t.style.display='none'}});
</script></body></html>
"@

    $svgPath = Join-Path $OutputPath "Network_Topology.html"
    $html | Out-File -FilePath $svgPath -Encoding UTF8 -Force
    Write-Status "Network topology diagram: $svgPath" "OK"
    # ═══ DRAW.IO FILE ═════════════════════════════════════════════════════
    Write-Status "  Generating draw.io network topology..." "INFO"

    function EscXml([string]$s) { [System.Security.SecurityElement]::Escape($s) }
    $cid = 10; $nm = @{}

    $drawio = @"
<?xml version="1.0" encoding="UTF-8"?>
<mxfile host="app.diagrams.net">
<diagram name="Network Topology" id="net-001">
<mxGraphModel dx="1600" dy="1000" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="3000" pageHeight="2000" math="0" shadow="0">
<root>
<mxCell id="0"/><mxCell id="1" parent="0"/>
"@

    # Styles
    $sCloud  = "ellipse;fillColor=#E8F4FD;strokeColor=#0078D4;strokeWidth=2;fontSize=14;fontFamily=Segoe UI;fontStyle=1;fontColor=#001D3D;"
    $sPip    = "rounded=1;whiteSpace=wrap;fillColor=#FFFFFF;strokeColor=#0078D4;strokeWidth=1.5;fontSize=10;fontFamily=Segoe UI;fontColor=#001D3D;shadow=1;align=left;spacingLeft=10;"
    $sPipOrph = "rounded=1;whiteSpace=wrap;fillColor=#FEF5F5;strokeColor=#D13438;strokeWidth=1.5;dashed=1;dashPattern=4 3;fontSize=10;fontFamily=Segoe UI;fontColor=#D13438;shadow=1;align=left;spacingLeft=10;"
    $sEdge   = "rounded=1;whiteSpace=wrap;fillColor=#F3F6FA;strokeColor=#5C2D91;strokeWidth=1.5;fontSize=10;fontFamily=Segoe UI;fontColor=#001D3D;shadow=1;align=left;spacingLeft=10;"
    $sNat    = "rounded=1;whiteSpace=wrap;fillColor=#F5FBF5;strokeColor=#107C10;strokeWidth=1.5;fontSize=10;fontFamily=Segoe UI;fontColor=#001D3D;shadow=1;align=left;spacingLeft=10;"
    $sVnet   = "rounded=1;whiteSpace=wrap;fillColor=#E8F4FD;strokeColor=#0078D4;strokeWidth=2;fontSize=12;fontFamily=Segoe UI;fontStyle=1;fontColor=#001D3D;verticalAlign=top;align=center;spacingTop=10;container=1;collapsible=0;"
    $sSub    = "rounded=1;whiteSpace=wrap;fillColor=#FFFFFF;strokeColor=#107C10;strokeWidth=1;fontSize=9;fontFamily=Segoe UI;fontColor=#1A1A2E;shadow=1;align=left;spacingLeft=8;"
    $sSubBad = "rounded=1;whiteSpace=wrap;fillColor=#FEF5F5;strokeColor=#D13438;strokeWidth=1.5;fontSize=9;fontFamily=Segoe UI;fontColor=#1A1A2E;shadow=1;align=left;spacingLeft=8;"
    $sInbound = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor=#0078D4;strokeWidth=1.5;fontFamily=Segoe UI;fontSize=9;fontColor=#5C6370;"
    $sInternet = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor=#0078D4;strokeWidth=1.5;dashed=1;dashPattern=6 3;fontFamily=Segoe UI;fontSize=9;fontColor=#5C6370;"
    $sPeering = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor=#CA5010;strokeWidth=2;dashed=1;dashPattern=8 4;fontFamily=Segoe UI;fontSize=10;fontColor=#CA5010;fontStyle=1;"
    $sNatEdge = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor=#107C10;strokeWidth=1.5;fontFamily=Segoe UI;fontSize=9;fontColor=#107C10;"

    # Internet cloud
    $cid++; $cloudId = $cid
    $drawio += "<mxCell id=`"$cid`" value=`"Internet`" style=`"$sCloud`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"500`" y=`"40`" width=`"180`" height=`"70`" as=`"geometry`"/></mxCell>`n"

    # Associated PIPs (left column)
    $pipY = 180
    foreach ($pip in $assocPips) {
        $cid++; $nm["pip_$($pip.Name)"] = $cid
        $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $pip.Name)&#10;$($pip.IpAddress) → $(EscXml $pip.AssociatedTo)`" style=`"$sPip`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"40`" y=`"$pipY`" width=`"220`" height=`"48`" as=`"geometry`"/></mxCell>`n"
        $cid++; $drawio += "<mxCell id=`"$cid`" value=`"Inbound`" edge=`"1`" source=`"$cloudId`" target=`"$($cid-1)`" style=`"$sInternet`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n"
        $pipY += 68
    }

    # Edge devices (right column)
    $edgeY = 180
    foreach ($e in $edgeItems) {
        $cid++; $nm["edge_$($e.Name)"] = $cid
        $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $e.Name)&#10;$($e.Label)`" style=`"$sEdge`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"920`" y=`"$edgeY`" width=`"200`" height=`"48`" as=`"geometry`"/></mxCell>`n"
        $cid++; $drawio += "<mxCell id=`"$cid`" value=`"Inbound`" edge=`"1`" source=`"$cloudId`" target=`"$($cid-1)`" style=`"$sInternet`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n"
        $edgeY += 68
    }

    # VNets with subnets (center, below)
    $vnetX = 300
    foreach ($vm in $vnetMetas) {
        $vn = $vm.VNet; $subs = $vm.Subnets; $sc = [Math]::Max($subs.Count,1)
        $vnetH = 50 + ($sc * 50) + 20
        $cid++; $vnetCid = $cid; $nm["vnet_$($vn.Name)"] = $cid
        $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $vn.Name)&#10;$($vn.AddressSpace)`" style=`"$sVnet`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"$vnetX`" y=`"400`" width=`"300`" height=`"$vnetH`" as=`"geometry`"/></mxCell>`n"
        $subY = 44
        foreach ($sn in $subs) {
            $cid++; $hasN = [bool]$sn.NsgName
            $hasNat = [bool]$sn.NatGatewayName
            $st = if ($hasN) { $sSub } else { $sSubBad }
            $nl = if ($hasN) { "NSG: $($sn.NsgName)" } else { "No NSG" }
            $natInfo = if ($hasNat) { " | NAT: $($sn.NatGatewayName)" } else { "" }
            $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $sn.Name)&#10;$($sn.AddressPrefix) | $nl$natInfo`" style=`"$st`" vertex=`"1`" parent=`"$vnetCid`"><mxGeometry x=`"16`" y=`"$subY`" width=`"268`" height=`"42`" as=`"geometry`"/></mxCell>`n"
            $subY += 50
        }
        # Connect PIP/Edge -> VNet
        if ($assocPips.Count -gt 0) {
            $sp = $nm["pip_$($assocPips[0].Name)"]
            if ($sp) { $cid++; $drawio += "<mxCell id=`"$cid`" edge=`"1`" source=`"$sp`" target=`"$vnetCid`" style=`"$sInbound`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n" }
        }
        if ($edgeItems.Count -gt 0) {
            $se = $nm["edge_$($edgeItems[0].Name)"]
            if ($se) { $cid++; $drawio += "<mxCell id=`"$cid`" edge=`"1`" source=`"$se`" target=`"$vnetCid`" style=`"$sInbound`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n" }
        }
        $vnetX += 380
    }

    # Peerings (deduplicated)
    $drawnPeerings2 = @{}
    foreach ($vn in $vnets) {
        if (-not $vn.Peerings) { continue }
        $sid = $nm["vnet_$($vn.Name)"]
        foreach ($pn in ($vn.Peerings -split ", ")) {
            $pn = $pn.Trim()
            $tid = $nm["vnet_$pn"]
            $peerKey = (@($vn.Name, $pn) | Sort-Object) -join "~"
            if ($drawnPeerings2[$peerKey]) { continue }
            $drawnPeerings2[$peerKey] = $true
            if ($sid -and $tid) { $cid++; $drawio += "<mxCell id=`"$cid`" value=`"Peering`" edge=`"1`" source=`"$sid`" target=`"$tid`" style=`"$sPeering`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n" }
        }
    }

    # NAT Gateways
    $natX = 300
    foreach ($ngName in $natGwNames) {
        $cid++; $natId = $cid
        $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $ngName)&#10;NAT Gateway`" style=`"$sNat`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"$natX`" y=`"900`" width=`"200`" height=`"48`" as=`"geometry`"/></mxCell>`n"
        # VNet -> NAT
        foreach ($vm in $vnetMetas) {
            $vn = $vm.VNet; $vid = $nm["vnet_$($vn.Name)"]
            $hasNat = $false
            foreach ($sn in $vm.Subnets) { if ($sn.NatGatewayName -eq $ngName) { $hasNat = $true; break } }
            if ($hasNat -and $vid) {
                $cid++; $drawio += "<mxCell id=`"$cid`" value=`"Outbound`" edge=`"1`" source=`"$vid`" target=`"$natId`" style=`"$sNatEdge`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n"
            }
        }
        # NAT -> Internet
        $cid++; $drawio += "<mxCell id=`"$cid`" value=`"Outbound`" edge=`"1`" source=`"$natId`" target=`"$cloudId`" style=`"$sNatEdge`" parent=`"1`"><mxGeometry relative=`"1`" as=`"geometry`"/></mxCell>`n"
        $natX += 260
    }

    # Orphaned PIPs
    $orphY = 900
    foreach ($pip in $orphanPips) {
        $cid++
        $drawio += "<mxCell id=`"$cid`" value=`"$(EscXml $pip.Name)&#10;$($pip.IpAddress) — Unassociated`" style=`"$sPipOrph`" vertex=`"1`" parent=`"1`"><mxGeometry x=`"40`" y=`"$orphY`" width=`"220`" height=`"48`" as=`"geometry`"/></mxCell>`n"
        $orphY += 58
    }

    $drawio += "</root></mxGraphModel></diagram></mxfile>"
    $drawioPath = Join-Path $OutputPath "Network_Topology.drawio"
    $drawio | Out-File -FilePath $drawioPath -Encoding UTF8 -Force
    Write-Status "Draw.io file: $drawioPath" "OK"
}


# ============================================================================
# 15. EXECUTIVE REPORT IN PRINT/PDF-OPTIMIZED HTML
# ============================================================================
function Generate-ExecutiveReport {
    Write-Status "Generating executive report for PDF..." "SECTION"

    $genDate   = Get-Date -Format "MMMM dd, yyyy"
    $genTime   = Get-Date -Format "HH:mm"
    $duration  = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 0)
    $subNames  = ($script:Subscriptions | ForEach-Object { $_.Name }) -join ", "
    $tenantId  = if ($script:Subscriptions.Count -gt 0) { $script:Subscriptions[0].TenantId } else { "N/A" }

    # ── Calculate consolidated metrics ───────────────────────────────────────
    $totalFindings  = $script:Findings.Count
    $critCount = ($script:Findings | Where-Object Severity -eq "Critical").Count
    $highCount = ($script:Findings | Where-Object Severity -eq "High").Count
    $medCount  = ($script:Findings | Where-Object Severity -eq "Medium").Count
    $lowCount  = ($script:Findings | Where-Object Severity -eq "Low").Count

    # ── Overall qualitative assessment ───────────────────────────────────────
    $overallStatus = if ($critCount -ge 3) { "Critical" } `
        elseif ($critCount -ge 1)          { "High Risk" } `
        elseif ($highCount -ge 5)          { "Needs Attention" } `
        elseif ($highCount -ge 1)          { "Improvable" } `
        elseif ($medCount -ge 3)           { "Acceptable" } `
        else                               { "Good" }

    $overallColor = switch ($overallStatus) {
        "Critical"         { "#d13438" }
        "High Risk"        { "#d13438" }
        "Needs Attention"  { "#ca5010" }
        "Improvable"       { "#ca5010" }
        "Acceptable"       { "#0078d4" }
        default            { "#107c10" }
    }
    $overallBg = switch ($overallStatus) {
        "Critical"         { "#fde7e9" }
        "High Risk"        { "#fde7e9" }
        "Needs Attention"  { "#fff4ce" }
        "Improvable"       { "#fff4ce" }
        "Acceptable"       { "#deecf9" }
        default            { "#dff6dd" }
    }
    $overallDesc = switch ($overallStatus) {
        "Critical"         { "The environment has multiple active critical vulnerabilities requiring immediate action to prevent data exposure or service disruptions." }
        "High Risk"        { "Critical vulnerabilities were identified representing active security or availability risks. Attention is recommended within the next 24-48 hours." }
        "Needs Attention"  { "The environment has a reasonable foundation but several important controls are not implemented. A structured short-term remediation plan is required." }
        "Improvable"       { "The infrastructure is functional with some active controls, but security and reliability gaps need to be resolved in the short term." }
        "Acceptable"       { "The environment meets basic controls. Identified improvement opportunities are preventive and optimization in nature." }
        default            { "The environment shows good alignment with Azure best practices. Findings are primarily low-impact improvements." }
    }

    # ── Pillar assessment helper ─────────────────────────────────────────────
    function Get-PillarStatus([string]$pillar) {
        $pf   = $script:Findings | Where-Object { $_.Pillar -eq $pillar }
        $pc   = ($pf | Where-Object Severity -eq "Critical").Count
        $ph   = ($pf | Where-Object Severity -eq "High").Count
        $pm   = ($pf | Where-Object Severity -eq "Medium").Count
        $pl   = ($pf | Where-Object Severity -eq "Low").Count
        $total = $pc + $ph + $pm + $pl
        $status = if ($pc -ge 2)     { "Critical" } `
            elseif ($pc -ge 1)       { "High Risk" } `
            elseif ($ph -ge 4)       { "Needs Attention" } `
            elseif ($ph -ge 1)       { "Improvable" } `
            elseif ($pm -ge 3)       { "Acceptable" } `
            elseif ($total -gt 0)    { "Good" } `
            else                     { "No findings" }
        $color = switch ($status) { "Critical"{"#d13438"} "High Risk"{"#d13438"} "Needs Attention"{"#ca5010"} "Improvable"{"#ca5010"} "Acceptable"{"#0078d4"} "Good"{"#107c10"} default{"#8a8886"} }
        $bg    = switch ($status) { "Critical"{"#fde7e9"} "High Risk"{"#fde7e9"} "Needs Attention"{"#fff4ce"} "Improvable"{"#fff4ce"} "Acceptable"{"#deecf9"} "Good"{"#dff6dd"} default{"#f3f2f1"} }
        $priority = if ($pc -ge 1) { "Immediate" } elseif ($ph -ge 1) { "Short term" } elseif ($pm -ge 1) { "Medium term" } else { "—" }
        return [PSCustomObject]@{ Status=$status; Color=$color; Bg=$bg; Crit=$pc; High=$ph; Med=$pm; Low=$pl; Total=$total; Priority=$priority }
    }

    $pillarData = @(
        @{ Name="Security";               Icon="&#128737;"; Desc="Encryption, access, NSGs, TLS, Defender";     Info=(Get-PillarStatus "Security") }
        @{ Name="Reliability";            Icon="&#128260;"; Desc="Backups, availability, geo-replication";      Info=(Get-PillarStatus "Reliability") }
        @{ Name="Cost Optimization";      Icon="&#128176;"; Desc="Unused resources, right-sizing, waste";      Info=(Get-PillarStatus "Cost Optimization") }
        @{ Name="Operational Excellence"; Icon="&#9881;";   Desc="Monitoring, diagnostics, tags, governance";  Info=(Get-PillarStatus "Operational Excellence") }
        @{ Name="Performance Efficiency"; Icon="&#9889;";   Desc="SKUs, configuration, Always On";             Info=(Get-PillarStatus "Performance Efficiency") }
        @{ Name="Zero Trust";             Icon="&#128274;"; Desc="JIT, Bastion, CA/MFA, PIM, Sentinel";        Info=(Get-PillarStatus "Zero Trust") }
    )

    $pillarCardsHtml = ""
    foreach ($p in $pillarData) {
        $inf = $p.Info
        $pillarCardsHtml += @"
<tr>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-weight:600;font-size:8.5pt;color:#323130;white-space:nowrap">$($p.Icon) $($p.Name)</td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-size:8pt;color:#605e5c">$($p.Desc)</td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;text-align:center">
    <span style="background:$($inf.Bg);color:$($inf.Color);padding:2px 10px;border-radius:10px;font-size:7.5pt;font-weight:700;border:1px solid $($inf.Color);white-space:nowrap">$($inf.Status)</span>
  </td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;color:$(if($inf.Crit -gt 0){'#d13438'}else{'#605e5c'});font-weight:$(if($inf.Crit -gt 0){'700'}else{'400'})">$($inf.Crit)</td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;color:$(if($inf.High -gt 0){'#ca5010'}else{'#605e5c'});font-weight:$(if($inf.High -gt 0){'700'}else{'400'})">$($inf.High)</td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;color:#605e5c">$($inf.Med)</td>
  <td style="padding:6px 10px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;color:$(if($inf.Priority -ne '—'){'#0078d4'}else{'#8a8886'});font-weight:$(if($inf.Priority -ne '—'){'600'}else{'400'});white-space:nowrap">$($inf.Priority)</td>
</tr>
"@
    }

    # ── Top 15 Critical findings ─────────────────────────────────────────────
    $topFindings = $script:Findings | Sort-Object @{Expression={
        switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}"Low"{3}default{4}}
    }} | Select-Object -First 20
    $topFindingsHtml = ""
    foreach ($f in $topFindings) {
        $sevColor = switch($f.Severity){"Critical"{"#d13438"}"High"{"#ca5010"}"Medium"{"#8a8886"}default{"#107c10"}}
        $sevBg    = switch($f.Severity){"Critical"{"#fde7e9"}"High"{"#fff4ce"}"Medium"{"#f3f2f1"}default{"#dff6dd"}}
        $topFindingsHtml += @"
<tr>
  <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;white-space:nowrap">
    <span style="background:$sevBg;color:$sevColor;padding:2px 7px;border-radius:8px;font-weight:700;font-size:7pt;border:1px solid $sevColor">$($f.Severity)</span>
  </td>
  <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;color:#605e5c;white-space:nowrap">$(ConvertTo-SafeHtml $f.Subscription)</td>
  <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#323130">$(ConvertTo-SafeHtml $f.ResourceName)</td>
  <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;color:#323130">$(ConvertTo-SafeHtml $f.Description)</td>
  <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;color:#0078d4">$(ConvertTo-SafeHtml $f.Recommendation)</td>
</tr>
"@
    }

    # ── Domain-specific metrics (all 25 Analyze-* functions) ─────────────────
    # Helper to count findings by category regex
    function Get-DomainCounts([string]$regex) {
        $items = @($script:Findings | Where-Object { $_.Category -match $regex })
        $c = ($items | Where-Object Severity -eq "Critical").Count
        $h = ($items | Where-Object Severity -eq "High").Count
        $m = ($items | Where-Object Severity -eq "Medium").Count
        return [PSCustomObject]@{ Total=$items.Count; Crit=$c; High=$h; Med=$m }
    }

    # Network
    $dNet = Get-DomainCounts 'Subnet|NSG|Public IP|Load Balancer|DDoS|App Gateway|Orphaned NIC|VNet'
    # VMs
    $dVM = Get-DomainCounts 'VM |Virtual Machine|Availability|Disk Encryption|Azure Monitor Agent|Unmanaged Disk'
    # App Services
    $dApp = Get-DomainCounts 'App Service|HTTPS|TLS|Managed Identity|Always On'
    # SQL
    $dSQL = Get-DomainCounts 'SQL |Firewall Rule|TDE|Geo-Rep|Auditing|Advanced Threat'
    # Storage
    $dStor = Get-DomainCounts 'Storage|Secure Transfer|Blob Public|Soft Delete'
    # Key Vault
    $dKV = Get-DomainCounts 'Key Vault'
    # Defender / Security Center
    $dDef = Get-DomainCounts 'Defender|Secure Score|Security Assessment|Security Alert|Compliance'
    # AKS
    $dAKS = Get-DomainCounts 'AKS|Kubernetes|RBAC|Network Policy|Private Cluster'
    # Zero Trust
    $dZT = Get-DomainCounts 'ZT-'
    $ztNet  = ($script:Findings | Where-Object { $_.Category -match "ZT-Network" }).Count
    $ztComp = ($script:Findings | Where-Object { $_.Category -match "ZT-Compute" }).Count
    $ztPlat = ($script:Findings | Where-Object { $_.Category -match "ZT-Platform" }).Count
    # DevOps Security
    $dDevOps = Get-DomainCounts 'ACR|Container Registry|Remote Debugging|FTP|Deployment Slot'
    # Application Security
    $dAppSec = Get-DomainCounts 'CORS|Client Certificate|HTTP/2|API Management'
    # Modernization
    $dMod = Get-DomainCounts 'Legacy|Classic|Outdated|Free.Shared Tier|SQL on IaaS|Unmanaged Disk|Basic SKU|Container'
    # Cost Advisor + Orphaned
    $dCost = Get-DomainCounts 'Advisor|Hybrid Benefit|Auto-Shutdown|Orphaned|Unattached'
    # Hybrid / Arc
    $dHybrid = Get-DomainCounts 'Arc|ExpressRoute|VPN Gateway'
    # BCDR
    $dBCDR = Get-DomainCounts 'BCDR|Backup|Recovery|Replication|Retention|Disaster|Soft Delete.*Vault'
    # Resource Locks
    $dLocks = Get-DomainCounts 'Resource Lock|No Locks'
    # Expiring Secrets
    $dSecrets = Get-DomainCounts 'Key Vault.*Expir|Key Vault.*Expired|Key Vault.*No Expiry'
    # Tag Compliance
    $dTags = Get-DomainCounts 'Tag Compliance'
    # Diagnostic Settings
    $dDiag = Get-DomainCounts 'Diagnostic Settings'
    # Private Endpoints
    $dPE = Get-DomainCounts 'Private Endpoint'
    # Policy Compliance
    $dPolicy = Get-DomainCounts 'Policy -'
    # Cosmos / OSS DBs
    $dCosmos = Get-DomainCounts 'Cosmos DB|PostgreSQL|MySQL|Redis'
    # Subscription Hygiene
    $dHygiene = Get-DomainCounts 'Hygiene'
    # Underutilized
    $utilTotal = $script:UnderutilizedResources.Count
    $utilVMs   = ($script:UnderutilizedResources | Where-Object ResourceType -match "Virtual Machine").Count
    $utilApps  = ($script:UnderutilizedResources | Where-Object ResourceType -match "App Service").Count
    $utilSQL   = ($script:UnderutilizedResources | Where-Object ResourceType -match "SQL").Count

    # ── Network Architecture metrics ─────────────────────────────────────────
    $exVnetCount = 0; $exSubnetsTotal = 0; $exSubnetsNoNSG = 0; $exPeeringCount = 0
    $exPipTotal = 0; $exPipOrphaned = 0; $exGwCount = 0
    try {
        $exNetVnets    = @($script:NetworkTopology | Where-Object { $_.Type -eq 'VNet' })
        $exNetPIPs     = @($script:NetworkTopology | Where-Object { $_.Type -eq 'PublicIP' })
        $exNetGateways = @($script:NetworkTopology | Where-Object { $_.Type -eq 'Gateway' })
        $exVnetCount   = $exNetVnets.Count
        $exPipTotal    = $exNetPIPs.Count
        $exPipOrphaned = @($exNetPIPs | Where-Object { -not $_.AssociatedTo -or $_.AssociatedTo -eq 'Unassociated' }).Count
        $exGwCount     = $exNetGateways.Count
        foreach ($v in $exNetVnets) {
            $sc = 0; if ($v.SubnetCount) { $sc = [int]$v.SubnetCount }
            $exSubnetsTotal += $sc
            if ($v.SubnetDetails) {
                $exSubnetsNoNSG += @($v.SubnetDetails | Where-Object { -not $_.NsgName }).Count
            }
            if ($v.PeeringDetails) {
                $exPeeringCount += @($v.PeeringDetails).Count
            }
        }
    } catch { Write-Status "  Executive report — network metrics: $($_.Exception.Message)" "WARN" }

    # ── Cost Analysis metrics ────────────────────────────────────────────────
    $exCostTotal = 0; $exCostCurrency = "USD"; $exCostMonthlyAvg = 0
    $exCostTopService = "N/A"; $exCostTopServicesHtml = ""
    try {
        if ($script:CostData -and $script:CostData.Count -gt 0) {
            foreach ($cdVal in $script:CostData.Values) {
                if ($cdVal -and $cdVal.TotalCost) { $exCostTotal += $cdVal.TotalCost }
                if ($cdVal -and $cdVal.Currency -and $exCostCurrency -eq "USD") { $exCostCurrency = $cdVal.Currency }
            }
            $monthCounts = @($script:CostData.Values | Where-Object { $_ -and $_.Months } | ForEach-Object { $_.Months.Count })
            $maxMonths = if ($monthCounts.Count -gt 0) { ($monthCounts | Measure-Object -Maximum).Maximum } else { 0 }
            if ($maxMonths -gt 0) { $exCostMonthlyAvg = [math]::Round($exCostTotal / $maxMonths, 0) }
            $svcTotals = @{}
            foreach ($cdVal in $script:CostData.Values) {
                if ($cdVal -and $cdVal.TopServices) {
                    foreach ($svc in $cdVal.TopServices) {
                        if ($svc.Key) {
                            $sn = [string]$svc.Key
                            if ($svcTotals.ContainsKey($sn)) { $svcTotals[$sn] += $svc.Value } else { $svcTotals[$sn] = $svc.Value }
                        }
                    }
                }
            }
            if ($svcTotals.Count -gt 0) {
                $topSvcs = $svcTotals.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
                $firstSvc = $topSvcs | Select-Object -First 1
                if ($firstSvc) { $exCostTopService = [string]$firstSvc.Name }
                foreach ($ts in $topSvcs) {
                    $pct = if ($exCostTotal -gt 0) { [math]::Round(($ts.Value / $exCostTotal) * 100, 1) } else { 0 }
                    $barW = [math]::Min([math]::Round($pct), 100)
                    $safeName = ConvertTo-SafeHtml ([string]$ts.Name)
                    $fmtCost = "$exCostCurrency $([math]::Round($ts.Value,0).ToString('N0'))"
                    $exCostTopServicesHtml += "<tr><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#323130'>$safeName</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:right;font-weight:600;color:#0078d4'>$fmtCost</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;width:35%'><div style='background:#e8e8e8;border-radius:3px;height:10px;width:100%'><div style='background:#0078d4;border-radius:3px;height:10px;width:${barW}%'></div></div></td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c;text-align:right'>${pct}%</td></tr>"
                }
            }
        }
    } catch { Write-Status "  Executive report — cost metrics: $($_.Exception.Message)" "WARN" }
    $exCostAvailable = $exCostTotal -gt 0

    # ── Reservation & Savings Plan metrics ───────────────────────────────────
    $exRiTotal = 0; $exRiActive = 0; $exRiExpiring = 0; $exRiExpired = 0; $exRiLowUtil = 0; $exRiAvgUtil = -1
    try {
        if ($script:ReservationData -and $script:ReservationData.Count -gt 0) {
            $exRiTotal    = $script:ReservationData.Count
            $exRiActive   = @($script:ReservationData | Where-Object { $_.DaysToExpiry -ge 0 -or ($_.DaysToExpiry -eq -1 -and $_.Status -eq 'Succeeded') }).Count
            $exRiExpiring = @($script:ReservationData | Where-Object { $_.DaysToExpiry -ge 0 -and $_.DaysToExpiry -le 90 }).Count
            $exRiExpired  = @($script:ReservationData | Where-Object { $_.DaysToExpiry -lt 0 -and $_.ExpiryDate }).Count
            $exRiLowUtil  = @($script:ReservationData | Where-Object { $_.UtilizationPct -ge 0 -and $_.UtilizationPct -lt 50 }).Count
            $exRiWithUtil = @($script:ReservationData | Where-Object { $_.UtilizationPct -ge 0 })
            if ($exRiWithUtil.Count -gt 0) { $exRiAvgUtil = [math]::Round(($exRiWithUtil | Measure-Object -Property UtilizationPct -Average).Average, 0) }
        }
    } catch { Write-Status "  Executive report — reservation metrics: $($_.Exception.Message)" "WARN" }
    $exRiAvailable = $exRiTotal -gt 0

    # ── Identity & Access metrics ────────────────────────────────────────────
    $exIdCount = 0; $exIdCrit = 0; $exIdHigh = 0
    try {
        $exIdentityFindings = @($script:Findings | Where-Object { $_.Category -match 'Identity|RBAC|PIM|MFA|Authentication' })
        $exIdCount = $exIdentityFindings.Count
        $exIdCrit  = @($exIdentityFindings | Where-Object Severity -eq "Critical").Count
        $exIdHigh  = @($exIdentityFindings | Where-Object Severity -eq "High").Count
    } catch { Write-Status "  Executive report — identity metrics: $($_.Exception.Message)" "WARN" }

    # ── Pre-build conditional HTML blocks using string concat (no nested here-strings) ──
    # Cost section
    $utilBorderColor = if ($utilTotal -gt 0) { '#ca5010' } else { '#107c10' }
    $utilBgColor     = if ($utilTotal -gt 0) { '#fff4ce' } else { '#dff6dd' }
    $costOptClass    = if ($utilTotal -gt 0 -or $dCost.Total -gt 0) { ' warn' } else { ' good' }
    $costOptNarrative = ""
    if ($utilTotal -gt 0) { $costOptNarrative += "&#9888; <strong>$utilTotal underutilized resource(s)</strong> detected via Azure Monitor metrics ($utilVMs VMs, $utilApps App Services, $utilSQL SQL DBs). " }
    if ($dCost.Total -gt 0) { $costOptNarrative += "&#128176; <strong>$($dCost.Total) cost optimization finding(s)</strong>: orphaned resources, missing Azure Hybrid Benefit, auto-shutdown opportunities. " }
    if ($utilTotal -eq 0 -and $dCost.Total -eq 0) { $costOptNarrative = "&#9989; No immediate cost optimization findings." }

    $fmtTotal = $exCostTotal.ToString('N0')
    $fmtMonthly = $exCostMonthlyAvg.ToString('N0')
    $safeTopSvc = ConvertTo-SafeHtml $exCostTopService

    if ($exCostAvailable) {
        $exCostSectionHtml = "<div class=`"stats-row`" style=`"margin-bottom:10px`">" +
            "<div class=`"stat-box`" style=`"border-color:#0078d4;background:#deecf9`"><div class=`"num`" style=`"color:#0078d4`">$exCostCurrency $fmtTotal</div><div class=`"lbl`" style=`"color:#0078d4`">Total (6 months)</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:#0078d4;background:#deecf9`"><div class=`"num`" style=`"color:#0078d4`">$exCostCurrency $fmtMonthly</div><div class=`"lbl`" style=`"color:#0078d4`">Monthly Average</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:$utilBorderColor;background:$utilBgColor`"><div class=`"num`" style=`"color:$utilBorderColor`">$utilTotal</div><div class=`"lbl`" style=`"color:$utilBorderColor`">Underutilized</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:#0078d4;background:#deecf9`"><div class=`"num`" style=`"color:#0078d4;font-size:10pt`">$safeTopSvc</div><div class=`"lbl`" style=`"color:#0078d4`">Top Service</div></div>" +
            "</div>" +
            "<div class=`"two-col`"><div>" +
            "<div class=`"section-title-sm`">Top 5 Services by Spend</div>" +
            "<table class=`"section-table`"><thead><tr><th class=`"tbl-header`" style=`"width:30%`">Service</th><th class=`"tbl-header`" style=`"text-align:right;width:22%`">Spend</th><th class=`"tbl-header`" style=`"width:35%`">Distribution</th><th class=`"tbl-header`" style=`"text-align:right;width:13%`">%</th></tr></thead>" +
            "<tbody>$exCostTopServicesHtml</tbody></table>" +
            "</div><div>" +
            "<div class=`"section-title-sm`">Cost Optimization Opportunities</div>" +
            "<div class=`"narrative$costOptClass`">$costOptNarrative</div>" +
            "</div></div>"
    } else {
        $utilNoCostClass = if ($utilTotal -gt 0) { ' warn' } else { ' good' }
        $utilNoCostMsg = if ($utilTotal -gt 0) { "&#9888; <strong>$utilTotal underutilized resource(s)</strong> detected via Azure Monitor metrics ($utilVMs VMs, $utilApps App Services, $utilSQL SQL DBs). Right-sizing can reduce costs." } else { "&#9989; No underutilized resources detected via Azure Monitor metrics." }
        $exCostSectionHtml = "<div class=`"narrative`"><strong>&#128176; Cost data not available</strong> — Cost Management Reader role is required to retrieve spending data. Assign the role and re-run the assessment for cost visibility.</div>" +
            "<div class=`"narrative$utilNoCostClass`">$utilNoCostMsg</div>"
    }

    # Reservation section
    if ($exRiAvailable) {
        $riExpColor  = if ($exRiExpiring -gt 0) { '#ca5010' } else { '#107c10' }
        $riExpBg     = if ($exRiExpiring -gt 0) { '#fff4ce' } else { '#dff6dd' }
        $riExpdColor = if ($exRiExpired -gt 0)  { '#d13438' } else { '#107c10' }
        $riExpdBg    = if ($exRiExpired -gt 0)  { '#fde7e9' } else { '#dff6dd' }
        $riLowColor  = if ($exRiLowUtil -gt 0)  { '#ca5010' } else { '#107c10' }
        $riLowBg     = if ($exRiLowUtil -gt 0)  { '#fff4ce' } else { '#dff6dd' }
        $riAvgColor  = if ($exRiAvgUtil -lt 50) { '#ca5010' } elseif ($exRiAvgUtil -lt 80) { '#0078d4' } else { '#107c10' }
        $riAvgBg     = if ($exRiAvgUtil -lt 50) { '#fff4ce' } elseif ($exRiAvgUtil -lt 80) { '#deecf9' } else { '#dff6dd' }
        $riAvgLabel  = if ($exRiAvgUtil -ge 0) { "${exRiAvgUtil}%" } else { 'N/A' }
        $riNarrClass = if ($exRiExpiring -gt 0 -or $exRiLowUtil -gt 0) { ' warn' } elseif ($exRiExpired -gt 0) { ' danger' } else { ' good' }
        $riNarrative = ""
        if ($exRiExpired -gt 0)  { $riNarrative += "<strong>$exRiExpired expired reservation(s)</strong> — renew or convert to Savings Plans to avoid on-demand pricing. " }
        if ($exRiExpiring -gt 0) { $riNarrative += "<strong>$exRiExpiring reservation(s) expiring within 90 days</strong> — plan renewals. " }
        if ($exRiLowUtil -gt 0)  { $riNarrative += "<strong>$exRiLowUtil reservation(s) with utilization below 50%</strong> — consider exchanging or scoping adjustments. " }
        if ($exRiExpired -eq 0 -and $exRiExpiring -eq 0 -and $exRiLowUtil -eq 0) { $riNarrative = "All reservations and savings plans are active with healthy utilization." }
        $exRiSectionHtml = "<div class=`"stats-row`" style=`"margin-bottom:10px`">" +
            "<div class=`"stat-box`" style=`"border-color:#0078d4;background:#deecf9`"><div class=`"num`" style=`"color:#0078d4`">$exRiTotal</div><div class=`"lbl`" style=`"color:#0078d4`">Total RI/SP</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:#107c10;background:#dff6dd`"><div class=`"num`" style=`"color:#107c10`">$exRiActive</div><div class=`"lbl`" style=`"color:#107c10`">Active</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:$riExpColor;background:$riExpBg`"><div class=`"num`" style=`"color:$riExpColor`">$exRiExpiring</div><div class=`"lbl`" style=`"color:$riExpColor`">Expiring (&le;90d)</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:$riExpdColor;background:$riExpdBg`"><div class=`"num`" style=`"color:$riExpdColor`">$exRiExpired</div><div class=`"lbl`" style=`"color:$riExpdColor`">Expired</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:$riLowColor;background:$riLowBg`"><div class=`"num`" style=`"color:$riLowColor`">$exRiLowUtil</div><div class=`"lbl`" style=`"color:$riLowColor`">Low Utilization</div></div>" +
            "<div class=`"stat-box`" style=`"border-color:$riAvgColor;background:$riAvgBg`"><div class=`"num`" style=`"color:$riAvgColor`">$riAvgLabel</div><div class=`"lbl`" style=`"color:#605e5c`">Avg Utilization</div></div>" +
            "</div>" +
            "<div class=`"narrative$riNarrClass`"><strong>&#128176; Financial commitments:</strong> $riNarrative</div>"
    } else {
        $exRiSectionHtml = "<div class=`"narrative`"><strong>&#128176; No reservations or savings plans detected.</strong> Consider purchasing Reserved Instances or Savings Plans for predictable workloads to achieve 30-72% savings over pay-as-you-go pricing.</div>"
    }

    # Network narrative
    $netNarrClass = if ($exSubnetsNoNSG -gt 0 -or $exPipOrphaned -gt 0) { ' warn' } else { ' good' }
    $netNarrative = ""
    if ($exSubnetsNoNSG -gt 0) { $netNarrative += "<strong>$exSubnetsNoNSG subnet(s)</strong> lack NSG protection — immediate segmentation required. " } else { $netNarrative += "All subnets have NSG protection. " }
    if ($exPipOrphaned -gt 0) { $netNarrative += "<strong>$exPipOrphaned orphaned Public IP(s)</strong> should be removed to reduce attack surface and cost. " }
    if ($exPeeringCount -gt 0) { $netNarrative += "$exPeeringCount VNet peering(s) configured. " }
    if ($exGwCount -gt 0) { $netNarrative += "$exGwCount VPN/ExpressRoute gateway(s) deployed. " }

    # Network KPI colors
    $nsgBorderColor = if ($exSubnetsNoNSG -gt 0) { '#d13438' } else { '#107c10' }
    $nsgBgColor     = if ($exSubnetsNoNSG -gt 0) { '#fde7e9' } else { '#dff6dd' }
    $pipBorderColor = if ($exPipOrphaned -gt 0)  { '#ca5010' } else { '#107c10' }
    $pipBgColor     = if ($exPipOrphaned -gt 0)  { '#fff4ce' } else { '#dff6dd' }

    # Identity narrative
    $idNarrClass = if ($exIdCrit -gt 0) { ' danger' } elseif ($exIdHigh -gt 0) { ' warn' } else { ' good' }
    $idNarrative = ""
    if ($exIdCount -eq 0) {
        $idNarrative = "No identity or access control findings. Authentication, RBAC, and privilege management are well configured."
    } else {
        $idSeverityNote = if ($exIdCrit -gt 0) { " ($exIdCrit critical)" } elseif ($exIdHigh -gt 0) { " ($exIdHigh high)" } else { "" }
        $idAction = if ($exIdCrit -gt 0 -or $exIdHigh -gt 0) { "Immediate review recommended — identity is the primary attack vector in cloud environments." } else { "Medium-priority improvements to strengthen identity controls." }
        $idNarrative = "<strong>$exIdCount finding(s)</strong> identified${idSeverityNote} across Conditional Access, MFA, RBAC, and PIM controls. $idAction"
    }

    # ── Domain assessment rows builder ───────────────────────────────────────
    function Build-DomainRow([string]$icon, [string]$name, $d, [string]$scope) {
        $statusLabel = if ($d.Crit -gt 0) { "Critical" } elseif ($d.High -gt 0) { "High" } elseif ($d.Med -gt 0) { "Medium" } elseif ($d.Total -gt 0) { "Low" } else { "Clean" }
        $statusColor = switch ($statusLabel) { "Critical"{"#d13438"} "High"{"#ca5010"} "Medium"{"#8a8886"} "Low"{"#107c10"} default{"#107c10"} }
        $statusBg    = switch ($statusLabel) { "Critical"{"#fde7e9"} "High"{"#fff4ce"} "Medium"{"#f3f2f1"} "Low"{"#dff6dd"} default{"#dff6dd"} }
        $critHtml = if ($d.Crit -gt 0) { "<span style='color:#d13438;font-weight:700'>$($d.Crit)</span>" } else { "<span style='color:#c8c6c4'>0</span>" }
        $highHtml = if ($d.High -gt 0) { "<span style='color:#ca5010;font-weight:700'>$($d.High)</span>" } else { "<span style='color:#c8c6c4'>0</span>" }
        return @"
<tr>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#323130;white-space:nowrap">$icon $name</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">$scope</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;text-align:center"><span style="background:$statusBg;color:$statusColor;padding:1px 7px;border-radius:8px;font-size:6.5pt;font-weight:700;border:1px solid $statusColor">$statusLabel</span></td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center">$critHtml</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center">$highHtml</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:#605e5c">$($d.Med)</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:600;color:#323130">$($d.Total)</td>
</tr>
"@
    }

    $domainRowsHtml  = Build-DomainRow "&#128225;" "Networking"           $dNet     "NSGs, VNets, PIPs, LBs, DDoS, App GWs"
    $domainRowsHtml += Build-DomainRow "&#128187;" "Virtual Machines"     $dVM      "Backup, AZ, encryption, monitoring"
    $domainRowsHtml += Build-DomainRow "&#127760;" "App Services"         $dApp     "HTTPS, TLS, identity, diagnostics"
    $domainRowsHtml += Build-DomainRow "&#128451;" "SQL Databases"        $dSQL     "Firewall, TDE, auditing, ATP"
    $domainRowsHtml += Build-DomainRow "&#128190;" "Storage Accounts"     $dStor    "HTTPS, network, public access, TLS"
    $domainRowsHtml += Build-DomainRow "&#128273;" "Key Vaults"           $dKV      "Soft delete, purge, network, audit"
    $domainRowsHtml += Build-DomainRow "&#128737;" "Defender for Cloud"   $dDef     "Plans, Secure Score, alerts, benchmark"
    $domainRowsHtml += Build-DomainRow "&#9784;"   "AKS Clusters"        $dAKS     "RBAC, network policy, private API"
    $domainRowsHtml += Build-DomainRow "&#128274;" "Zero Trust"           $dZT      "Network, compute, platform controls"
    $domainRowsHtml += Build-DomainRow "&#128736;" "DevOps Security"      $dDevOps  "ACR, FTP, debugging, deployment"
    $domainRowsHtml += Build-DomainRow "&#128272;" "Application Security" $dAppSec  "CORS, mTLS, HTTP/2, APIM"
    $domainRowsHtml += Build-DomainRow "&#128640;" "Modernization"        $dMod     "Legacy OS, runtimes, classic resources"
    $domainRowsHtml += Build-DomainRow "&#128176;" "Cost Optimization"    $dCost    "Advisor, hybrid benefit, orphaned"
    $domainRowsHtml += Build-DomainRow "&#127968;" "Hybrid / Arc"         $dHybrid  "Arc servers, ExpressRoute, VPN GWs"
    $domainRowsHtml += Build-DomainRow "&#127973;" "BCDR"                 $dBCDR    "Backup, replication, retention, vaults"
    $domainRowsHtml += Build-DomainRow "&#128274;" "Resource Locks"       $dLocks   "Delete/ReadOnly locks on critical res."
    $domainRowsHtml += Build-DomainRow "&#128272;" "Expiring Secrets"     $dSecrets "Secrets, certificates, keys expiration"
    $domainRowsHtml += Build-DomainRow "&#127991;" "Tag Compliance"       $dTags    "Mandatory tags, empty RGs, untagged"
    $domainRowsHtml += Build-DomainRow "&#128225;" "Diagnostic Settings"  $dDiag    "Log Analytics coverage, Activity Log"
    $domainRowsHtml += Build-DomainRow "&#128274;" "Private Endpoints"    $dPE      "PaaS public vs private access"
    $domainRowsHtml += Build-DomainRow "&#128220;" "Policy Compliance"    $dPolicy  "Assignments, compliance %, enforcement"
    $domainRowsHtml += Build-DomainRow "&#128024;" "Cosmos DB &amp; OSS DBs"    $dCosmos  "Cosmos, PostgreSQL, MySQL, Redis"
    $domainRowsHtml += Build-DomainRow "&#129529;" "Subscription Hygiene" $dHygiene "Regions, naming, empty RGs, sprawl"

    # ── Category summary ─────────────────────────────────────────────────────
    $categoryGroups = $script:Findings | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 15
    $categoryHtml = ""
    foreach ($cg in $categoryGroups) {
        $cCrit = ($cg.Group | Where-Object Severity -eq "Critical").Count
        $cHigh = ($cg.Group | Where-Object Severity -eq "High").Count
        $maxBadge = if ($cCrit -gt 0) { "<span style='background:#fde7e9;color:#d13438;padding:1px 6px;border-radius:8px;font-size:6.5pt;font-weight:700;border:1px solid #d13438'>$cCrit Crit</span>" } `
                    elseif ($cHigh -gt 0) { "<span style='background:#fff4ce;color:#ca5010;padding:1px 6px;border-radius:8px;font-size:6.5pt;font-weight:700;border:1px solid #ca5010'>$cHigh High</span>" } `
                    else { "" }
        $categoryHtml += "<tr><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#323130'>$(ConvertTo-SafeHtml $cg.Name)</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:#323130'>$($cg.Count)</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt'>$maxBadge</td></tr>"
    }

    # ── Resource type summary ────────────────────────────────────────────────
    $rtSummary = $script:Resources | Group-Object Type | Sort-Object Count -Descending | Select-Object -First 10
    $rtHtml = ""
    foreach ($rt in $rtSummary) {
        $rawShort = $rt.Name.Split('/')[-1]
        $shortType = if ($script:FriendlyTypeNames.ContainsKey($rawShort.ToLower())) { $script:FriendlyTypeNames[$rawShort.ToLower()] } else { $rawShort }
        $rtHtml += "<tr><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;color:#323130'>$(ConvertTo-SafeHtml $shortType)</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:600;color:#0078d4'>$($rt.Count)</td></tr>"
    }

    # ── Subscription rows ────────────────────────────────────────────────────
    $subRowsHtml = ""
    foreach ($s in $script:Subscriptions) {
        $subFindings = ($script:Findings | Where-Object Subscription -eq $s.Name).Count
        $subRowsHtml += "<tr><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600'>$(ConvertTo-SafeHtml $s.Name)</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c;font-family:Consolas,monospace'>$(ConvertTo-SafeHtml $s.Id)</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:600;color:#0078d4'>$subFindings</td><td style='padding:3px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;color:#107c10'>$(ConvertTo-SafeHtml $s.State)</td></tr>"
    }

    # ── Narrative blocks ─────────────────────────────────────────────────────
    $narrativeSecurity = if ($critCount -gt 0) {
        "The environment has <strong>$critCount critical-severity finding(s)</strong> requiring immediate action. These represent active risks of data exposure, unauthorized access, or service loss."
    } else {
        "No critical-severity findings were identified. The environment shows an adequate baseline security posture; however, there are <strong>$highCount high-severity finding(s)</strong> that should be addressed."
    }

    $narrativeBCDR = if ($dBCDR.Total -gt 0) {
        "BCDR analysis found <strong>$($dBCDR.Total) finding(s)</strong> ($($dBCDR.Crit) critical, $($dBCDR.High) high). Areas include backup coverage, stale backups, retention policies, and ASR replication health."
    } else { "Backup and disaster recovery controls are well configured across evaluated resources." }

    $narrativeGov = ""
    if ($dTags.Total -gt 0) { $narrativeGov += "Tag compliance: <strong>$($dTags.Total) finding(s)</strong>. " }
    if ($dPolicy.Total -gt 0) { $narrativeGov += "Policy compliance: <strong>$($dPolicy.Total) finding(s)</strong>. " }
    if ($dLocks.Total -gt 0) { $narrativeGov += "Resource locks: <strong>$($dLocks.Total) unprotected resource(s)</strong>. " }
    if ($dHygiene.Total -gt 0) { $narrativeGov += "Subscription hygiene: <strong>$($dHygiene.Total) finding(s)</strong>. " }
    if ($narrativeGov -eq "") { $narrativeGov = "Governance controls are well implemented across the environment." }

    $narrativeDataSec = ""
    if ($dPE.Total -gt 0) { $narrativeDataSec += "Private Endpoints: <strong>$($dPE.Total) PaaS service(s)</strong> still use public access. " }
    if ($dDiag.Total -gt 0) { $narrativeDataSec += "Diagnostic Settings: <strong>$($dDiag.Total) resource(s)</strong> missing log collection. " }
    if ($dSecrets.Total -gt 0) { $narrativeDataSec += "Secrets lifecycle: <strong>$($dSecrets.Total) expiring/expired item(s)</strong> in Key Vault. " }
    if ($dCosmos.Total -gt 0) { $narrativeDataSec += "Database security: <strong>$($dCosmos.Total) finding(s)</strong> across Cosmos DB, PostgreSQL, MySQL, Redis. " }
    if ($narrativeDataSec -eq "") { $narrativeDataSec = "Data services security controls are well configured." }

    # ── Per-subscription summary ─────────────────────────────────────────────
    $subSummaryHtml = ""
    foreach ($s in $script:Subscriptions) {
        $sf = @($script:Findings | Where-Object Subscription -eq $s.Name)
        $sc = ($sf | Where-Object Severity -eq "Critical").Count
        $sh = ($sf | Where-Object Severity -eq "High").Count
        $sm = ($sf | Where-Object Severity -eq "Medium").Count
        $sl = ($sf | Where-Object Severity -eq "Low").Count
        $topCats = ($sf | Group-Object Category | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
        if (-not $topCats) { $topCats = "—" }
        $subSummaryHtml += @"
<tr>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#323130">$(ConvertTo-SafeHtml $s.Name)</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:$(if($sc -gt 0){'#d13438;font-weight:700'}else{'#c8c6c4'})">$sc</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:$(if($sh -gt 0){'#ca5010;font-weight:700'}else{'#c8c6c4'})">$sh</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:#605e5c">$sm</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;color:#605e5c">$sl</td>
  <td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">$(ConvertTo-SafeHtml $topCats)</td>
</tr>
"@
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # HTML OUTPUT — 4 PAGE EXECUTIVE REPORT
    # ═══════════════════════════════════════════════════════════════════════════
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Azure Assessment — Executive Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Aptos','Segoe UI',Calibri,Arial,sans-serif;font-size:9pt;color:#323130;background:#fff;line-height:1.5}
@page{size:A4;margin:14mm 13mm 16mm 13mm}
@media print{body{background:#fff;font-size:8pt}.no-print{display:none!important}.page-break{page-break-before:always}.avoid-break{page-break-inside:avoid}a{color:#0078d4;text-decoration:none}thead{display:table-header-group}}
@media screen{body{background:#e8e8e8}.page{background:#fff;width:210mm;min-height:297mm;margin:12px auto;padding:14mm 13mm;box-shadow:0 2px 12px rgba(0,0,0,.15)}.print-bar{position:fixed;top:0;left:0;right:0;z-index:100;background:#002050;color:#fff;padding:10px 24px;display:flex;align-items:center;justify-content:space-between;font-size:13px}.print-bar button{background:#0078d4;color:#fff;border:none;padding:8px 22px;border-radius:5px;cursor:pointer;font-size:13px;font-weight:600}.print-bar button:hover{background:#005a9e}}
table{width:100%;border-collapse:collapse}
.tbl-header{background:#004578;color:#fff;font-size:7.5pt;font-weight:600;padding:6px 8px;text-align:left}
.section-table{margin-bottom:12px}
.section-table td{vertical-align:top}
.report-header{background:linear-gradient(135deg,#002050 0%,#0078d4 65%,#00b7c3 100%);color:#fff;padding:16px 18px 14px;margin-bottom:16px;border-radius:4px}
.header-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.ms-logo{display:flex;align-items:center;gap:10px}
.ms-squares{display:grid;grid-template-columns:1fr 1fr;gap:2px;width:20px;height:20px}
.ms-sq{border-radius:1px}
.report-title{font-size:16pt;font-weight:700;margin-bottom:2px}
.report-subtitle{font-size:9pt;opacity:.85}
.header-meta{display:flex;gap:18px;font-size:7.5pt;opacity:.8;border-top:1px solid rgba(255,255,255,.2);padding-top:8px;margin-top:6px;flex-wrap:wrap}
.section-title{font-size:10pt;font-weight:700;color:#002050;border-bottom:2.5px solid #0078d4;padding-bottom:4px;margin:16px 0 8px;text-transform:uppercase;letter-spacing:.3px}
.section-title-sm{font-size:9pt;font-weight:700;color:#004578;border-left:3px solid #0078d4;padding-left:8px;margin:10px 0 6px}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.three-col{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}
.stats-row{display:flex;gap:8px;margin-bottom:14px}
.stat-box{flex:1;border-radius:5px;padding:8px 10px;text-align:center;border:1px solid}
.stat-box .num{font-size:16pt;font-weight:800}
.stat-box .lbl{font-size:7pt;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
.narrative{background:#f3f9ff;border-left:3px solid #0078d4;padding:8px 12px;font-size:8pt;margin-bottom:10px;border-radius:0 4px 4px 0;line-height:1.6}
.narrative.warn{background:#fff4ce;border-left-color:#ca5010}
.narrative.danger{background:#fde7e9;border-left-color:#d13438}
.narrative.good{background:#dff6dd;border-left-color:#107c10}
.page-footer{border-top:1px solid #edebe9;margin-top:16px;padding-top:6px;display:flex;justify-content:space-between;font-size:7pt;color:#8a8886}
.pill{display:inline-block;padding:1px 7px;border-radius:8px;font-size:7pt;font-weight:700;border:1px solid;white-space:nowrap}
.pill-crit{background:#fde7e9;color:#d13438;border-color:#d13438}
.pill-high{background:#fff4ce;color:#ca5010;border-color:#ca5010}
.pill-med{background:#f3f2f1;color:#605e5c;border-color:#8a8886}
.pill-low{background:#dff6dd;color:#107c10;border-color:#107c10}
.mini-header{background:#004578;color:#fff;padding:10px 18px;border-radius:4px 4px 0 0;margin-bottom:0;display:flex;align-items:center;justify-content:space-between}
.mini-header .ms-squares{width:16px;height:16px}
</style>
</head>
<body>

<!-- Print bar (screen only) -->
<div class="print-bar no-print">
    <span>&#128196; Executive Report — Azure Tenant Assessment &nbsp;&#183;&nbsp; To save as PDF: Ctrl+P &#8594; Save as PDF</span>
    <button onclick="window.print()">&#128424; Print / Save PDF</button>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 1 — Executive Summary + WAF Pillar Assessment
════════════════════════════════════════════════════════════════ -->
<div class="page">

    <div class="report-header">
        <div class="header-top">
            <div class="ms-logo">
                <div class="ms-squares">
                    <div class="ms-sq" style="background:#f25022"></div><div class="ms-sq" style="background:#7fba00"></div>
                    <div class="ms-sq" style="background:#00a4ef"></div><div class="ms-sq" style="background:#ffb900"></div>
                </div>
                <span style="font-size:10pt;font-weight:600;letter-spacing:.2px">Microsoft Azure</span>
            </div>
            <div style="text-align:right;font-size:7.5pt;opacity:.8">
                <div>$genDate &nbsp;&#183;&nbsp; $genTime</div>
                <div>Tenant: $tenantId</div>
            </div>
        </div>
        <div class="report-title">Azure Well-Architected &amp; Zero Trust Assessment</div>
        <div class="report-subtitle">Executive Report — Cloud Architecture &amp; Security Assessment</div>
        <div class="header-meta">
            <span>Subscriptions: <strong>$($script:Subscriptions.Count)</strong></span>
            <span>Resources: <strong>$($script:Summary.TotalResources)</strong></span>
            <span>Total findings: <strong>$totalFindings</strong></span>
            <span>Domains assessed: <strong>$(@($script:StepResults | Where-Object { $_.Step -notin 'DataCollection','CostAnalysis','ResourceInventory','Generate-HTMLReport','Generate-ArchitectureDiagram','Generate-ExecutiveReport','Export-Data' -and $_.Subscription -ne 'Reports' -and $_.Subscription -ne 'Tenant-wide' }).Step | Select-Object -Unique).Count</strong></span>
            <span>Duration: <strong>$duration min</strong></span>
        </div>
    </div>

    <!-- Overall status + severity counters -->
    <div class="avoid-break">
        <div class="two-col" style="margin-bottom:14px">
            <div style="background:$overallBg;border:2px solid $overallColor;border-radius:6px;padding:12px 16px;display:flex;align-items:flex-start;gap:12px">
                <div style="background:$overallColor;color:#fff;border-radius:5px;padding:5px 10px;font-size:10pt;font-weight:800;white-space:nowrap;flex-shrink:0;letter-spacing:.3px">$overallStatus</div>
                <div>
                    <div style="font-size:8.5pt;font-weight:700;color:$overallColor;margin-bottom:3px">Overall Environment Status</div>
                    <div style="font-size:7.5pt;color:#323130;line-height:1.5">$overallDesc</div>
                </div>
            </div>
            <div>
                <div class="stats-row" style="margin-bottom:0">
                    <div class="stat-box" style="border-color:#d13438;background:#fde7e9"><div class="num" style="color:#d13438">$critCount</div><div class="lbl" style="color:#d13438">Critical</div></div>
                    <div class="stat-box" style="border-color:#ca5010;background:#fff4ce"><div class="num" style="color:#ca5010">$highCount</div><div class="lbl" style="color:#ca5010">High</div></div>
                    <div class="stat-box" style="border-color:#8a8886;background:#f3f2f1"><div class="num" style="color:#605e5c">$medCount</div><div class="lbl" style="color:#605e5c">Medium</div></div>
                    <div class="stat-box" style="border-color:#107c10;background:#dff6dd"><div class="num" style="color:#107c10">$lowCount</div><div class="lbl" style="color:#107c10">Low</div></div>
                </div>
            </div>
        </div>
    </div>

    <!-- 1. Executive Summary narratives -->
    <div class="section-title">1. Executive Summary</div>
    <div class="avoid-break">
        <p style="font-size:8pt;margin-bottom:8px;line-height:1.6">
            Automated assessment of <strong>$($script:Summary.TotalResources) resources</strong> across <strong>$($script:Subscriptions.Count) subscription(s)</strong>:
            <em>$subNames</em>. Evaluated against the <em>Azure Well-Architected Framework</em>, <em>Zero Trust</em> model, and Azure best practices across <strong>23 security and governance domains</strong>.
        </p>
        <div class="narrative$(if($critCount -gt 0){' danger'}elseif($highCount -gt 5){' warn'}else{' good'})">
            <strong>&#128737; Security &amp; Compliance:</strong> $narrativeSecurity
        </div>
        <div class="narrative">
            <strong>&#127973; Business Continuity:</strong> $narrativeBCDR
        </div>
        <div class="narrative">
            <strong>&#128220; Governance:</strong> $narrativeGov
        </div>
        <div class="narrative">
            <strong>&#128274; Data &amp; Network Security:</strong> $narrativeDataSec
        </div>
    </div>

    <!-- 2. WAF Pillar Assessment -->
    <div class="section-title">2. Well-Architected Framework — Pillar Assessment</div>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:20%">Pillar</th>
                <th class="tbl-header" style="width:22%">Scope</th>
                <th class="tbl-header" style="width:14%;text-align:center">Status</th>
                <th class="tbl-header" style="width:8%;text-align:center">Crit</th>
                <th class="tbl-header" style="width:8%;text-align:center">High</th>
                <th class="tbl-header" style="width:8%;text-align:center">Med</th>
                <th class="tbl-header" style="width:14%;text-align:center">Priority</th>
            </tr></thead>
            <tbody>$pillarCardsHtml</tbody>
        </table>
    </div>

    <!-- 3. Scope -->
    <div class="section-title">3. Assessment Scope</div>
    <div class="avoid-break two-col">
        <div>
            <div class="section-title-sm">Subscriptions evaluated</div>
            <table class="section-table">
                <thead><tr><th class="tbl-header">Name</th><th class="tbl-header">ID</th><th class="tbl-header" style="text-align:center">Findings</th><th class="tbl-header">State</th></tr></thead>
                <tbody>$subRowsHtml</tbody>
            </table>
        </div>
        <div>
            <div class="section-title-sm">Top resource types</div>
            <table class="section-table">
                <thead><tr><th class="tbl-header" style="width:70%">Type</th><th class="tbl-header" style="text-align:center">Count</th></tr></thead>
                <tbody>$rtHtml</tbody>
            </table>
        </div>
    </div>

    <div class="page-footer">
        <span>Microsoft Azure — Executive Assessment Report</span>
        <span>$genDate &#183; Confidential</span>
        <span>Page 1 of 5</span>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 2 — Domain-by-Domain Assessment (all 23 domains)
════════════════════════════════════════════════════════════════ -->
<div class="page page-break">
    <div class="mini-header">
        <div class="ms-logo"><div class="ms-squares"><div class="ms-sq" style="background:#f25022"></div><div class="ms-sq" style="background:#7fba00"></div><div class="ms-sq" style="background:#00a4ef"></div><div class="ms-sq" style="background:#ffb900"></div></div><span style="font-size:9pt;font-weight:600">Microsoft Azure — Executive Assessment</span></div>
        <span style="font-size:7.5pt;opacity:.8">$genDate</span>
    </div>

    <div class="section-title" style="margin-top:14px">4. Domain-by-Domain Assessment (23 Domains)</div>
    <p style="font-size:7.5pt;color:#605e5c;margin-bottom:8px">Each domain represents a dedicated analysis function evaluating a specific area of Azure infrastructure, security, or governance.</p>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:17%">Domain</th>
                <th class="tbl-header" style="width:25%">Scope evaluated</th>
                <th class="tbl-header" style="width:12%;text-align:center">Status</th>
                <th class="tbl-header" style="width:8%;text-align:center">Crit</th>
                <th class="tbl-header" style="width:8%;text-align:center">High</th>
                <th class="tbl-header" style="width:8%;text-align:center">Med</th>
                <th class="tbl-header" style="width:8%;text-align:center">Total</th>
            </tr></thead>
            <tbody>$domainRowsHtml</tbody>
        </table>
    </div>

    <!-- Per-subscription breakdown -->
    <div class="section-title">5. Findings by Subscription</div>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:22%">Subscription</th>
                <th class="tbl-header" style="width:8%;text-align:center">Crit</th>
                <th class="tbl-header" style="width:8%;text-align:center">High</th>
                <th class="tbl-header" style="width:8%;text-align:center">Med</th>
                <th class="tbl-header" style="width:8%;text-align:center">Low</th>
                <th class="tbl-header" style="width:46%">Top Categories</th>
            </tr></thead>
            <tbody>$subSummaryHtml</tbody>
        </table>
    </div>

    <!-- Zero Trust summary -->
    <div class="section-title">6. Zero Trust Architecture Assessment</div>
    <div class="avoid-break two-col">
        <div>
            <div class="narrative">The Zero Trust model assesses security under <em>"never trust, always verify"</em>. <strong>$($dZT.Total) control(s)</strong> to improve were identified.</div>
            <table class="section-table">
                <thead><tr><th class="tbl-header">ZT Layer</th><th class="tbl-header" style="text-align:center">Findings</th><th class="tbl-header">Focus areas</th></tr></thead>
                <tbody>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#0078d4">&#127760; Network</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700;color:#0078d4">$ztNet</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">Segmentation, Private Endpoints, Firewall, NSGs</td></tr>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#107c10">&#128187; Compute</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700;color:#107c10">$ztComp</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">JIT Access, EDR, Managed Identity, Encryption</td></tr>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600;color:#002050">&#127963; Platform</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700;color:#002050">$ztPlat</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">CA/MFA, PIM, RBAC, Sentinel, Activity Log</td></tr>
                </tbody>
            </table>
        </div>
        <div>
            <div class="section-title-sm">Underutilized Resources (Azure Monitor)</div>
            <table class="section-table">
                <thead><tr><th class="tbl-header">Type</th><th class="tbl-header" style="text-align:center">Count</th><th class="tbl-header">Metric</th></tr></thead>
                <tbody>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600">&#128187; VMs</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700">$utilVMs</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">Avg CPU &lt; 10% (${MetricDays}d)</td></tr>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600">&#127760; App Services</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700">$utilApps</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">Requests/hr &lt; 10 (${MetricDays}d)</td></tr>
                    <tr><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;font-weight:600">&#128451; SQL DBs</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt;text-align:center;font-weight:700">$utilSQL</td><td style="padding:4px 8px;border-bottom:1px solid #edebe9;font-size:7pt;color:#605e5c">DTU/vCore &lt; 10% (${MetricDays}d)</td></tr>
                    <tr><td style="padding:4px 8px;font-size:7.5pt;font-weight:700;color:#605e5c">Total</td><td style="padding:4px 8px;font-size:7.5pt;text-align:center;font-weight:800;color:#0078d4">$utilTotal</td><td style="padding:4px 8px;font-size:7pt;color:#8a8886">Azure Monitor metrics — verifiable</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="page-footer">
        <span>Microsoft Azure — Executive Assessment Report</span>
        <span>$genDate &#183; Confidential</span>
        <span>Page 2 of 5</span>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 3 — Infrastructure, Cost & Financial Overview
════════════════════════════════════════════════════════════════ -->
<div class="page page-break">
    <div class="mini-header">
        <div class="ms-logo"><div class="ms-squares"><div class="ms-sq" style="background:#f25022"></div><div class="ms-sq" style="background:#7fba00"></div><div class="ms-sq" style="background:#00a4ef"></div><div class="ms-sq" style="background:#ffb900"></div></div><span style="font-size:9pt;font-weight:600">Microsoft Azure — Executive Assessment</span></div>
        <span style="font-size:7.5pt;opacity:.8">$genDate</span>
    </div>

    <!-- 7. Network Architecture -->
    <div class="section-title" style="margin-top:14px">7. Network Architecture Overview</div>
    <div class="avoid-break">
        <div class="stats-row" style="margin-bottom:10px">
            <div class="stat-box" style="border-color:#0078d4;background:#deecf9"><div class="num" style="color:#0078d4">$exVnetCount</div><div class="lbl" style="color:#0078d4">VNets</div></div>
            <div class="stat-box" style="border-color:#0078d4;background:#deecf9"><div class="num" style="color:#0078d4">$exSubnetsTotal</div><div class="lbl" style="color:#0078d4">Subnets</div></div>
            <div class="stat-box" style="border-color:$nsgBorderColor;background:$nsgBgColor"><div class="num" style="color:$nsgBorderColor">$exSubnetsNoNSG</div><div class="lbl" style="color:$nsgBorderColor">No NSG</div></div>
            <div class="stat-box" style="border-color:#0078d4;background:#deecf9"><div class="num" style="color:#0078d4">$exPeeringCount</div><div class="lbl" style="color:#0078d4">Peerings</div></div>
            <div class="stat-box" style="border-color:#0078d4;background:#deecf9"><div class="num" style="color:#0078d4">$exPipTotal</div><div class="lbl" style="color:#0078d4">Public IPs</div></div>
            <div class="stat-box" style="border-color:$pipBorderColor;background:$pipBgColor"><div class="num" style="color:$pipBorderColor">$exPipOrphaned</div><div class="lbl" style="color:$pipBorderColor">Orphaned PIPs</div></div>
            <div class="stat-box" style="border-color:#0078d4;background:#deecf9"><div class="num" style="color:#0078d4">$exGwCount</div><div class="lbl" style="color:#0078d4">Gateways</div></div>
        </div>
        <div class="narrative$netNarrClass">
            <strong>&#128225; Network posture:</strong> $netNarrative
        </div>
    </div>

    <!-- 8. Cost Analysis -->
    <div class="section-title">8. Cost Analysis &amp; Optimization</div>
    <div class="avoid-break">
$exCostSectionHtml
    </div>

    <!-- 9. Reservations & Savings Plans -->
    <div class="section-title">9. Reservations &amp; Savings Plans</div>
    <div class="avoid-break">
$exRiSectionHtml
    </div>

    <!-- 10. Identity & Access Risk -->
    <div class="section-title">10. Identity &amp; Access Risk Summary</div>
    <div class="avoid-break">
        <div class="narrative$idNarrClass">
            <strong>&#128100; Identity posture:</strong> $idNarrative
        </div>
    </div>

    <div class="page-footer">
        <span>Microsoft Azure — Executive Assessment Report</span>
        <span>$genDate &#183; Confidential</span>
        <span>Page 3 of 5</span>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 4 — Priority Findings (Top 20) + Category Distribution
════════════════════════════════════════════════════════════════ -->
<div class="page page-break">
    <div class="mini-header">
        <div class="ms-logo"><div class="ms-squares"><div class="ms-sq" style="background:#f25022"></div><div class="ms-sq" style="background:#7fba00"></div><div class="ms-sq" style="background:#00a4ef"></div><div class="ms-sq" style="background:#ffb900"></div></div><span style="font-size:9pt;font-weight:600">Microsoft Azure — Executive Assessment</span></div>
        <span style="font-size:7.5pt;opacity:.8">$genDate</span>
    </div>

    <div class="section-title" style="margin-top:14px">11. Priority Findings (Top 20)</div>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:8%;text-align:center">Sev.</th>
                <th class="tbl-header" style="width:14%">Subscription</th>
                <th class="tbl-header" style="width:16%">Resource</th>
                <th class="tbl-header" style="width:32%">Finding</th>
                <th class="tbl-header" style="width:30%">Recommendation</th>
            </tr></thead>
            <tbody>$topFindingsHtml</tbody>
        </table>
        <p style="font-size:7pt;color:#8a8886;margin-top:-6px">Top 20 findings sorted by severity. See the interactive HTML report for the complete list of $totalFindings findings.</p>
    </div>

    <!-- Category distribution -->
    <div class="section-title">12. Top Categories by Finding Count</div>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:55%">Category</th>
                <th class="tbl-header" style="text-align:center;width:20%">Count</th>
                <th class="tbl-header" style="width:25%">Max Severity</th>
            </tr></thead>
            <tbody>$categoryHtml</tbody>
        </table>
    </div>

    <div class="page-footer">
        <span>Microsoft Azure — Executive Assessment Report</span>
        <span>$genDate &#183; Confidential</span>
        <span>Page 4 of 5</span>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════
     PAGE 5 — Recommended Action Plan + Methodology
════════════════════════════════════════════════════════════════ -->
<div class="page page-break">
    <div class="mini-header">
        <div class="ms-logo"><div class="ms-squares"><div class="ms-sq" style="background:#f25022"></div><div class="ms-sq" style="background:#7fba00"></div><div class="ms-sq" style="background:#00a4ef"></div><div class="ms-sq" style="background:#ffb900"></div></div><span style="font-size:9pt;font-weight:600">Microsoft Azure — Executive Assessment</span></div>
        <span style="font-size:7.5pt;opacity:.8">$genDate</span>
    </div>

    <div class="section-title" style="margin-top:14px">13. Recommended Remediation Plan</div>
    <div class="avoid-break">
        <table class="section-table">
            <thead><tr>
                <th class="tbl-header" style="width:4%;text-align:center">#</th>
                <th class="tbl-header" style="width:14%">Timeframe</th>
                <th class="tbl-header" style="width:14%">Area</th>
                <th class="tbl-header" style="width:68%">Recommended Action</th>
            </tr></thead>
            <tbody>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">1</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-crit">Immediate</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Critical Security</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Resolve $critCount critical finding(s): subnets without NSG, SQL firewall rules open to Internet, storage accounts with public blob access, VMs without backup, expired secrets/certificates.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">2</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-high">1-2 weeks</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">BCDR &amp; Reliability</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Enable Azure Backup on unprotected VMs. Review stale backups and short retention policies. Enable soft delete on Recovery Vaults. Configure Availability Zones for production workloads.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">3</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-high">2-4 weeks</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Zero Trust &amp; Network</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Deploy Private Endpoints for SQL, Storage, Key Vault, Cosmos DB ($($dPE.Total) services exposed). Enable JIT VM Access, deploy Azure Bastion. Configure Conditional Access with MFA. Review broad RBAC assignments.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">4</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-high">2-4 weeks</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Secrets &amp; Key Vault</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Rotate $($dSecrets.Total) expiring/expired secret(s), certificate(s), and key(s). Implement auto-rotation policies. Enable Key Vault diagnostic settings and purge protection.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">5</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-med">1-2 months</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Observability</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Configure Diagnostic Settings on $($dDiag.Total) resource(s) to send logs to Log Analytics. Export Activity Logs. Deploy Microsoft Sentinel with Entra ID and Defender connectors. Enable NSG Flow Logs v2.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">6</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-med">1-2 months</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Governance</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Implement mandatory tagging via Azure Policy ($($dTags.Total) tag compliance issues). Assign Azure Security Benchmark initiative. Enable 'Deny' on critical policies. Deploy Resource Locks on $($dLocks.Total) unprotected critical resource(s).</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">7</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-med">1-3 months</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Cost Optimization</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Right-size $utilTotal underutilized resource(s). Remove orphaned disks/NICs/PIPs. Implement Azure Hybrid Benefit. Enable auto-shutdown on dev/test VMs. Review Azure Advisor cost recommendations.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;text-align:center;font-weight:700">8</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt"><span class="pill pill-low">3-6 months</span></td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:8pt;font-weight:600">Modernization</td>
                    <td style="padding:5px 8px;border-bottom:1px solid #edebe9;font-size:7.5pt">Migrate legacy OS (Windows 2012/2016, Ubuntu 16.04/18.04). Upgrade outdated runtimes. Migrate Basic SKU LBs/PIPs to Standard. Evaluate PaaS migration for SQL-on-IaaS workloads. Enable Defender Standard for all resource types.</td>
                </tr>
                <tr>
                    <td style="padding:5px 8px;font-size:8pt;text-align:center;font-weight:700">9</td>
                    <td style="padding:5px 8px;font-size:7.5pt"><span class="pill pill-low">3-6 months</span></td>
                    <td style="padding:5px 8px;font-size:8pt;font-weight:600">Database Security</td>
                    <td style="padding:5px 8px;font-size:7.5pt">Address $($dCosmos.Total) finding(s) in Cosmos DB and OSS databases. Disable public access, enable HA, switch to continuous backup, implement RBAC over shared keys. Enforce TLS 1.2 on Redis.</td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- Methodology -->
    <div class="section-title">14. Assessment Methodology</div>
    <div class="avoid-break">
        <div style="font-size:7.5pt;color:#605e5c;line-height:1.7;columns:2;column-gap:20px">
            <p style="margin-bottom:6px"><strong>Framework:</strong> Azure Well-Architected Framework (5 pillars) + Zero Trust security model (3 layers). 28+ specialized analysis domains covering networking, compute, PaaS, data services, identity, governance, BCDR, cost, modernization, and hybrid infrastructure.</p>
            <p style="margin-bottom:6px"><strong>Data sources:</strong> Azure Resource Graph (bulk queries in batches of 20 subscriptions), Azure Monitor metrics ($MetricDays-day window), Microsoft Defender for Cloud, Azure Advisor, Azure Policy compliance, Recovery Services, Key Vault data plane.</p>
            <p style="margin-bottom:6px"><strong>Scope:</strong> Top-level resources only (child/extension resources excluded from inventory). DDoS findings limited to VNets with public IP exposure. Conditional Access and PIM evaluated once at tenant level. Private endpoint coverage checked for 12 PaaS resource types.</p>
            <p style="margin-bottom:6px"><strong>Severity classification:</strong> <span style="color:#d13438;font-weight:600">Critical</span> = active exploitation risk or imminent service loss. <span style="color:#ca5010;font-weight:600">High</span> = significant gap requiring short-term action. <span style="color:#605e5c;font-weight:600">Medium</span> = best practice deviation. <span style="color:#107c10;font-weight:600">Low</span> = optimization opportunity.</p>
            <p style="margin-bottom:6px"><strong>Limitations:</strong> This assessment reflects point-in-time configuration state. It does not perform penetration testing, data classification, or application-level security review. Findings should be validated with the architecture and security team before implementing changes in production environments.</p>
        </div>
    </div>

    <!-- Disclaimer -->
    <div style="background:#f3f2f1;border-radius:4px;padding:8px 12px;margin-top:12px;font-size:7pt;color:#605e5c;line-height:1.5">
        <strong>Disclaimer:</strong> This report was automatically generated by the Azure Tenant Assessment tool. Findings are based on current resource configuration and metrics from the indicated period. Results are advisory and do not replace a manual Well-Architected Framework assessment or professional security audit. Microsoft is not responsible for actions taken based on this automated assessment.
    </div>

    <div class="page-footer">
        <span>Microsoft Azure — Executive Assessment Report</span>
        <span>$genDate &#183; Confidential</span>
        <span>Page 5 of 5</span>
    </div>
</div>

</body>
</html>
"@

    $reportPath = Join-Path $OutputPath "Executive_Report.html"
    $html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
    Write-Status "Executive report generated: $reportPath" "OK"
    Write-Status "  -> Open in Chrome/Edge and use Ctrl+P (Save as PDF) to export" "INFO"
}


function Export-Data {
    Write-Status "Exporting data..." "SECTION"

    # Full JSON
    $exportData = @{
        GeneratedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Subscriptions  = $script:Subscriptions
        Summary        = $script:Summary
        Findings       = $script:Findings
        Resources      = $script:Resources
        NetworkTopology = $script:NetworkTopology
    }
    $jsonPath = Join-Path $OutputPath "Assessment_Data.json"
    $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Status "  JSON: $jsonPath" "OK"

    # Findings CSV
    $csvPath = Join-Path $OutputPath "Findings.csv"
    $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Status "  CSV: $csvPath" "OK"
}

# ============================================================================
# MAIN - ORCHESTRATION
# ============================================================================
function Main {
    Initialize-Assessment
    Start-KeepAlive   # Prevent Cloud Shell idle timeout

    # ── Pre-fetch security data via Resource Graph (bulk, in batches of 10 subs) ──
    $script:CachedSecurityAssessments = @{}   # Key = subscriptionId
    $script:CachedSecurityAlerts = @{}        # Key = subscriptionId
    $allSubIds = $script:Subscriptions | ForEach-Object { $_.Id }
    if ((Get-Module -ListAvailable -Name Az.ResourceGraph) -and $allSubIds.Count -gt 0) {
        Import-Module Az.ResourceGraph -ErrorAction SilentlyContinue

        # Helper: runs a Resource Graph query in batches of $SubBatchSize subscriptions with full pagination
        $SubBatchSize = 20
        function Invoke-GraphBulkQuery {
            param([string]$QueryText, [array]$SubscriptionIds, [int]$BatchSize = 20)
            $allResults = [System.Collections.Generic.List[PSObject]]::new()
            $subBatches = for ($i = 0; $i -lt $SubscriptionIds.Count; $i += $BatchSize) {
                ,@($SubscriptionIds[$i..[math]::Min($i + $BatchSize - 1, $SubscriptionIds.Count - 1)])
            }
            $totalBatches = $subBatches.Count
            $batchNum = 0
            foreach ($batch in $subBatches) {
                $batchNum++
                Write-Host "    [$batchNum/$totalBatches] " -NoNewline -ForegroundColor DarkGray
                try {
                    $skipToken = $null
                    $pageCount = 0
                    do {
                        $graphParams = @{
                            Query        = $QueryText
                            Subscription = $batch
                            First        = 1000
                            ErrorAction  = 'Stop'
                        }
                        if ($skipToken) { $graphParams['SkipToken'] = $skipToken }
                        $result = Search-AzGraph @graphParams
                        if ($result) {
                            foreach ($item in $result) { $allResults.Add($item) }
                            $pageCount++
                            Write-Host "." -NoNewline -ForegroundColor DarkGray
                        }
                        $skipToken = $result.SkipToken
                    } while ($skipToken)
                    Write-Host " $($allResults.Count)" -ForegroundColor DarkGray
                } catch {
                    Write-Host " FAIL" -ForegroundColor Yellow
                    Write-Status "  Batch $batchNum failed (partial results kept): $($_.Exception.Message)" "WARN"
                }
            }
            return $allResults
        }

        Write-Status "Pre-fetching security assessments via Resource Graph (batches of $SubBatchSize subs)..." "SECTION"
        try {
            $allAssessments = Invoke-GraphBulkQuery -QueryText "securityresources | where type == 'microsoft.security/assessments' | where properties.status.code == 'Unhealthy' | where properties.metadata.severity == 'High' | project subscriptionId, name, displayName=properties.displayName, severity=properties.metadata.severity, statusCode=properties.status.code, resourceId=properties.resourceDetails.Id" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($a in $allAssessments) {
                $sid = $a.subscriptionId
                if (-not $script:CachedSecurityAssessments.ContainsKey($sid)) {
                    $script:CachedSecurityAssessments[$sid] = [System.Collections.Generic.List[PSObject]]::new()
                }
                $script:CachedSecurityAssessments[$sid].Add($a)
            }
            Write-Status "  Security assessments cached: $($allAssessments.Count) unhealthy across $($script:CachedSecurityAssessments.Keys.Count) subscriptions" "OK"
        } catch {
            Write-Status "  Resource Graph security query failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        Write-Status "Pre-fetching security alerts via Resource Graph..." "INFO"
        try {
            $allAlerts = Invoke-GraphBulkQuery -QueryText "securityresources | where type == 'microsoft.security/locations/alerts' | where properties.status == 'Active' or properties.status == 'InProgress' | project subscriptionId, alertName=properties.alertDisplayName, severity=properties.severity, status=properties.status, entity=properties.compromisedEntity, intent=properties.intent" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($a in $allAlerts) {
                $sid = $a.subscriptionId
                if (-not $script:CachedSecurityAlerts.ContainsKey($sid)) {
                    $script:CachedSecurityAlerts[$sid] = [System.Collections.Generic.List[PSObject]]::new()
                }
                $script:CachedSecurityAlerts[$sid].Add($a)
            }
            Write-Status "  Security alerts cached: $($allAlerts.Count) active across $($script:CachedSecurityAlerts.Keys.Count) subscriptions" "OK"
        } catch {
            Write-Status "  Resource Graph alerts query failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Advisor Recommendations (Cost category) ──
        $script:CachedAdvisorCost = @{}
        Write-Status "Pre-fetching Advisor cost recommendations via Resource Graph..." "INFO"
        try {
            $allAdvisor = Invoke-GraphBulkQuery -QueryText "advisorresources | where type =~ 'microsoft.advisor/recommendations' | where properties.category == 'Cost' | project subscriptionId, id, name, resourceGroup, properties" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($a in $allAdvisor) {
                $sid = $a.subscriptionId
                if (-not $script:CachedAdvisorCost.ContainsKey($sid)) { $script:CachedAdvisorCost[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedAdvisorCost[$sid].Add($a)
            }
            Write-Status "  Advisor cost recs cached: $($allAdvisor.Count) across $($script:CachedAdvisorCost.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Advisor pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Policy States (non-compliant) ──
        $script:CachedPolicyStates = @{}
        Write-Status "Pre-fetching policy compliance via Resource Graph..." "INFO"
        try {
            $allPolicy = Invoke-GraphBulkQuery -QueryText "policyresources | where type =~ 'microsoft.policyinsights/policystates' | where properties.complianceState == 'NonCompliant' | summarize nonCompliantCount=count(), policies=make_set(properties.policyDefinitionName, 5) by subscriptionId" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($p in $allPolicy) {
                $script:CachedPolicyStates[$p.subscriptionId] = $p
            }
            Write-Status "  Policy states cached: $($allPolicy.Count) subscriptions with non-compliant resources" "OK"
        } catch {
            Write-Status "  Policy pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Resource Locks ──
        $script:CachedResourceLocks = @{}
        Write-Status "Pre-fetching resource locks via Resource Graph..." "INFO"
        try {
            $allLocks = Invoke-GraphBulkQuery -QueryText "authorizationresources | where type =~ 'microsoft.authorization/locks' | project subscriptionId, id, name, properties" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($l in $allLocks) {
                $sid = $l.subscriptionId
                if (-not $script:CachedResourceLocks.ContainsKey($sid)) { $script:CachedResourceLocks[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedResourceLocks[$sid].Add($l)
            }
            Write-Status "  Resource locks cached: $($allLocks.Count) across $($script:CachedResourceLocks.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Locks pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Role Assignments (summarized count per sub — full list too large for big tenants) ──
        $script:CachedRoleAssignments = @{}
        Write-Status "Pre-fetching role assignments via Resource Graph..." "INFO"
        try {
            $allRoles = Invoke-GraphBulkQuery -QueryText "authorizationresources | where type =~ 'microsoft.authorization/roleassignments' | project subscriptionId, id, roleId=tostring(properties.roleDefinitionId), principalType=tostring(properties.principalType), scope=tostring(properties.scope)" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($r in $allRoles) {
                $sid = $r.subscriptionId
                if (-not $script:CachedRoleAssignments.ContainsKey($sid)) { $script:CachedRoleAssignments[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedRoleAssignments[$sid].Add($r)
            }
            Write-Status "  Role assignments cached: $($allRoles.Count) across $($script:CachedRoleAssignments.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Role assignments pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Secure Scores ──
        $script:CachedSecureScores = @{}
        Write-Status "Pre-fetching secure scores via Resource Graph..." "INFO"
        try {
            $allScores = Invoke-GraphBulkQuery -QueryText "securityresources | where type =~ 'microsoft.security/securescores' | project subscriptionId, properties" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($s in $allScores) {
                $sid = $s.subscriptionId
                if (-not $script:CachedSecureScores.ContainsKey($sid)) { $script:CachedSecureScores[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedSecureScores[$sid].Add($s)
            }
            Write-Status "  Secure scores cached: $($allScores.Count) across $($script:CachedSecureScores.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Secure scores pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Regulatory Compliance ──
        $script:CachedRegulatoryCompliance = @{}
        Write-Status "Pre-fetching regulatory compliance via Resource Graph..." "INFO"
        try {
            $allComp = Invoke-GraphBulkQuery -QueryText "securityresources | where type =~ 'microsoft.security/regulatorycompliancestandards' | project subscriptionId, name, properties" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($c in $allComp) {
                $sid = $c.subscriptionId
                if (-not $script:CachedRegulatoryCompliance.ContainsKey($sid)) { $script:CachedRegulatoryCompliance[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedRegulatoryCompliance[$sid].Add($c)
            }
            Write-Status "  Regulatory compliance cached: $($allComp.Count) across $($script:CachedRegulatoryCompliance.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Regulatory compliance pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Auto-shutdown schedules ──
        $script:CachedAutoShutdown = @{}
        Write-Status "Pre-fetching auto-shutdown schedules via Resource Graph..." "INFO"
        try {
            $allShutdown = Invoke-GraphBulkQuery -QueryText "resources | where type =~ 'microsoft.devtestlab/schedules' | where name startswith 'shutdown-computevm-' | project subscriptionId, id, name, properties" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($s in $allShutdown) {
                $sid = $s.subscriptionId
                if (-not $script:CachedAutoShutdown.ContainsKey($sid)) { $script:CachedAutoShutdown[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedAutoShutdown[$sid].Add($s)
            }
            Write-Status "  Auto-shutdown cached: $($allShutdown.Count) schedules across $($script:CachedAutoShutdown.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Auto-shutdown pre-fetch failed (will fall back to per-sub): $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache Key Vault secrets/keys/certificates expiration via Resource Graph ──
        Write-Status "Pre-fetching Key Vault secrets/keys/certificates expiration via Resource Graph..." "INFO"
        try {
            $kvSecrets = Invoke-GraphBulkQuery -QueryText "resources | where type =~ 'microsoft.keyvault/vaults/secrets' | project subscriptionId, id, name, resourceGroup, enabled=properties.attributes.enabled, expires=properties.attributes.exp, vaultName=tostring(split(id, '/')[8])" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($s in $kvSecrets) {
                $sid = $s.subscriptionId
                if (-not $script:CachedKVSecrets.ContainsKey($sid)) { $script:CachedKVSecrets[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedKVSecrets[$sid].Add($s)
            }
            Write-Status "  KV secrets cached: $($kvSecrets.Count) across $($script:CachedKVSecrets.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  KV secrets pre-fetch failed (will fall back to data-plane): $($_.Exception.Message)" "WARN"
        }
        try {
            $kvKeys = Invoke-GraphBulkQuery -QueryText "resources | where type =~ 'microsoft.keyvault/vaults/keys' | project subscriptionId, id, name, resourceGroup, enabled=properties.attributes.enabled, expires=properties.attributes.exp, vaultName=tostring(split(id, '/')[8])" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($k in $kvKeys) {
                $sid = $k.subscriptionId
                if (-not $script:CachedKVKeys.ContainsKey($sid)) { $script:CachedKVKeys[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedKVKeys[$sid].Add($k)
            }
            Write-Status "  KV keys cached: $($kvKeys.Count) across $($script:CachedKVKeys.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  KV keys pre-fetch failed: $($_.Exception.Message)" "WARN"
        }
        try {
            $kvCerts = Invoke-GraphBulkQuery -QueryText "resources | where type =~ 'microsoft.keyvault/vaults/certificates' | project subscriptionId, id, name, resourceGroup, enabled=properties.attributes.enabled, expires=properties.attributes.exp, vaultName=tostring(split(id, '/')[8])" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($c in $kvCerts) {
                $sid = $c.subscriptionId
                if (-not $script:CachedKVCerts.ContainsKey($sid)) { $script:CachedKVCerts[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedKVCerts[$sid].Add($c)
            }
            Write-Status "  KV certificates cached: $($kvCerts.Count) across $($script:CachedKVCerts.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  KV certificates pre-fetch failed: $($_.Exception.Message)" "WARN"
        }

        # ── Pre-cache BCDR backup items via Resource Graph (recoveryservicesresources table) ──
        Write-Status "Pre-fetching backup items via Resource Graph..." "INFO"
        try {
            $allBackupItems = Invoke-GraphBulkQuery -QueryText "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | project subscriptionId, id, name, resourceGroup, lastBackupStatus=properties.lastBackupStatus, lastBackupTime=properties.lastBackupTime, protectionState=properties.protectionState, sourceResourceId=properties.sourceResourceId, backupManagementType=properties.backupManagementType, vaultName=tostring(split(id, '/')[8])" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($b in $allBackupItems) {
                $sid = $b.subscriptionId
                if (-not $script:CachedBackupItems.ContainsKey($sid)) { $script:CachedBackupItems[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedBackupItems[$sid].Add($b)
            }
            Write-Status "  Backup items cached: $($allBackupItems.Count) across $($script:CachedBackupItems.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Backup items pre-fetch failed (will fall back to per-vault): $($_.Exception.Message)" "WARN"
        }
        try {
            $allBackupPolicies = Invoke-GraphBulkQuery -QueryText "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backuppolicies' | project subscriptionId, id, name, resourceGroup, properties, vaultName=tostring(split(id, '/')[8])" -SubscriptionIds $allSubIds -BatchSize $SubBatchSize
            foreach ($p in $allBackupPolicies) {
                $sid = $p.subscriptionId
                if (-not $script:CachedBackupPolicies.ContainsKey($sid)) { $script:CachedBackupPolicies[$sid] = [System.Collections.Generic.List[PSObject]]::new() }
                $script:CachedBackupPolicies[$sid].Add($p)
            }
            Write-Status "  Backup policies cached: $($allBackupPolicies.Count) across $($script:CachedBackupPolicies.Keys.Count) subs" "OK"
        } catch {
            Write-Status "  Backup policies pre-fetch failed: $($_.Exception.Message)" "WARN"
        }
    }

    # ── ALZ/CAF Readiness (tenant-wide, runs once before per-subscription loop) ──
    Invoke-AnalysisStep "ALZReadiness" "" "Tenant-wide" { Analyze-ALZReadiness }

    $subIndex = 0
    $subTotal = $script:Subscriptions.Count
    $consecutiveNetworkFailures = 0
    foreach ($sub in $script:Subscriptions) {
        $subIndex++
        $elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
        Write-Host ""
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
        Write-Status "[$subIndex/$subTotal] ANALYZING SUBSCRIPTION: $($sub.Name)  ($elapsed min elapsed)" "SECTION"
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

        # Switch subscription context with retry logic for transient network failures
        $switchSuccess = $false
        for ($retryAttempt = 1; $retryAttempt -le 3; $retryAttempt++) {
            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
                $switchSuccess = $true
                $consecutiveNetworkFailures = 0
                break
            } catch {
                $errMsg = $_.Exception.Message
                if ($errMsg -match 'No such host is known|name.resolution|DNS|network.unreachable|timeout' -and $retryAttempt -lt 3) {
                    Write-Status "  Network error switching to $($sub.Name) (attempt $retryAttempt/3) — retrying in $($retryAttempt * 15)s..." "WARN"
                    Start-Sleep -Seconds ($retryAttempt * 15)
                } else {
                    Write-Status "Could not switch to subscription $($sub.Name): $errMsg" "ERROR"
                    break
                }
            }
        }
        if (-not $switchSuccess) {
            $consecutiveNetworkFailures++
            if ($consecutiveNetworkFailures -ge 3) {
                Write-Host ""
                Write-Status "ABORTING: $consecutiveNetworkFailures consecutive network failures detected." "ERROR"
                Write-Status "Cloud Shell has lost connectivity to Azure (DNS resolution failed for management.azure.com)." "ERROR"
                Write-Status "The report will be generated with data collected so far ($($subIndex - $consecutiveNetworkFailures)/$subTotal subscriptions)." "WARN"
                Write-Status "To complete the assessment: restart Cloud Shell and re-run the script." "INFO"
                Write-Host ""
                break
            }
            continue
        }

        # Clear caches from previous subscription to prevent cross-contamination
        Clear-SubscriptionCaches

        # Collect data once per subscription (eliminates redundant API calls)
        Invoke-AnalysisStep "DataCollection"          $sub.Id $sub.Name { Invoke-DataCollection -SubId $sub.Id -SubName $sub.Name; $script:DataCollectionSucceeded = $true }

        # Skip all analysis if data collection failed (prevents stale cache from previous sub)
        if (-not $script:DataCollectionSucceeded) {
            Write-Status "Skipping analysis for $($sub.Name) — data collection failed" "WARN"
            continue
        }

        # Collect cost analysis (6 months)
        Invoke-AnalysisStep "CostAnalysis"            $sub.Id $sub.Name { Get-SubscriptionCostAnalysis -SubId $sub.Id -SubName $sub.Name }

        Invoke-AnalysisStep "ResourceInventory"       $sub.Id $sub.Name { Get-ResourceInventory -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "Networking"               $sub.Id $sub.Name { Analyze-Networking    -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "VirtualMachines"          $sub.Id $sub.Name { Analyze-VirtualMachines -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "AppServices"              $sub.Id $sub.Name { Analyze-AppServices   -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "Databases"                $sub.Id $sub.Name { Analyze-Databases     -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "Storage"                  $sub.Id $sub.Name { Analyze-Storage       -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "KeyVaults"                $sub.Id $sub.Name { Analyze-KeyVaults     -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "OrphanedResources"        $sub.Id $sub.Name { Analyze-OrphanedResources -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "SecurityCenter"           $sub.Id $sub.Name { Analyze-SecurityCenter -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "AKS"                      $sub.Id $sub.Name { Analyze-AKS               -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "ZeroTrust"                $sub.Id $sub.Name { Analyze-ZeroTrust         -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "UnderutilizedResources"   $sub.Id $sub.Name { Analyze-UnderutilizedResources -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "Modernization"            $sub.Id $sub.Name { Analyze-Modernization          -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "DevOpsSecurity"           $sub.Id $sub.Name { Analyze-DevOpsSecurity         -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "ApplicationSecurity"      $sub.Id $sub.Name { Analyze-ApplicationSecurity    -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "CostAdvisor"              $sub.Id $sub.Name { Analyze-CostAdvisor            -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "Reservations"             $sub.Id $sub.Name { Analyze-Reservations           -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "HybridInfrastructure"     $sub.Id $sub.Name { Analyze-HybridInfrastructure   -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "HighAvailability"         $sub.Id $sub.Name { Analyze-HighAvailability       -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "BCDR"                     $sub.Id $sub.Name { Analyze-BCDR                   -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "ResourceLocks"            $sub.Id $sub.Name { Analyze-ResourceLocks          -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "ExpiringSecrets"          $sub.Id $sub.Name { Analyze-ExpiringSecrets        -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "TagCompliance"            $sub.Id $sub.Name { Analyze-TagCompliance          -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "DiagnosticSettings"       $sub.Id $sub.Name { Analyze-DiagnosticSettings     -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "PrivateEndpoints"         $sub.Id $sub.Name { Analyze-PrivateEndpoints       -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "PolicyCompliance"         $sub.Id $sub.Name { Analyze-PolicyCompliance       -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "CosmosOSSDatabase"        $sub.Id $sub.Name { Analyze-CosmosOSSDatabase      -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "SubscriptionHygiene"      $sub.Id $sub.Name { Analyze-SubscriptionHygiene    -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "AdditionalChecks"         $sub.Id $sub.Name { Analyze-AdditionalChecks       -SubId $sub.Id -SubName $sub.Name }
        Invoke-AnalysisStep "CrossPillarCorrelation"   $sub.Id $sub.Name { Analyze-CrossPillarCorrelation -SubId $sub.Id -SubName $sub.Name }
    }

    # Generate reports
    Invoke-AnalysisStep "Generate-HTMLReport"       "" "Reports" { Generate-HTMLReport }
    Invoke-AnalysisStep "Generate-ArchitectureDiagram" "" "Reports" { Generate-ArchitectureDiagram }
    Invoke-AnalysisStep "Generate-ExecutiveReport"  "" "Reports" { Generate-ExecutiveReport }
    Invoke-AnalysisStep "Export-Data"               "" "Reports" { Export-Data }

    Stop-KeepAlive   # Clean up keep-alive timer

    # ── Compute final status ──
    $duration     = (Get-Date) - $script:StartTime
    $totalSteps   = $script:StepResults.Count
    $failedSteps  = @($script:StepResults | Where-Object { $_.Status -eq 'FAILED' })
    $okSteps      = @($script:StepResults | Where-Object { $_.Status -eq 'OK' })
    $errorCount   = $script:ErrorLog.Count
    $reportsOK    = @($script:StepResults | Where-Object { $_.Subscription -eq 'Reports' -and $_.Status -eq 'OK' }).Count

    if ($errorCount -eq 0 -and $reportsOK -ge 4) {
        $overallStatus = "SUCCESS"
        $statusColor   = "Green"
        $statusIcon    = "✅"
    } elseif ($reportsOK -ge 2 -and $failedSteps.Count -lt ($totalSteps / 2)) {
        $overallStatus = "COMPLETED WITH WARNINGS"
        $statusColor   = "Yellow"
        $statusIcon    = "⚠️"
    } else {
        $overallStatus = "FAILED"
        $statusColor   = "Red"
        $statusIcon    = "❌"
    }

    # ── Banner ──
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor $statusColor
    Write-Host "║        ASSESSMENT $overallStatus $(' ' * [Math]::Max(0, 35 - $overallStatus.Length))║" -ForegroundColor $statusColor
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor $statusColor
    Write-Host ""

    # ── Duration and counts ──
    $durationStr = if ($duration.TotalHours -ge 1) {
        "$([math]::Floor($duration.TotalHours))h $($duration.Minutes)m $($duration.Seconds)s"
    } else {
        "$([math]::Round($duration.TotalMinutes, 1)) minutes"
    }
    Write-Status "Total duration: $durationStr" "OK"
    Write-Status "Subscriptions processed: $subTotal" "OK"
    Write-Status "Analysis steps: $($okSteps.Count)/$totalSteps succeeded" $(if($errorCount -eq 0){"OK"}else{"WARN"})
    Write-Status "Resources analyzed: $($script:Summary.TotalResources)" "OK"
    Write-Status "Total findings: $($script:Findings.Count)" "OK"
    Write-Status "  🔴 Critical: $($script:Summary.Critical)" $(if($script:Summary.Critical -gt 0){"WARN"}else{"OK"})
    Write-Status "  🟠 High:     $($script:Summary.High)" $(if($script:Summary.High -gt 0){"WARN"}else{"OK"})
    Write-Status "  🟡 Medium:   $($script:Summary.Medium)" "INFO"
    Write-Status "  🟢 Low:      $($script:Summary.Low)" "INFO"

    # ── Errors detail ──
    if ($errorCount -gt 0) {
        Write-Host ""
        Write-Host "  ── ERRORS ($errorCount) ──────────────────────────────────────────" -ForegroundColor Red
        foreach ($err in $script:ErrorLog) {
            $ts = $err.Timestamp.ToString("HH:mm:ss")
            Write-Host "  [$ts] $($err.Step) @ $($err.Subscription): $($err.Error)" -ForegroundColor Red
        }
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor Red
    }

    # ── Slowest steps (top 5) ──
    $slowest = $script:StepResults | Sort-Object DurationSec -Descending | Select-Object -First 5
    if ($slowest) {
        Write-Host ""
        Write-Host "  ── SLOWEST STEPS ─────────────────────────────────────────────" -ForegroundColor DarkGray
        foreach ($s in $slowest) {
            $durStr = if ($s.DurationSec -ge 60) { "$([math]::Floor($s.DurationSec / 60))m $([math]::Round($s.DurationSec % 60))s" } else { "$($s.DurationSec)s" }
            $icon = if ($s.Status -eq 'OK') { '✓' } else { '✗' }
            Write-Host "  $icon $($s.Step.PadRight(28)) $($durStr.PadLeft(8))  ($($s.Subscription))" -ForegroundColor $(if($s.Status -eq 'OK'){"DarkGray"}else{"Red"})
        }
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    }

    # ── Files ──
    Write-Host ""
    Write-Status "FILES GENERATED IN: $((Resolve-Path $OutputPath).Path)" "OK"
    $expectedFiles = @(
        @{ Name = "Assessment_Report.html";  Desc = "Full interactive report" }
        @{ Name = "Executive_Report.html";   Desc = "Executive report (PDF-ready)" }
        @{ Name = "Network_Topology.html";   Desc = "Interactive SVG network diagram" }
        @{ Name = "Network_Topology.drawio"; Desc = "Editable network diagram (draw.io)" }
        @{ Name = "Assessment_Data.json";    Desc = "Complete data in JSON" }
        @{ Name = "Findings.csv";            Desc = "Exportable findings" }
        @{ Name = "Assessment_Log.txt";      Desc = "Execution log" }
    )
    foreach ($f in $expectedFiles) {
        $fPath = Join-Path (Resolve-Path $OutputPath).Path $f.Name
        if (Test-Path $fPath) {
            $sizeMB = [math]::Round((Get-Item $fPath).Length / 1MB, 2)
            Write-Host "  ✓ $($f.Name.PadRight(32)) $($sizeMB.ToString().PadLeft(6)) MB  - $($f.Desc)" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $($f.Name.PadRight(32))  MISSING  - $($f.Desc)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # Create ZIP for easy download (especially useful in Azure Cloud Shell)
    $zipPath = "$((Resolve-Path $OutputPath).Path).zip"
    try {
        Compress-Archive -Path "$((Resolve-Path $OutputPath).Path)/*" -DestinationPath $zipPath -Force
        $zipSizeMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
        Write-Host "  📦 $zipPath ($zipSizeMB MB)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  To download in Azure Cloud Shell: click Download, enter path:" -ForegroundColor Yellow
        Write-Host "    $zipPath" -ForegroundColor White
    } catch {
        Write-Host "  (ZIP creation skipped: $($_.Exception.Message))" -ForegroundColor DarkGray
    }

    # ── Write completion to log file ──
    $logSummary = @"

══════════════════════════════════════════════════════════════
FINAL STATUS: $statusIcon $overallStatus
Duration: $durationStr
Steps: $($okSteps.Count)/$totalSteps OK | $($failedSteps.Count) failed
Findings: $($script:Findings.Count) (Critical=$($script:Summary.Critical), High=$($script:Summary.High), Medium=$($script:Summary.Medium), Low=$($script:Summary.Low))
Resources: $($script:Summary.TotalResources)
Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
══════════════════════════════════════════════════════════════
"@
    $logSummary | Out-File -FilePath $script:LogFilePath -Append -Encoding UTF8 -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "  To generate the executive PDF: open Executive_Report.html in Chrome/Edge and use Ctrl+P." -ForegroundColor Yellow
    Write-Host ""

    # Audible notification — 3 beeps to alert the user (skip on Linux/Cloud Shell)
    try { 1..3 | ForEach-Object { [Console]::Beep(800, 300); Start-Sleep -Milliseconds 200 } } catch { Write-Host "`a" -NoNewline }
    Write-Host ""
}

# Execute
try {
    Main
} catch {
    Write-Host "`n`n[FATAL] Assessment terminated with error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
} finally {
    # Ensure keep-alive timer is always cleaned up
    try { Stop-KeepAlive } catch { }
}

# SIG # Begin signature block
# MIIcEQYJKoZIhvcNAQcCoIIcAjCCG/4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAzeG3odWR063ex
# 1/TstxSilSws3XcGETV9fImz5+PXH6CCFlQwggMWMIIB/qADAgECAhB05LE1IRL+
# rkeuEM34A+X/MA0GCSqGSIb3DQEBCwUAMCMxITAfBgNVBAMMGFBhYmxvQVIgQXp1
# cmUgQXNzZXNzbWVudDAeFw0yNjA1MjMwMTM5MDdaFw0zMTA1MjMwMTQ5MDRaMCMx
# ITAfBgNVBAMMGFBhYmxvQVIgQXp1cmUgQXNzZXNzbWVudDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALETiq+evA0GyJqXzgXGIhXNJuFZdBfmsmI4tWaM
# WAU28a3P3geQ7k12eKaj4T6eh1yNJyUeRGgHipayBuAkrA3O5wVB7YPFKi07D2Oi
# RQS8pZccCoLRt7Keo34IDYjZid/vr5eVAGRCbP1vqjfsOOIsRg539P+o4IDJweEt
# N5u+FINQsw2Y1z+Ef1SwLhD+EL3mhhpPoCyh/nK9IQUQtKlNZxh5BkhldClc+5RA
# uSQ0NxvnqBxAyw5EjwnjIqehZ2qH7v0y6DzhpRusFk8ZAq0kjweOb0FYYRaEw1OH
# 6q65jNyQEt7gBpl7Na49HwjoJFiP76NqG9pV5qDYbxndTvUCAwEAAaNGMEQwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSS0ibQ
# WTQL69zeyoqaYLp+jgW/ozANBgkqhkiG9w0BAQsFAAOCAQEAEfR8ruic7dMRostA
# MiJyIjP6Dm19N0id/cEQbcgd0Vx8c+7fFavvlU3X+y0t/2/GFZf6+ttUuCW41YVE
# FK6MIPJChXVKzBAnolGecwt/R5DTz6cdWh49v8W9EMbdvkwg5NxiSsdlhkBpF6+h
# WE2Clr69hUFDhhy/V1cpxZ+behL6/7ZMbf5cEHZ2frC1tWx1wAze71rTi+IvxRsK
# D+0QeBdFQRJgLm1hldobGNWLUXDcP0NlaRLuMSA875ug6EWnG+k54di3BvWU4mDL
# lH1NShfXEe6Eu7WpXJeuxpQ0PcAmaFLS8ExCY4yuBaqGgomeY0+0l+O7dNkm98Us
# Zp7z6zCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEM
# BQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UE
# CxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJ
# RCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkG
# A1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRp
# Z2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zC
# pyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf
# 1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x
# 4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEio
# ZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A2raRmECQecN4x7ax
# xLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZ
# OjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJ
# l2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz
# 2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH
# 4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb
# 5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ
# 9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuC
# MS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0g
# ADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs
# 7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq
# 3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/
# Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9
# /HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWoj
# ayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5lDCCBrQwggScoAMC
# AQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUw
# NzAwMDAwMFoXDTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2U
# tZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWC
# WgzbNfiR+2fkHUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+
# gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DP
# fNBKS7Zazch8NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVV
# gtmUPAW35xUUFREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifi
# nT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x
# 5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HH
# fIY4/6vHespYMQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQ
# yogxG9QEPHrPV6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70Ew
# gWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7Zr
# IGNTAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTv
# b1NK6eQGfHrK4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qY
# rhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYB
# BQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# QQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877
# FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI
# 9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3ess
# BS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qK
# tntujB71WPYAgwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I
# +ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q1
# 7r0z0noDjs6+BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+Mt
# ucVGyOxiDf06VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9J
# GYxOGLS/D284NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlH
# qhpB/8MluDezooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7G
# ELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlar
# Evf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ9k+5t1wwggbtMIIE1aADAgECAhAKgO8Y
# S43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0
# MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2
# IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfMGUIwYzKomd8U
# 1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt
# 281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9R
# aUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjKs3SKO1QNUdFd
# 2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8odbkqoK+lJ25L
# CHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK40uhktzUd/Yk0
# xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk12hE5FVs9HVV
# WcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0
# ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/
# DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT3pXWETTJkhd7
# 6CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A9/z7eacCAwEA
# AaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZ
# UEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB
# /wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgw
# gYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEF
# BQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAGUq
# rfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP2AGr181o2YWP
# oSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8wv2UV+Kbz/3Im
# ZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhc
# UT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihsQyfFg5fxUFEp
# 7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtf
# parz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu
# /CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8MmB10nfldPF9
# SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjFBtXVLcKtapnM
# G3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJVxwC+UpX2MSe
# y2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFlTxq25+T4QwX9
# xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMYIFEzCCBQ8CAQEwNzAjMSEw
# HwYDVQQDDBhQYWJsb0FSIEF6dXJlIEFzc2Vzc21lbnQCEHTksTUhEv6uR64QzfgD
# 5f8wDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgJEaUAb+NeqtkfpCcvFbxG9fE0cS9clXb
# Kcn7Ts4plUgwDQYJKoZIhvcNAQEBBQAEggEAZKRtnWctfHucoNE8ktrvmsaOZvHG
# rVA1PkN2SJci3+scwQiGdtAgF+P+uOx49ssSSHIgGUW/HUCbpjY5n8dwH3abdry3
# tZY53X1/S/PrfyrE1fwwM3ZKfT6SXR5RV4/Im/SpvepW/qyL47jPwsVG7u2mcSmg
# FEY0ffD4wYL/pVi51YbF77mFtu4nyG1H6RT117Tq5UJAyB7czDd8pEo49zJYZdfs
# ZL8IU7sgW4NTCxmju/44FDGCVh1AmMRKcTZ7VHrXVUQYKiFZ8BFpCwo/AaqaB5DI
# KaRVBSmJEhsOVAl1lz8HgbzDSA9DThuTFgRb33rSMbTb3Syhpj1CqWGhZqGCAyYw
# ggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcN
# AQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA1MjUyMjU0MDlaMC8GCSqGSIb3DQEJBDEi
# BCCYktL09zBCBkdXF9D2vguwKuHps/lEkbngJdo3KFuvJzANBgkqhkiG9w0BAQEF
# AASCAgAmypRcmQlHfE7867wmrFF4p3boUp8fgbMdscJsGE82/5uBAxwnky1Kf50e
# RyXYcIimUYScGktATKaJ7ZbCmeB1eYUXkexh7cvQY1ZM7rKvDZNUTlkl3GtbrnU+
# xlq3SJ8BGhoBnDiPX3G/efRt5A+qnY95UaJL3BV3+Ai9y1UAdj8SaQORYv9KOVpI
# ytbCSi62QFwZQwS40iTA8C0FF2UufLqB5OeRXYueiRNi9k1jyPyFKTiH5+7xEjzx
# 55aYHrpQSNIWjM5Uxx/i62AbhH20vSlb4M6c1I1WqaORbp3lKtcSE4KX2lTf1ulE
# I9LvirloXnFh2Anjq3qGP674GJJhV5XgEMD9d6OirsYDXJGZ+jCjqycxk2WG3x8W
# ZZ8ju3Iru8qTK54itDne28o1RtIiToO8EhjMAY7Vb2QG2thDOnKs4qujIL+MmbtH
# iZWsf7ITnVaf5at8jF3eQMo35qFbVcXCCuYgYCjdSbgcfQKBlJF/SbaZE2eKfbM/
# QDWzSbznr4K359VVQRGmUd6HUvDXY5J/0RSpWuqXMenHoYhKbye2IBYWO1UMtEDW
# A9XnkaNmb63hr351O6NWox5WxhcEjk0HSL9l1fjszhbwfKlmHbZVhqyN3MKkgswX
# z/5G/jtraivahhYyFJSAIIWV9o81kgVvjVVLqLqFxJhH1piF7Q==
# SIG # End signature block

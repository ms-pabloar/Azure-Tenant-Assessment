$scriptPath = Join-Path $PSScriptRoot '..\Azure-Tenant-Assessment.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

function Get-FunctionText {
    param([string]$Name)

    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $Name" }
    return $definition.Extent.Text
}

. ([scriptblock]::Create((Get-FunctionText 'Test-CachedResourceType')))
. ([scriptblock]::Create((Get-FunctionText 'Get-CachedResourceGraphResourcesByType')))
. ([scriptblock]::Create((Get-FunctionText 'Test-ObjectProperty')))
. ([scriptblock]::Create((Get-FunctionText 'ConvertFrom-GitHubCopilotReport')))
. ([scriptblock]::Create((Get-FunctionText 'Invoke-ExternalRequestWithRetry')))

Describe 'Resource-aware collection' {
    It 'skips types known to be absent' {
        $script:CachedResourceTypeCounts = @{}
        Test-CachedResourceType 'microsoft.compute/virtualmachines' | Should Be $false
    }

    It 'allows types present in the Resource Graph inventory' {
        $script:CachedResourceTypeCounts = @{ 'microsoft.compute/virtualmachines' = 3 }
        Test-CachedResourceType 'Microsoft.Compute/virtualMachines' | Should Be $true
    }

    It 'uses the safe fallback when Resource Graph inventory is unavailable' {
        $script:CachedResourceTypeCounts = $null
        Test-CachedResourceType 'microsoft.compute/virtualmachines' | Should Be $true
    }

    It 'guards detailed collection cmdlets by resource type' {
        $text = Get-FunctionText 'Invoke-DataCollection'
        $text | Should Match "Invoke-AzCollectionWhenResourceTypeExists 'microsoft.compute/virtualmachines'"
        $text | Should Match "Invoke-AzCollectionWhenResourceTypeExists 'microsoft.keyvault/vaults'"
        $text | Should Match "Invoke-AzCollectionWhenResourceTypeExists 'microsoft.web/sites'"
        $text | Should Match 'ResourceGroupName \$resourceGroupName'
    }

    It 'gates expensive resource-specific analysis steps' {
        $scriptText = $ast.Extent.Text
        $scriptText | Should Match 'Invoke-AnalysisStepForResourceTypes "Networking"'
        $scriptText | Should Match 'Invoke-AnalysisStepForResourceTypes "DiagnosticSettings"'
        $scriptText | Should Match 'Invoke-AnalysisStepForResourceTypes "CosmosOSSDatabase"'
        $scriptText | Should Match 'Invoke-AnalysisStepForResourceTypes "AIFoundry"'
    }
}

Describe 'Inventory and analysis cache reuse' {
    It 'supports Resource Graph PSCustomObject tags' {
        $tags = [pscustomobject]@{ Owner = 'Platform'; Environment = 'Production' }

        (Test-ObjectProperty -InputObject $tags -Name 'owner') | Should Be $true
        (Test-ObjectProperty -InputObject $tags -Name 'CostCenter') | Should Be $false
    }

    It 'supports hashtable tags' {
        $tags = @{ Owner = 'Platform' }

        (Test-ObjectProperty -InputObject $tags -Name 'Owner') | Should Be $true
    }

    It 'reuses the centralized Resource Graph inventory' {
        (Get-FunctionText 'Get-ResourceInventory') | Should Match 'CachedResourceGraphResources'
        (Get-FunctionText 'Analyze-TagCompliance') | Should Match 'CachedResourceGraphResources'
        (Get-FunctionText 'Analyze-PrivateEndpoints') | Should Match 'CachedResourceGraphResources'
        (Get-FunctionText 'Analyze-SubscriptionHygiene') | Should Match 'CachedResourceGraphResources'
    }

    It 'indexes Resource Graph inventory by resource type in one pass' {
        $collectionText = Get-FunctionText 'Invoke-DataCollection'
        $collectionText | Should Match '\$script:CachedResourcesByType = @\{\}'
        $collectionText | Should Match '\$script:CachedResourcesByType\[\$resourceType\]\.Add\(\$resource\)'
        (Get-FunctionText 'Get-CachedResourceDetailsByType') | Should Match 'Get-CachedResourceGraphResourcesByType'
        (Get-FunctionText 'Analyze-Networking') | Should Match "Get-CachedResourceGraphResourcesByType 'microsoft\.network/networkwatchers/flowlogs'"
    }

    It 'returns a truly empty collection for an absent indexed resource type' {
        $script:CachedResourcesByType = @{}

        $resources = @(Get-CachedResourceGraphResourcesByType 'microsoft.compute/virtualmachines/extensions')

        $resources.Count | Should Be 0
    }

    It 'derives VM extensions from the paged inventory without another query' {
        $text = Get-FunctionText 'Invoke-DataCollection'
        $text | Should Match "Get-CachedResourceGraphResourcesByType 'microsoft\.compute/virtualmachines/extensions'"
        $text | Should Match 'CachedVMExtensions'
        $text | Should Not Match "type -eq 'microsoft\.compute/virtualmachines/extensions'"
        $text | Should Not Match 'Querying VM extensions via Resource Graph'
        $text | Should Not Match '\| order by type asc'
    }

    It 'does not list private endpoints again' {
        (Get-FunctionText 'Analyze-PrivateEndpoints') | Should Not Match 'Get-AzPrivateEndpoint\s+-ErrorAction'
    }

    It 'avoids per-resource NAT gateway detail calls' {
        $text = Get-FunctionText 'Analyze-Networking'
        $text | Should Match 'CachedResourceGraphResources'
        $text | Should Match 'Get-AzNatGateway -ErrorAction'
        $text | Should Not Match 'Get-AzNatGateway -Name'
        $text | Should Not Match "Get-AzResource -ResourceType 'Microsoft\.Network/natGateways'"
    }

    It 'indexes authoritative flow log resources without per-NSG calls' {
        $text = Get-FunctionText 'Analyze-Networking'
        $text | Should Match 'microsoft\.network/networkwatchers/flowlogs'
        $text | Should Match 'targetResourceId'
        $text | Should Match 'flowLogInventoryAvailable'
        $text | Should Not Match 'Get-AzNetworkSecurityGroup -Name'
    }

    It 'indexes public endpoint resource groups for VNet DDoS checks' {
        $text = Get-FunctionText 'Analyze-Networking'
        $text | Should Match 'HashSet\[string\].*OrdinalIgnoreCase'
        $text | Should Match '\$publicEndpointResourceGroups\.Add\(\[string\]\$publicIp\.ResourceGroupName\)'
        $text | Should Match '\$publicEndpointResourceGroups\.Contains\(\[string\]\$vnet\.ResourceGroupName\)'
        $text | Should Not Match '\$script:CachedPublicIPs \| Where-Object'
    }

    It 'treats an empty successful diagnostic query as authoritative' {
        $text = Get-FunctionText 'Analyze-DiagnosticSettings'
        $text | Should Match '\$diagnosticGraphSucceeded = \$true'
        $text | Should Match 'if \(\$diagnosticGraphSucceeded\)'
        $text | Should Match 'SkipToken'
        $text | Should Not Match 'if \(\$resourcesWithDiag\.Count -gt 0\)'
    }

    It 'loads tenant-wide reservation inventory only once' {
        $text = Get-FunctionText 'Analyze-Reservations'
        $text | Should Match 'if \(-not \$SkipTenantInventory -and -not \$script:ReservationInventoryLoaded\)'
        $text | Should Match '\$script:ReservationInventoryLoaded = \$true'
        $ast.Extent.Text | Should Match "Analyze-Reservations\s+-SubName 'Tenant-wide' -TenantInventoryOnly"
        $ast.Extent.Text | Should Match 'Analyze-Reservations\s+-SubId \$sub.Id -SubName \$sub.Name -SkipTenantInventory'
    }

    It 'uses centralized Marketplace metadata and REST only as fallback' {
        $collectionText = Get-FunctionText 'Invoke-DataCollection'
        $marketplaceText = Get-FunctionText 'Analyze-Marketplace'
        $collectionText | Should Match 'sku, plan, properties'
        $marketplaceText | Should Match 'CachedResourceGraphResources'
        $marketplaceText | Should Match 'if \(-not \$marketplaceGraphSucceeded\)'
        $marketplaceText | Should Match 'Get-AzRestPagedValues -Path "/subscriptions/\$SubId/providers/Microsoft\.SaaS/resources'
        $marketplaceText | Should Match 'Get-AzRestPagedValues -Path "/subscriptions/\$SubId/providers/Microsoft\.Solutions/applications'
        $marketplaceText | Should Not Match 'Invoke-AzRestMethod -Path "/subscriptions/\$SubId/providers/Microsoft\.(SaaS/resources|Solutions/applications)'
    }

    It 'paginates the Advisor REST fallback' {
        $text = Get-FunctionText 'Analyze-CostAdvisor'
        $text | Should Match 'Get-AzRestPagedValues -Path \$advisorPath'
        $text | Should Not Match 'Invoke-AzRestMethod -Path "/subscriptions/\$SubId/providers/Microsoft\.Advisor/recommendations'
    }

    It 'reuses cached resource group tags for VM scheduling checks' {
        $text = Get-FunctionText 'Analyze-CostAdvisor'
        $text | Should Match '\$resourceGroupTags\[\[string\]\$resourceGroup\.ResourceGroupName\] = \$resourceGroup\.Tags'
        $text | Should Match '\$resourceGroupTags\.ContainsKey\(\[string\]\$vm\.ResourceGroupName\)'
        $text | Should Not Match 'Get-AzResourceGroup -Name \$vm\.ResourceGroupName'
    }

    It 'treats a successful empty auto-shutdown query as authoritative' {
        $costText = Get-FunctionText 'Analyze-CostAdvisor'
        $ast.Extent.Text | Should Match '\$script:CachedAutoShutdownAvailable = \$true'
        $costText | Should Match 'if \(\$script:CachedAutoShutdownAvailable\)'
        $costText | Should Not Match 'if \(\$shutdownSchedules\.Count -gt 0\)'
    }

    It 'queries SQL failover groups once per server' {
        $text = Get-FunctionText 'Analyze-Databases'
        ([regex]::Matches($text, 'Get-AzSqlDatabaseFailoverGroup')).Count | Should Be 1
        $text | Should Match '\$failoverGroups = Safe-AzCommand'
        $text | Should Match '\$failoverGroups \| Where-Object \{ \$_\.Databases -contains \$db\.Id \}'
    }

    It 'retries Policy Insights POST requests' {
        $text = Get-FunctionText 'Analyze-PolicyCompliance'
        $text | Should Match 'Invoke-AzRestMethodWithRetry -Path \$complianceUrl -Method POST'
        $text | Should Not Match 'Invoke-AzRestMethod -Path \$complianceUrl'
    }

    It 'initializes Marketplace cost data when no deployments exist' {
        $ast.Extent.Text | Should Match '\$script:MarketplaceCostData\s*=\s*@\{\}\s*# Key = SubscriptionId'
    }

    It 'keeps partial JSON bounded by referencing subscription checkpoints' {
        $text = Get-FunctionText 'Write-PartialAssessmentReport'
        $text | Should Match "Format = 'Per-subscription checkpoints'"
        $text | Should Match 'Join-Path \$CheckpointPath ''subscriptions'''
        $text | Should Not Match 'Resources = \$script:Resources'
        $text | Should Not Match 'NetworkTopology = \$script:NetworkTopology'
    }

    It 'throttles expensive partial report regeneration but forces a final refresh' {
        $text = Get-FunctionText 'Write-PartialAssessmentReport'
        $text | Should Match '\[switch\]\$Force'
        $text | Should Match 'LastPartialReportAt.*TotalSeconds -lt \$ProgressIntervalSeconds'
        $ast.Extent.Text | Should Match 'Write-PartialAssessmentReport -Force'
    }

    It 'indexes checkpoint snapshots before building the manifest' {
        $text = Get-FunctionText 'Write-CheckpointManifest'
        $text | Should Match '\$snapshotBySubscriptionId\[\[string\]\$snapshot\.SubscriptionId\] = \$snapshot'
        $text | Should Match '\$snapshot = \$snapshotBySubscriptionId\[\[string\]\$sub\.Id\]'
        $text | Should Not Match '\$snapshots \| Where-Object'
    }

    It 'keeps tenant authentication and preflight out of subscription workers' {
        $text = Get-FunctionText 'Initialize-Assessment'
        $text | Should Match '(?s)if \(\$WorkerMode\).*Microsoft Graph authentication is coordinator-owned'
        $text | Should Match '(?s)if \(-not \$WorkerMode\).*Test-PreFlightPermissions'
        $text | Should Match 'Get-AzSubscription -SubscriptionId \$requestedSubscriptionIds\[0\]'
    }

    It 'terminates timed-out workers without blocking remaining subscriptions' {
        $text = Get-FunctionText 'Invoke-ParallelSubscriptionWorkers'
        $text | Should Match 'TotalMinutes -ge \$WorkerTimeoutMinutes'
        $text | Should Match 'Stop-Process -Id \$worker\.Process\.Id -Force'
        $text | Should Match 'Save-SubscriptionCheckpoint -Subscription \$worker\.Subscription -Status Failed'
        $text | Should Match 'Complete-ExecutionProgressUnit'
    }

    It 'uses stable UTC windows for cost and backup calculations' {
        (Get-FunctionText 'Get-SubscriptionCostAnalysis') | Should Match 'ToUniversalTime\(\)\.Date'
        $bcdrText = Get-FunctionText 'Analyze-BCDR'
        $bcdrText | Should Match '\$assessmentNow = \(Get-Date\)\.ToUniversalTime\(\)'
        $bcdrText | Should Not Match '\(Get-Date\)\.AddHours\(-48\)'
        (Get-FunctionText 'Analyze-Marketplace') | Should Match 'ToUniversalTime\(\)\.Date'
    }

    It 'keeps cached RBAC shape consistent and filters at Resource Graph' {
        $zeroTrustText = Get-FunctionText 'Analyze-ZeroTrust'
        $additionalText = Get-FunctionText 'Analyze-AdditionalChecks'
        $zeroTrustText | Should Match '\$_\.roleId'
        $zeroTrustText | Should Match '\$_\.principalType'
        $zeroTrustText | Should Not Match '\$_\.properties\.roleDefinitionId'
        $additionalText | Should Match '\$_\.principalType'
        $ast.Extent.Text | Should Match "principalType =~ 'User'.*roleId endswith"
        $ast.Extent.Text | Should Match '\$script:CachedRoleAssignmentsAvailable = \$true'
    }

    It 'reuses paged Resource Graph details for Cosmos and OSS databases' {
        $text = Get-FunctionText 'Analyze-CosmosOSSDatabase'
        $text | Should Match "Get-CachedResourceDetailsByType 'microsoft\.documentdb/databaseaccounts'"
        $text | Should Match "Get-CachedResourceDetailsByType 'microsoft\.dbforpostgresql/flexibleservers'"
        $text | Should Match "Get-CachedResourceDetailsByType 'microsoft\.dbformysql/flexibleservers'"
        $text | Should Match "Get-CachedResourceDetailsByType 'microsoft\.cache/redis'"
        $text | Should Not Match 'Get-AzResource -ResourceId'
    }

    It 'reuses Resource Graph for Azure AI inventory' {
        $text = Get-FunctionText 'Analyze-AIFoundry'
        $text | Should Match 'CachedResourceGraphResources'
        $text | Should Not Match 'Get-AzResource\s'
        $text | Should Match 'microsoft\.cognitiveservices/accounts'
    }

    It 'queries AI metrics only when explicitly enabled' {
        $text = Get-FunctionText 'Analyze-AIFoundry'
        $text | Should Match '\$IncludeAIMetrics -and -not \$SkipMetrics'
        $text | Should Match 'Get-AzMetricDefinition'
        $text | Should Match 'Get-AzMetric -ResourceId'
    }

    It 'summarizes aggregate GitHub Copilot usage without user-level data' {
        $report = [pscustomobject]@{ day_totals = @([pscustomobject]@{
            day = '2026-09-10'; daily_active_users = 4; weekly_active_users = 8; monthly_active_users = 10
            code_generation_activity_count = 20; code_acceptance_activity_count = 5
            loc_suggested_to_add_sum = 100; loc_added_sum = 40
            monthly_active_chat_users = 3; monthly_active_agent_users = 2; monthly_active_copilot_code_review_users = 1
        }) }

        $summary = ConvertFrom-GitHubCopilotReport -Report $report -Organization 'contoso'

        $summary.Organization | Should Be 'contoso'
        $summary.MonthlyActiveUsers | Should Be 10
        $summary.AcceptanceRate | Should Be 25
    }

    It 'renders a dedicated Azure AI and Copilot blade with Excel-compatible exports' {
        $text = Get-FunctionText 'Generate-HTMLReport'
        $text | Should Match 'id="blade-ai-copilot"'
        $text | Should Match "navTo\('blade-ai-copilot'"
        $text | Should Match 'id="aiInventoryTable"'
        $text | Should Match 'id="aiUsageTable"'
        $text | Should Match 'id="copilotAdoptionTable"'
        $text | Should Match 'id="aiCopilotFindingsTable"'
        $text | Should Match '<th>PTU Avg\.</th><th>PTU Peak</th><th>Availability</th>'
        $text | Should Match '<th>Resource</th><th>Resource Group</th><th>Kind</th>'
        ([regex]::Matches($text, "exportTableCSV\('(?:aiInventoryTable|aiUsageTable|copilotAdoptionTable|aiCopilotFindingsTable)'\)")).Count | Should Be 4
        $text | Should Match 'function filterTableRows'
    }

    It 'accepts GitHub Copilot NDJSON report downloads' {
        $report = '{"day_totals":[{"day":"2026-09-10","monthly_active_users":7,"code_generation_activity_count":10,"code_acceptance_activity_count":4}]}'

        $summary = ConvertFrom-GitHubCopilotReport -Report $report -Organization 'contoso'

        $summary.MonthlyActiveUsers | Should Be 7
        $summary.AcceptanceRate | Should Be 40
    }

    It 'retries transient external API failures' {
        $script:externalAttempts = 0

        $result = Invoke-ExternalRequestWithRetry -MaxAttempts 3 -BaseDelaySeconds 0 -Request {
            $script:externalAttempts++
            if ($script:externalAttempts -lt 3) { throw 'HTTP 429 Too Many Requests' }
            'available'
        }

        $result | Should Be 'available'
        $script:externalAttempts | Should Be 3
    }

    It 'routes optional integrations through bounded retry handling' {
        (Get-FunctionText 'Invoke-GitHubAdoptionAssessment') | Should Match 'Invoke-ExternalRequestWithRetry'
        (Get-FunctionText 'Invoke-M365CopilotAdoptionAssessment') | Should Match 'Invoke-ExternalRequestWithRetry'
    }
}

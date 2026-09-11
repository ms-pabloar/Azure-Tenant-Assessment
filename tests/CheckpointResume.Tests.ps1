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

@(
    'Write-AtomicJsonFile',
    'Get-SubscriptionCheckpointFile',
    'Update-ResultSummary',
    'Remove-SubscriptionResultState',
    'Set-SubscriptionResultIdentity',
    'New-SubscriptionResultSnapshot',
    'Save-SubscriptionCheckpoint',
    'Import-SubscriptionCheckpoint',
    'Get-CheckpointSnapshots',
    'Write-CheckpointManifest',
    'Save-TenantCheckpoint',
    'Import-TenantCheckpoint',
    'Get-SubscriptionExecutionPlan',
    'Initialize-CheckpointStore',
    'Split-SubscriptionBatches',
    'Get-WorkerArgumentList',
    'New-WorkerConfiguration'
    'Get-ExecutionProgressMessage'
) | ForEach-Object { . ([scriptblock]::Create((Get-FunctionText $_))) }

function Reset-CheckpointTestState {
    $script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:Resources = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:NetworkTopology = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:UnderutilizedResources = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:AIServiceInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:AIUsageData = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:StepResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:ErrorLog = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:CommitmentRecommendations = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:ReservationData = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:MarketplaceInventory = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:MarketplaceCostData = @{}
    $script:AdoptionData = [ordered]@{ GitHub = @(); GitHubCopilot = @(); Microsoft365Copilot = $null }
    $script:CostData = @{}
    $script:Summary = @{ TotalResources = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    $script:Subscriptions = [System.Collections.Generic.List[PSCustomObject]]::new()
}

Describe 'Subscription checkpoints' {
    It 'round-trips report state through a per-subscription JSON file' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'checkpoint'
        $subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($subscription)
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Production'; Severity = 'High'; Category = 'Test' })
        $script:Resources.Add([pscustomobject]@{ Subscription = 'Production'; Name = 'vm-1' })
        $script:StepResults.Add([pscustomobject]@{ Subscription = 'Production'; Step = 'DataCollection'; Status = 'OK' })
        $script:CostData['sub-1'] = [pscustomobject]@{ TotalCost = 42 }
        $script:AIServiceInventory.Add([pscustomobject]@{ SubscriptionId = 'sub-1'; Subscription = 'Production'; Name = 'ai-1'; Kind = 'OpenAI' })
        $script:AIUsageData.Add([pscustomobject]@{ SubscriptionId = 'sub-1'; Subscription = 'Production'; ResourceName = 'ai-1'; Requests = 100 })

        Save-SubscriptionCheckpoint -Subscription $subscription -Status Completed | Out-Null
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'checkpoint'
        $script:Subscriptions.Add($subscription)
        $snapshot = Import-SubscriptionCheckpoint -Path (Get-SubscriptionCheckpointFile 'sub-1')

        $snapshot.Status | Should Be 'Completed'
        $script:Findings.Count | Should Be 1
        $script:Resources.Count | Should Be 1
        $script:Summary.High | Should Be 1
        $script:Summary.TotalResources | Should Be 1
        $script:CostData['sub-1'].TotalCost | Should Be 42
        $script:AIServiceInventory.Count | Should Be 1
        $script:AIUsageData[0].Requests | Should Be 100
    }

    It 'replaces prior subscription state instead of duplicating it' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'replace'
        $subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($subscription)
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Production'; Severity = 'Low'; Category = 'Only once' })
        Save-SubscriptionCheckpoint -Subscription $subscription -Status Completed | Out-Null
        $path = Get-SubscriptionCheckpointFile 'sub-1'

        Import-SubscriptionCheckpoint -Path $path | Out-Null
        Import-SubscriptionCheckpoint -Path $path | Out-Null

        $script:Findings.Count | Should Be 1
    }

    It 'writes completed, failed, and pending states to the manifest' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'manifest'
        $completed = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $pending = [pscustomobject]@{ Id = 'sub-2'; Name = 'Development'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($completed)
        $script:Subscriptions.Add($pending)
        Save-SubscriptionCheckpoint -Subscription $completed -Status Completed | Out-Null

        $manifest = Write-CheckpointManifest

        ($manifest.Subscriptions | Where-Object Id -eq 'sub-1').Status | Should Be 'Completed'
        ($manifest.Subscriptions | Where-Object Id -eq 'sub-2').Status | Should Be 'Pending'
    }

    It 'splits subscriptions into bounded batches' {
        $subscriptions = @(1..5 | ForEach-Object { [pscustomobject]@{ Id = "sub-$_" } })
        $batches = @(Split-SubscriptionBatches -Subscriptions $subscriptions -Size 2)

        $batches.Count | Should Be 3
        @($batches[0]).Count | Should Be 2
        @($batches[2]).Count | Should Be 1
    }

    It 'accepts an empty execution plan when every subscription is complete' {
        @(Split-SubscriptionBatches -Subscriptions @() -Size 2).Count | Should Be 0
    }

    It 'resumes only incomplete subscriptions and restores completed state' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'resume'
        $completed = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $pending = [pscustomobject]@{ Id = 'sub-2'; Name = 'Development'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($completed)
        $script:Subscriptions.Add($pending)
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Production'; Severity = 'High'; Category = 'Restored' })
        Save-SubscriptionCheckpoint -Subscription $completed -Status Completed | Out-Null
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'resume'
        $script:Subscriptions.Add($completed)
        $script:Subscriptions.Add($pending)
        $script:Resume = $true
        $script:RetryFailedOnly = $false

        $plan = @(Get-SubscriptionExecutionPlan)

        $plan.Count | Should Be 1
        $plan[0].Id | Should Be 'sub-2'
        $script:Findings.Count | Should Be 1
    }

    It 'selects only failed subscriptions for retry' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'retry'
        $completed = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $failed = [pscustomobject]@{ Id = 'sub-2'; Name = 'Development'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($completed)
        $script:Subscriptions.Add($failed)
        Save-SubscriptionCheckpoint -Subscription $completed -Status Completed | Out-Null
        Save-SubscriptionCheckpoint -Subscription $failed -Status Failed -FailureReason 'network' | Out-Null
        $script:Resume = $false
        $script:RetryFailedOnly = $true

        $plan = @(Get-SubscriptionExecutionPlan)

        $plan.Count | Should Be 1
        $plan[0].Id | Should Be 'sub-2'
    }

    It 'passes the subscription and worker isolation flags to child processes' {
        $script:CheckpointPath = 'C:\assessment\checkpoint'
        $script:MetricDays = 7; $script:CommitmentLookbackDays = 30
        $script:CpuLowPercent = 10; $script:CpuIdlePercent = 5; $script:NetLowMB = 5
        $script:AppRequestLowPerHour = 10; $script:SqlDtuLowPercent = 10; $script:SqlCpuLowPercent = 10; $script:DiskLowIops = 5
        $script:MandatoryTags = @('Environment','Owner')
        $script:SkipMetrics = $true; $script:SkipKeyVaultDataPlane = $false; $script:SkipBackupDetails = $false
        $script:IncludeALZ = $false; $script:RequireValidSignature = $false
        $script:ProgressIntervalSeconds = 60
        $configuration = New-WorkerConfiguration -Subscription ([pscustomobject]@{ Id = 'sub-1' }) -WorkerOutputPath 'C:\worker output' -ContextPath 'C:\worker\context.json'
        $arguments = @(Get-WorkerArgumentList -ConfigPath 'C:\worker output\config.json' -ScriptPath 'C:\assessment\Azure Tenant Assessment.ps1')

        $configuration.SubscriptionId[0] | Should Be 'sub-1'
        $configuration.WorkerMode | Should Be $true
        $configuration.SkipLogin | Should Be $true
        $configuration.SkipMetrics | Should Be $true
        $configuration.WorkerContextPath | Should Be 'C:\worker\context.json'
        $configuration.ProgressIntervalSeconds | Should Be 60
        $configuration.TenantId | Should BeNullOrEmpty
        $configuration.SkipGraphLogin | Should Be $true
        ($configuration.PSObject.Properties.Name -contains 'GitHubOrganization') | Should Be $false
        ($configuration.PSObject.Properties.Name -contains 'IncludeM365Copilot') | Should Be $false
        ($arguments -join ' ') | Should Match '"C:\\assessment\\Azure Tenant Assessment\.ps1"'
        ($arguments -join ' ') | Should Match '"C:\\worker output\\config\.json"'
    }

    It 'uses persistent Cloud Shell storage for default output when available' {
        $text = Get-FunctionText 'Main'
        $text | Should Match 'Join-Path \$HOME ''clouddrive'''
        $text | Should Match '-not \$script:OutputPathExplicitlySpecified'
        $text | Should Match '\$script:OutputPath = Join-Path \$cloudDrivePath'
    }

    It 'calculates subscription progress and estimated completion' {
        $state = @{ Total = 4; Completed = 2; StartedAt = [datetime]'2026-09-09T10:00:00' }

        $message = Get-ExecutionProgressMessage -ProgressState $state -Now ([datetime]'2026-09-09T10:10:00')

        $message | Should Match '2/4 subscriptions \(50%\)'
        $message | Should Match 'remaining ~10m 00s'
        $message | Should Match 'estimated finish 10:20'
    }

    It 'waits for a completed subscription before estimating time remaining' {
        $state = @{ Total = 3; Completed = 0; StartedAt = [datetime]'2026-09-09T10:00:00' }

        $message = Get-ExecutionProgressMessage -ProgressState $state -Now ([datetime]'2026-09-09T10:02:00')

        $message | Should Match 'ETA calculating'
    }

    It 'round-trips tenant-wide findings and ALZ data' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'tenant'
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Tenant-wide'; Severity = 'High'; Category = 'ALZ' })
        $script:StepResults.Add([pscustomobject]@{ Subscription = 'Tenant-wide'; Step = 'ALZReadiness'; Status = 'OK' })
        $script:ReservationData.Add([pscustomobject]@{ Subscription = 'Tenant-wide'; SubscriptionId = 'Tenant-wide'; Type = 'Reservation'; UtilizationPct = 75 })
        $script:ALZData = @{ Checks = @([pscustomobject]@{ Name = 'Policy'; Status = 'Pass' }) }
        $script:AdoptionData.GitHubCopilot = @([pscustomobject]@{ Organization = 'contoso'; MonthlyActiveUsers = 10 })
        Save-TenantCheckpoint
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'tenant'

        Import-TenantCheckpoint | Should Be $true
        $script:Findings.Count | Should Be 1
        $script:StepResults.Count | Should Be 1
        $script:ReservationData.Count | Should Be 1
        $script:ReservationInventoryLoaded | Should Be $true
        @($script:ALZData.Checks).Count | Should Be 1
        $script:AdoptionData.GitHubCopilot[0].MonthlyActiveUsers | Should Be 10
    }

    It 'keeps results isolated when subscription names are identical' {
        Reset-CheckpointTestState
        $script:CheckpointPath = Join-Path $TestDrive 'duplicate-names'
        $first = [pscustomobject]@{ Id = 'sub-1'; Name = 'Production'; TenantId = 'tenant-1' }
        $second = [pscustomobject]@{ Id = 'sub-2'; Name = 'Production'; TenantId = 'tenant-1' }
        $script:Subscriptions.Add($first)
        $script:Subscriptions.Add($second)
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Production'; SubscriptionId = 'sub-1'; Severity = 'High'; Category = 'First' })
        $script:Findings.Add([pscustomobject]@{ Subscription = 'Production'; SubscriptionId = 'sub-2'; Severity = 'Low'; Category = 'Second' })
        Save-SubscriptionCheckpoint -Subscription $first -Status Completed | Out-Null
        Save-SubscriptionCheckpoint -Subscription $second -Status Completed | Out-Null

        Import-SubscriptionCheckpoint -Path (Get-SubscriptionCheckpointFile 'sub-1') | Out-Null

        $script:Findings.Count | Should Be 2
        @($script:Findings | Where-Object SubscriptionId -eq 'sub-1').Count | Should Be 1
        @($script:Findings | Where-Object SubscriptionId -eq 'sub-2').Count | Should Be 1
    }
}

$scriptPath = Join-Path $PSScriptRoot '..\Azure-Tenant-Assessment.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors.Message -join [Environment]::NewLine) }

$functionNames = @(
    'ConvertTo-AmountValue',
    'Get-LookbackDaysValue',
    'Get-PercentileValue',
    'ConvertFrom-AzureReservationRecommendation',
    'ConvertFrom-AzureSavingsPlanRecommendation',
    'ConvertFrom-ReservationUtilizationSummary',
    'Resolve-CommitmentRecommendationDecision'
)
foreach ($functionName in $functionNames) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

function Reset-CommitmentTestState {
    $script:UnderutilizedResources = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:CommitmentRecommendations = [System.Collections.Generic.List[PSCustomObject]]::new()
}

Describe 'Reservation recommendations' {
    It 'normalizes a profitable legacy 30-day recommendation' {
        Reset-CommitmentTestState
        $inputObject = [pscustomobject]@{
            id = '/recommendations/ri-1'
            location = 'eastus'
            sku = 'Standard_D4s_v5'
            properties = [pscustomobject]@{
                lookBackPeriod = 'Last30Days'; costWithNoReservedInstances = 1000
                totalCostWithReservedInstances = 700; netSavings = 300
                recommendedQuantity = 2; recommendedQuantityNormalized = 2
                totalHours = 1400; term = 'P1Y'; scope = 'Single'
                instanceFlexibilityGroup = 'Dsv5 Series'
            }
        }

        $result = ConvertFrom-AzureReservationRecommendation $inputObject 'sub-1' 'Sub A'

        $result.SavingsPercentage | Should Be 30
        $result.AnnualSavings | Should Be 3650
        $result.UtilizationPercentage | Should BeGreaterThan 79
        $result.DecisionStatus | Should Be 'Candidate'
    }

    It 'parses modern amount objects and flags underutilized matching SKUs' {
        Reset-CommitmentTestState
        $script:UnderutilizedResources.Add([pscustomobject]@{
            Subscription = 'Sub A'; ResourceType = 'Virtual Machine'; SKU = 'Standard_D4s_v5'
        })
        $inputObject = [pscustomobject]@{
            id = '/recommendations/ri-2'; location = 'eastus'; sku = 'Standard_D4s_v5'
            properties = [pscustomobject]@{
                lookBackPeriod = 60
                costWithNoReservedInstances = [pscustomobject]@{ value = 2000; currency = 'USD' }
                totalCostWithReservedInstances = [pscustomobject]@{ value = 1300; currency = 'USD' }
                netSavings = [pscustomobject]@{ value = 700; currency = 'USD' }
                recommendedQuantity = 1; totalHours = 1400; term = 'P3Y'; scope = 'Single'
            }
        }

        $result = ConvertFrom-AzureReservationRecommendation $inputObject 'sub-1' 'Sub A'

        $result.PaygCost | Should Be 2000
        $result.SavingsCurrency | Should Be 'USD'
        $result.DecisionStatus | Should Be 'Review first'
    }

    It 'caps impossible savings percentages and requires source-cost review' {
        Reset-CommitmentTestState
        $inputObject = [pscustomobject]@{
            id = '/recommendations/ri-invalid'; location = 'eastus'; sku = 'Standard_D4s_v5'
            properties = [pscustomobject]@{
                lookBackPeriod = 'Last30Days'; costWithNoReservedInstances = 100
                totalCostWithReservedInstances = 50; netSavings = 150
                recommendedQuantity = 1; totalHours = 720; term = 'P1Y'; scope = 'Single'
            }
        }

        $result = ConvertFrom-AzureReservationRecommendation $inputObject 'sub-1' 'Sub A'

        $result.SavingsPercentage | Should Be 100
        $result.IsSavingsEstimateValid | Should Be $false
        $result.DecisionStatus | Should Be 'Review first'
        $result.DecisionReason | Should Match 'inconsistent savings estimate'
    }
}

Describe 'Savings Plan recommendations' {
    It 'uses hourly usage and accepts a high-utilization recommendation' {
        Reset-CommitmentTestState
        $inputObject = [pscustomobject]@{
            id = '/recommendations/sp-1'; kind = 'SavingsPlan'
            properties = [pscustomobject]@{
                lookBackPeriod = 'Last30Days'; term = 'P1Y'; scope = 'Single'
                armSkuName = 'Compute_Savings_Plan'; currencyCode = 'USD'
                totalHours = 720; costWithoutBenefit = 2000
                usage = [pscustomobject]@{ usageGrain = 'Hourly'; charges = @(1..720 | ForEach-Object { 3.0 }) }
                recommendationDetails = [pscustomobject]@{
                    commitmentAmount = 1.2; totalCost = 1800; savingsAmount = 200
                    savingsPercentage = 10; averageUtilizationPercentage = 95
                    coveragePercentage = 70; benefitCost = 864; wastageCost = 0
                }
            }
        }

        $result = ConvertFrom-AzureSavingsPlanRecommendation $inputObject 'sub-1' 'Sub A'

        $result.UsageGrain | Should Be 'Hourly'
        $result.AverageHourlyCharge | Should Be 3
        $result.P95HourlyCharge | Should Be 3
        $result.AnnualSavings | Should Be 2433.33
        $result.DecisionStatus | Should Be 'Candidate'
    }

    It 'rejects projected utilization below 90 percent' {
        Reset-CommitmentTestState
        $inputObject = [pscustomobject]@{
            id = '/recommendations/sp-2'; kind = 'SavingsPlan'
            properties = [pscustomobject]@{
                lookBackPeriod = 'Last30Days'; term = 'P1Y'; scope = 'Single'
                totalHours = 720; costWithoutBenefit = 2000; currencyCode = 'USD'
                usage = [pscustomobject]@{ usageGrain = 'Hourly'; charges = @(1, 2) }
                recommendationDetails = [pscustomobject]@{
                    commitmentAmount = 1; totalCost = 1800; savingsAmount = 200
                    savingsPercentage = 10; averageUtilizationPercentage = 80
                    coveragePercentage = 70; benefitCost = 720; wastageCost = 0
                }
            }
        }

        (ConvertFrom-AzureSavingsPlanRecommendation $inputObject 'sub-1' 'Sub A').DecisionStatus | Should Be 'Review first'
    }
}

Describe 'Existing reservation utilization' {
    It 'calculates weighted utilization and unused reserved hours' {
        $dailySummaries = @(
            [pscustomobject]@{ properties = [pscustomobject]@{ usageDate = '2026-09-01'; reservedHours = 24; usedHours = 18; avgUtilizationPercentage = 75 } }
            [pscustomobject]@{ properties = [pscustomobject]@{ usageDate = '2026-09-02'; reservedHours = 48; usedHours = 24; avgUtilizationPercentage = 50 } }
        )

        $result = ConvertFrom-ReservationUtilizationSummary -InputObject $dailySummaries -WindowDays 30

        $result.ReservedHours | Should Be 72
        $result.UsedHours | Should Be 42
        $result.UnusedHours | Should Be 30
        $result.UtilizationPct | Should Be 58.3
        $result.UnusedCommitmentPercentage | Should Be 41.7
        $result.MeasuredDays | Should Be 2
    }

    It 'uses reported utilization when hour totals are unavailable' {
        $summaries = @(
            [pscustomobject]@{ properties = [pscustomobject]@{ avgUtilizationPercentage = 80 } }
            [pscustomobject]@{ properties = [pscustomobject]@{ utilizedPercentage = 60 } }
        )

        $result = ConvertFrom-ReservationUtilizationSummary -InputObject $summaries

        $result.UtilizationPct | Should Be 70
        $result.UnusedCommitmentPercentage | Should Be 30
        $result.ReservedHours | Should BeNullOrEmpty
    }
}

Describe 'Commitment option selection' {
    It 'selects one preferred option and marks overlapping candidates as alternatives' {
        Reset-CommitmentTestState
        $script:CommitmentRecommendations.Add([pscustomobject]@{
            SubscriptionId = 'sub-1'; Source = 'Azure Reservation Recommendations API'
            DecisionStatus = 'Candidate'; AnnualSavings = 1500; Type = 'Reservation'
        })
        $script:CommitmentRecommendations.Add([pscustomobject]@{
            SubscriptionId = 'sub-1'; Source = 'Azure Benefit Recommendations API'
            DecisionStatus = 'Candidate'; AnnualSavings = 2000; Type = 'SavingsPlan'
        })

        Resolve-CommitmentRecommendationDecision 'sub-1'

        ($script:CommitmentRecommendations | Where-Object DecisionStatus -eq 'Preferred').Type | Should Be 'SavingsPlan'
        ($script:CommitmentRecommendations | Where-Object DecisionStatus -eq 'Alternative').Count | Should Be 1
    }
}

Describe 'Native recommendation configuration' {
    It 'supports only 30-day and 60-day commitment lookbacks' {
        $parameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'CommitmentLookbackDays' }
        $parameter | Should Not BeNullOrEmpty
        $parameter.DefaultValue.SafeGetValue() | Should Be 30
        $validateSet = $parameter.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
        @($validateSet.PositionalArguments | ForEach-Object { $_.SafeGetValue() }) -join ',' | Should Be '30,60'
    }

    It 'queries official Reservation and Savings Plan recommendation APIs for both terms' {
        $definition = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-NativeCommitmentRecommendations'
        }, $true) | Select-Object -First 1
        $text = $definition.Extent.Text

        $text | Should Match 'Microsoft\.Consumption/reservationRecommendations'
        $text | Should Match 'Microsoft\.CostManagement/benefitRecommendations'
        $text | Should Match "@\('P1Y', 'P3Y'\)"
        $text | Should Match 'properties/usage,properties/allRecommendationDetails'
    }

    It 'collects reservation usage hours with a bounded fallback' {
        $definition = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Analyze-Reservations'
        }, $true) | Select-Object -First 1
        $text = $definition.Extent.Text

        $text | Should Match 'Microsoft\.Consumption/reservationSummaries'
        $text | Should Match 'grain=daily'
        $text | Should Match 'properties/UsageDate ge'
        $text | Should Match 'ConvertFrom-ReservationUtilizationSummary'
        $text | Should Match '\$expand=utilization'
        $text | Should Match 'UnusedCommitmentPercentage'
        $text | Should Match 'Get-AzRestPagedValues -Path "/providers/Microsoft\.Capacity/reservationOrders'
        $text | Should Match 'Get-AzRestPagedValues -Path "/providers/Microsoft\.BillingBenefits/savingsPlanOrders'
        $text | Should Match 'Invoke-AzRestMethodWithRetry -Path "\$\(\$ri\.id\)'
    }
}

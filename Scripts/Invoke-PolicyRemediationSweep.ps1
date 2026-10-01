<#
.SYNOPSIS
  Discovers all DINE/Modify policy assignments under a management group hierarchy and
  triggers remediation, filling in missing role assignments first for the root MG only
  (child MGs are already confirmed to get correct role assignments via Terraform/alzlib).

.PARAMETER RootManagementGroupId
  The top-level MG to sweep (e.g. "MG-AzLz-Acclrtr"). Children are discovered recursively -
  new child MGs are picked up automatically, no code change needed.

.PARAMETER TargetScope
  'All' (default) - process the root MG and all descendants.
  'RootOnly' - process only $RootManagementGroupId itself, skip all children.
  'ChildrenOnly' - process only descendant MGs, skip the root itself (also skips the
  role-assignment gap-fill check, since that only ever applies to the root).

.NOTES
  Requires Az.Accounts, Az.Resources, Az.PolicyInsights. Run authenticated as an identity
  with Owner (or at least roleAssignments/write + policy remediation rights) at $RootManagementGroupId.

  When run inside a GitHub Actions workflow (detected via $env:GITHUB_ACTIONS), output uses
  workflow log commands (::group::/::endgroup::, ::warning::, ::error::, ::notice::) so the
  run gets collapsible per-MG sections and surfaces in the Annotations panel. Falls back to
  plain text automatically when run locally.

  Additional log readability (GitHub Actions only): the "needs action" vs "no action" recap
  lists are ANSI colour-coded (yellow vs green) so they're easy to tell apart at a glance in a
  long log, role definition GUIDs are resolved to friendly names (e.g. "Resource Policy
  Contributor") wherever they're printed, and a short markdown table is written to the run's
  Summary tab ($env:GITHUB_STEP_SUMMARY) so the headline result doesn't require scrolling logs.

  Property names below are confirmed against Az.Resources 10.2.0's actual (flattened) output -
  Get-AzPolicyAssignment returns .Scope, .PolicyDefinitionId, .IdentityType, .IdentityPrincipalId, .Id
  directly on the object, NOT nested under .Properties/.Identity as raw ARM JSON would suggest.
  Get-AzPolicyDefinition/-PolicySetDefinition property paths (.PolicyRule, .PolicyDefinition, .Parameter)
  are ASSUMED to follow the same flattening convention in this module version - not yet independently
  verified. If Get-RequiredRoleAssignments returns nothing when it should find rdids, check those paths
  first with `Get-AzPolicyDefinition -Id <id> | Format-List *`.
#>
param(
    [Parameter(Mandatory)]
    [string]$RootManagementGroupId,

    [ValidateSet('All', 'RootOnly', 'ChildrenOnly')]
    [string]$TargetScope = 'All',

    [switch]$WhatIf
)

# --- GitHub Actions-aware logging helpers ---
$script:InGitHubActions = $env:GITHUB_ACTIONS -eq 'true'
# Tracks whether any operation failed, so the script can exit non-zero even though each
# failure is caught individually to let the rest of the sweep continue.
$script:HadFailures = $false

function Write-LogGroupStart {
    param([string]$Title)
    if ($script:InGitHubActions) { Write-Host "::group::$Title" } else { Write-Host "=== $Title ===" }
}

function Write-LogGroupEnd {
    if ($script:InGitHubActions) { Write-Host "::endgroup::" }
}

function Write-Notice {
    param([string]$Message)
    if ($script:InGitHubActions) { Write-Host "::notice::$Message" } else { Write-Host "  $Message" }
}

function Write-Warn {
    param([string]$Message)
    if ($script:InGitHubActions) { Write-Host "::warning::$Message" } else { Write-Host "  $Message" }
}

function Write-Err {
    param([string]$Message)
    if ($script:InGitHubActions) { Write-Host "::error::$Message" } else { Write-Host "  $Message" }
}

function Write-ColorLine {
    <#
      Plain ANSI-coloured Write-Host for display-only emphasis (deliberately NOT a GitHub workflow
      command, so it doesn't add extra entries to the Annotations panel the way ::warning::/::error::
      do - those are reserved for genuine problems raised inline during processing). GitHub Actions'
      log viewer renders ANSI colour natively; falls back to plain text outside Actions.
    #>
    param(
        [string]$Message,
        [ValidateSet('Green', 'Yellow', 'Red', 'Cyan', 'Bold')]
        [string]$Color = 'Cyan'
    )
    if (-not $script:InGitHubActions) { Write-Host $Message; return }

    $codes = @{ Green = '32'; Yellow = '33'; Red = '31'; Cyan = '36'; Bold = '1' }
    Write-Host "$([char]27)[$($codes[$Color])m$Message$([char]27)[0m"
}

$script:RoleNameCache = @{}

function Get-RoleDisplayName {
    <#
      Resolves a role definition GUID (or full resource ID) to "Friendly Name (guid)", e.g.
      "Resource Policy Contributor (36243c78-bf99-498c-9df9-86d9f8d28608)" - falls back to the
      bare GUID if the lookup fails (transient API error, custom role deleted, etc.) so the guid
      is still there to cross-reference in the Portal even when the name can't be resolved.
      Cached per-run since the same handful of roleDefinitionIds repeat across every assignment.
    #>
    param([string]$RoleDefinitionId)

    $guid = ($RoleDefinitionId -split '/')[-1]
    if ($script:RoleNameCache.ContainsKey($guid)) { return $script:RoleNameCache[$guid] }

    $display = $guid
    try {
        $def = Get-AzRoleDefinition -Id $guid -ErrorAction Stop
        if ($def -and $def.Name) { $display = "$($def.Name) ($guid)" }
    } catch {
        # Leave $display as the bare GUID - still usable, just not resolved to a friendly name.
    }

    $script:RoleNameCache[$guid] = $display
    $display
}

function Get-RequiredRoleAssignments {
    <#
      Mirrors alzlib's own logic (deployment/managementgroup.go):
      - For a plain policy definition: role assignment at the assignment's own scope, for each roleDefinitionId.
      - For a policy set (initiative): same, per member policy, PLUS an extra role assignment at whatever
        resource ID any assignPermissions=true parameter resolves to (e.g. a Log Analytics workspace ID).
    #>
    param($Assignment)

    $required = New-Object System.Collections.Generic.List[object]
    $defId = $Assignment.PolicyDefinitionId

    if ($defId -match '/policySetDefinitions/') {
        $setDef = Get-AzPolicySetDefinition -Id $defId
        foreach ($member in $setDef.PolicyDefinition) {
            $memberDef = Get-AzPolicyDefinition -Id $member.policyDefinitionId -ErrorAction SilentlyContinue
            if (-not $memberDef) { continue }
            $rdids = $memberDef.PolicyRule.then.details.roleDefinitionIds
            if (-not $rdids) { continue }

            foreach ($rdid in $rdids) {
                $required.Add([pscustomobject]@{ Scope = $Assignment.Scope; RoleDefinitionId = $rdid })
            }

            # assignPermissions parameters - resolve to the assignment's own parameter value (simple passthrough case)
            foreach ($paramName in $memberDef.Parameter.PSObject.Properties.Name) {
                $paramMeta = $memberDef.Parameter.$paramName.metadata
                if ($paramMeta -and $paramMeta.assignPermissions -eq $true) {
                    $val = $Assignment.Parameter.$paramName.Value
                    if ($val -and $val -match '^/subscriptions/') {
                        foreach ($rdid in $rdids) {
                            $required.Add([pscustomobject]@{ Scope = $val; RoleDefinitionId = $rdid })
                        }
                    }
                }
            }
        }
    } else {
        $def = Get-AzPolicyDefinition -Id $defId -ErrorAction SilentlyContinue
        $rdids = $def.PolicyRule.then.details.roleDefinitionIds
        foreach ($rdid in $rdids) {
            $required.Add([pscustomobject]@{ Scope = $Assignment.Scope; RoleDefinitionId = $rdid })
        }

        # assignPermissions parameters - same mechanism as the policy-set branch above, alzlib applies
        # this to plain policy definitions too (e.g. a `logAnalytics` parameter needing Log Analytics
        # Contributor at the workspace's own resource scope, not just the assignment's MG scope).
        foreach ($paramName in $def.Parameter.PSObject.Properties.Name) {
            $paramMeta = $def.Parameter.$paramName.metadata
            if ($paramMeta -and $paramMeta.assignPermissions -eq $true) {
                $val = $Assignment.Parameter.$paramName.Value
                if ($val -and $val -match '^/subscriptions/') {
                    foreach ($rdid in $rdids) {
                        $required.Add([pscustomobject]@{ Scope = $val; RoleDefinitionId = $rdid })
                    }
                }
            }
        }
    }

    $required | Sort-Object Scope, RoleDefinitionId -Unique
}

function Ensure-RoleAssignments {
    param($Assignment)

    $principalId = $Assignment.IdentityPrincipalId
    if (-not $principalId) { return $false }

    $label = "Policy Assignment '$($Assignment.DisplayName)' ['$($Assignment.Name)']"
    $foundMissing = $false

    foreach ($req in (Get-RequiredRoleAssignments -Assignment $Assignment)) {
        # Compare just the role definition GUID, not the full string - the policy definition's stored
        # roleDefinitionIds and Get-AzRoleAssignment's returned RoleDefinitionId can differ in casing
        # and/or subscription-prefix, causing a real existing assignment to be missed by exact -eq.
        $reqGuid = ($req.RoleDefinitionId -split '/')[-1]
        $existing = Get-AzRoleAssignment -ObjectId $principalId -Scope $req.Scope -ErrorAction SilentlyContinue |
            Where-Object { ($_.RoleDefinitionId -split '/')[-1] -ieq $reqGuid }

        if (-not $existing) {
            $foundMissing = $true
            $roleName = Get-RoleDisplayName -RoleDefinitionId $req.RoleDefinitionId
            Write-Warn "$label is missing a role assignment its managed identity needs before remediation can work: role $roleName at scope $($req.Scope)"
            if ($WhatIf) {
                Write-Notice "$label -> would assign $roleName (WhatIf - no change made)"
            } else {
                Write-Notice "$label -> assigning $roleName at $($req.Scope)..."
                try {
                    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $reqGuid -Scope $req.Scope -ErrorAction Stop | Out-Null
                    Write-ColorLine -Color Green "$label -> assigned $roleName at $($req.Scope)"
                } catch {
                    Write-Err "$label -> FAILED to assign $roleName at $($req.Scope) - $($_.Exception.Message)"
                    $script:HadFailures = $true
                }
            }
        }
    }

    $foundMissing
}

function Invoke-Remediation {
    param($Assignment, [string]$ManagementGroupId)

    $isSet = $Assignment.PolicyDefinitionId -match '/policySetDefinitions/'
    $label = "Policy Assignment '$($Assignment.DisplayName)' ['$($Assignment.Name)']"

    if (-not $isSet) {
        $nonCompliant = Get-AzPolicyState -ManagementGroupName $ManagementGroupId `
            -Filter "PolicyAssignmentId eq '$($Assignment.Id)' and ComplianceState eq 'NonCompliant'"
        if ($nonCompliant) {
            if ($WhatIf) {
                Write-Notice "$label has non-compliant resources at $ManagementGroupId -> would start a remediation task (WhatIf - no change made)"
            } else {
                Write-Notice "$label has non-compliant resources at $ManagementGroupId - starting a remediation task to deploy/modify them into compliance"
                try {
                    Start-AzPolicyRemediation -Name "sweep-$($Assignment.Name)-$(Get-Date -Format yyyyMMddHHmm)" `
                        -PolicyAssignmentId $Assignment.Id -ManagementGroupId $ManagementGroupId -ErrorAction Stop | Out-Null
                } catch {
                    Write-Err "$label -> FAILED to start remediation at $ManagementGroupId - $($_.Exception.Message)"
                    $script:HadFailures = $true
                }
            }
            return $true
        }
        return $false
    }

    # Initiative: only remediate member policy references that actually have non-compliant resources
    $nonCompliantRefs = Get-AzPolicyState -ManagementGroupName $ManagementGroupId `
        -Filter "PolicyAssignmentId eq '$($Assignment.Id)' and ComplianceState eq 'NonCompliant'" |
        Group-Object PolicyDefinitionReferenceId

    foreach ($refGroup in $nonCompliantRefs) {
        if ($WhatIf) {
            Write-Notice "$label member policy '$($refGroup.Name)' has non-compliant resources at $ManagementGroupId -> would start a remediation task (WhatIf - no change made)"
        } else {
            Write-Notice "$label member policy '$($refGroup.Name)' has non-compliant resources at $ManagementGroupId - starting a remediation task to deploy/modify them into compliance"
            try {
                Start-AzPolicyRemediation -Name "sweep-$($Assignment.Name)-$($refGroup.Name)-$(Get-Date -Format yyyyMMddHHmm)" `
                    -PolicyAssignmentId $Assignment.Id -ManagementGroupId $ManagementGroupId `
                    -PolicyDefinitionReferenceId $refGroup.Name -ErrorAction Stop | Out-Null
            } catch {
                Write-Err "$label member policy '$($refGroup.Name)' -> FAILED to start remediation at $ManagementGroupId - $($_.Exception.Message)"
                $script:HadFailures = $true
            }
        }
    }

    $nonCompliantRefs.Count -gt 0
}

# --- Main ---

# Collects one row per MG so the end-of-run grand total / Job Summary doesn't need a second pass.
$script:AllMgResults = New-Object System.Collections.Generic.List[object]

# Recursively discover every MG under root - new child MGs are picked up automatically.
$allMgIds = @($RootManagementGroupId)
$allMgIds += (Get-AzManagementGroup -GroupId $RootManagementGroupId -Expand -Recurse).Children |
    ForEach-Object { $_.Name }

# Apply -TargetScope filter.
switch ($TargetScope) {
    'RootOnly'     { $allMgIds = @($RootManagementGroupId) }
    'ChildrenOnly' { $allMgIds = $allMgIds | Where-Object { $_ -ne $RootManagementGroupId } }
}

foreach ($mgId in $allMgIds) {
    Write-LogGroupStart "Management Group: $mgId"
    $scope = "/providers/Microsoft.Management/managementGroups/$mgId"
    # Get-AzPolicyAssignment -Scope returns everything VISIBLE at that scope, including assignments
    # inherited from ancestors (e.g. Tenant Root Group). Filter to ones actually OWNED at this exact
    # scope, otherwise ancestor assignments get reprocessed once per descendant MG.
    $assignments = Get-AzPolicyAssignment -Scope $scope | Where-Object {
        $_.Scope -eq $scope -and $_.IdentityType -and $_.IdentityType -ne 'None'
    }
    Write-Notice "Found $($assignments.Count) policy assignment(s) with a managed identity at this scope"

    $needsAction = New-Object System.Collections.Generic.List[string]
    $noActionNeeded = New-Object System.Collections.Generic.List[string]

    foreach ($assignment in $assignments) {
        $label = "Policy Assignment '$($assignment.DisplayName)' ['$($assignment.Name)']"
        $foundIssue = $false

        # Only the root MG has the confirmed role-assignment gap - children already work via Terraform/alzlib.
        if ($mgId -eq $RootManagementGroupId) {
            if (Ensure-RoleAssignments -Assignment $assignment) { $foundIssue = $true }
        }

        if (Invoke-Remediation -Assignment $assignment -ManagementGroupId $mgId) { $foundIssue = $true }

        if ($foundIssue) {
            $needsAction.Add($label)
        } else {
            Write-ColorLine -Color Green "$label - all required role assignments present, no non-compliant resources found; nothing to do"
            $noActionNeeded.Add($label)
        }
    }

    Write-ColorLine -Color Bold "Summary for '$mgId': $($assignments.Count) total, $($needsAction.Count) need action, $($noActionNeeded.Count) need no action"

    if ($needsAction.Count -gt 0) {
        Write-ColorLine -Color Yellow "-- [ACTION] Assignments needing action ($($needsAction.Count)) --"
        foreach ($item in $needsAction) { Write-ColorLine -Color Yellow "  * $item" }
    }
    if ($noActionNeeded.Count -gt 0) {
        Write-ColorLine -Color Green "-- [OK] Assignments needing no action ($($noActionNeeded.Count)) --"
        foreach ($item in $noActionNeeded) { Write-ColorLine -Color Green "  * $item" }
    }

    $script:AllMgResults.Add([pscustomobject]@{
        ManagementGroupId = $mgId
        Total             = $assignments.Count
        NeedsAction       = $needsAction.Count
        NoActionNeeded    = $noActionNeeded.Count
        NeedsActionItems  = $needsAction
    })

    Write-LogGroupEnd
}

# --- Overall run summary across every MG processed - one place to look even when the
# group-by-group logs above are long, since the loop above only prints a per-MG recap. ---
$grandTotal       = ($script:AllMgResults | Measure-Object -Property Total -Sum).Sum
$grandNeedsAction = ($script:AllMgResults | Measure-Object -Property NeedsAction -Sum).Sum
$grandNoAction    = ($script:AllMgResults | Measure-Object -Property NoActionNeeded -Sum).Sum

Write-Host ""
Write-ColorLine -Color Bold "===== Overall sweep summary: $grandTotal assignment(s) across $($script:AllMgResults.Count) management group(s) - $grandNeedsAction needed action, $grandNoAction needed none ====="
foreach ($mgResult in $script:AllMgResults) {
    $flag = if ($mgResult.NeedsAction -gt 0) { 'Yellow' } else { 'Green' }
    Write-ColorLine -Color $flag "  $($mgResult.ManagementGroupId): $($mgResult.Total) total, $($mgResult.NeedsAction) action, $($mgResult.NoActionNeeded) none"
}

# GitHub Actions Job Summary (the run page's "Summary" tab) - a short markdown table that's easy
# to scan without scrolling the raw logs. No-ops automatically outside GitHub Actions.
if ($script:InGitHubActions -and $env:GITHUB_STEP_SUMMARY) {
    $summaryLines = New-Object System.Collections.Generic.List[string]
    $summaryLines.Add('## Policy remediation sweep summary')
    $summaryLines.Add('')
    $summaryLines.Add('| Management Group | Total | :warning: Needs action | :white_check_mark: No action needed |')
    $summaryLines.Add('|---|---|---|---|')
    foreach ($mgResult in $script:AllMgResults) {
        $summaryLines.Add("| $($mgResult.ManagementGroupId) | $($mgResult.Total) | $($mgResult.NeedsAction) | $($mgResult.NoActionNeeded) |")
    }
    $summaryLines.Add("| **Total** | **$grandTotal** | **$grandNeedsAction** | **$grandNoAction** |")

    if ($grandNeedsAction -gt 0) {
        $summaryLines.Add('')
        $summaryLines.Add('### Assignments that needed action')
        foreach ($mgResult in $script:AllMgResults) {
            foreach ($item in $mgResult.NeedsActionItems) {
                $summaryLines.Add("- **$($mgResult.ManagementGroupId)**: $item")
            }
        }
    }

    $summaryLines -join "`n" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}

# Fail the run explicitly if anything failed, even though each failure was caught individually
# so the rest of the sweep could still complete - otherwise the process exits 0 and GitHub
# Actions shows a green run despite a real error having occurred.
if ($script:HadFailures) {
    Write-Err "One or more operations failed during the sweep - see warnings/errors above."
    exit 1
}

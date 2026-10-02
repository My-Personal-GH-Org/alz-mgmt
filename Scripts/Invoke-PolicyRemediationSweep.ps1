<#
.SYNOPSIS
  Discovers all DINE/Modify policy assignments under a management group hierarchy and
  triggers remediation, filling in missing role assignments first for the root MG only
  (child MGs are already confirmed to get correct role assignments via Terraform/alzlib).
  Remediation is SKIPPED by default for any assignment in DoNotEnforce mode - a deliberate
  safety default for this unattended sweep, not an Azure limitation - opt in with
  -FixDoNotEnforcePolicies. Role-assignment gap-fill always applies regardless of enforcement
  mode or this switch, since that's inert RBAC prep, not a resource change.

.PARAMETER RootManagementGroupId
  The top-level MG to sweep (e.g. "MG-AzLz-Acclrtr"). Children are discovered recursively -
  new child MGs are picked up automatically, no code change needed.

.PARAMETER TargetScope
  'All' (default) - process the root MG and all descendants.
  'RootOnly' - process only $RootManagementGroupId itself, skip all children.
  'ChildrenOnly' - process only descendant MGs, skip the root itself (also skips the
  role-assignment gap-fill check, since that only ever applies to the root).

.PARAMETER FixDoNotEnforcePolicies
  Opt-in switch. By default, assignments in DoNotEnforce mode are left alone (remediation is
  skipped for them, role-assignment gap-fill still happens). Pass this switch to also remediate
  non-compliant resources under DoNotEnforce assignments - use once you're ready for those
  policies' real-world effects, not as a standing default.

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

    [switch]$FixDoNotEnforcePolicies,

    [switch]$WhatIf
)

# --- GitHub Actions-aware logging helpers ---
$script:InGitHubActions = $env:GITHUB_ACTIONS -eq 'true'
# Tracks whether any operation failed, so the script can exit non-zero even though each
# failure is caught individually to let the rest of the sweep continue.
$script:HadFailures = $false
# Flat, run-wide list of every concrete fix applied (role assignment created / remediation task
# started) - this is what answers "what did this run actually fix", surfaced as its own section
# in both the console summary and the GitHub Job Summary instead of being buried in per-MG detail.
$script:FixesThisRun = New-Object System.Collections.Generic.List[string]
# Same idea but for -WhatIf runs - nothing is actually applied, so these must never be reported as
# "fixed"; kept separate so the end-of-run summary can say "would fix" / "this was a dry run"
# instead of the misleading "nothing needed fixing" when there actually were findings.
$script:WouldFixThisRun = New-Object System.Collections.Generic.List[string]

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

$script:PrincipalNameCache = @{}

function Get-PrincipalDisplayName {
    <#
      Resolves a managed identity's object/principal ID to "Friendly Name (guid)" via its AAD
      service principal (managed identities register as service principals), e.g.
      "id-policysweep-sub (e5365c0d-e346-4396-bdcb-50984e9cb3c4)" - falls back to the bare GUID if
      the lookup fails. Cached per-run since the sweep UMI's own identity repeats across every
      assignment it fixes.
    #>
    param([string]$PrincipalId)

    if ($script:PrincipalNameCache.ContainsKey($PrincipalId)) { return $script:PrincipalNameCache[$PrincipalId] }

    $display = $PrincipalId
    try {
        $sp = Get-AzADServicePrincipal -ObjectId $PrincipalId -ErrorAction Stop
        if ($sp -and $sp.DisplayName) { $display = "$($sp.DisplayName) ($PrincipalId)" }
    } catch {
        # Leave $display as the bare GUID - still usable, just not resolved to a friendly name.
    }

    $script:PrincipalNameCache[$PrincipalId] = $display
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
    <#
      Returns a single pscustomobject { FoundMissing, Actions } instead of a bare bool - Actions is
      a flat list of one-line, already-tense-correct descriptions (FIXED/WOULD FIX/FAILED) so the
      caller can attach exactly what happened to this assignment in the per-MG recap and Job Summary,
      instead of a reader having to go hunt back through the scrolling per-role detail lines above.
    #>
    param($Assignment)

    $principalId = $Assignment.IdentityPrincipalId
    if (-not $principalId) { return [pscustomobject]@{ FoundMissing = $false; Actions = @() } }

    $label = "Policy Assignment '$($Assignment.DisplayName)' ['$($Assignment.Name)']"
    if ($Assignment.EnforcementMode -eq 'DoNotEnforce') { $label += ' [EnforcementMode: DoNotEnforce]' }
    $miName = Get-PrincipalDisplayName -PrincipalId $principalId
    $foundMissing = $false
    $actions = New-Object System.Collections.Generic.List[string]

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
            Write-Warn "$label is missing a role assignment its managed identity '$miName' needs before remediation can work: role '$roleName' at scope $($req.Scope)"

            if ($WhatIf) {
                $msg = "WOULD FIX: assign ROLE: '$roleName' at SCOPE: '$($req.Scope)' to MANAGED-IDENTITY: '$miName' (WhatIf - no change made)"
                $actions.Add($msg)
                Write-ColorLine -Color Yellow "$label -> $msg"
                $script:WouldFixThisRun.Add("$label -> $msg")
            } else {
                try {
                    # -ObjectType ServicePrincipal is required, not cosmetic - the sweep identity's own
                    # User Access Administrator grant has an ABAC condition that only allows roleAssignments/write
                    # when the request's PrincipalType is 'ServicePrincipal' (managed identities register as
                    # service principals); omitting -ObjectType leaves that attribute unset on the request and
                    # the condition denies it, surfacing as a generic AuthorizationFailed.
                    New-AzRoleAssignment -ObjectId $principalId -RoleDefinitionId $reqGuid -Scope $req.Scope -ObjectType ServicePrincipal -ErrorAction Stop | Out-Null
                    $msg = "FIXED: assigned ROLE: '$roleName' at SCOPE: '$($req.Scope)' to MANAGED-IDENTITY: '$miName'"
                    $actions.Add($msg)
                    Write-ColorLine -Color Green "$label -> $msg"
                    $script:FixesThisRun.Add("$label -> $msg")
                } catch {
                    $msg = "FAILED to assign ROLE: '$roleName' at SCOPE: '$($req.Scope)' to MANAGED-IDENTITY: '$miName' - $($_.Exception.Message)"
                    $actions.Add($msg)
                    Write-Err "$label -> $msg"
                    $script:HadFailures = $true
                }
            }
        }
    }

    [pscustomobject]@{ FoundMissing = $foundMissing; Actions = $actions }
}

function Invoke-Remediation {
    <#
      Returns { Started, Actions } like Ensure-RoleAssignments. Deliberately labelled "STARTED a
      remediation task", never "FIXED" - policy remediation is async (the task runs and re-evaluates
      compliance after this script exits), so claiming it's fixed here would be inaccurate.

      SKIPS remediation by default for DoNotEnforce assignments - a deliberate safety default, NOT an
      Azure limitation. Confirmed from Microsoft's own "Enforcement mode" docs: remediation tasks CAN be
      started manually regardless of enforcement mode ("Remediate manually" = Yes for both Default and
      DoNotEnforce) - enforcementMode only gates auto-enforcement on new/updated resources. Pass the
      top-level -FixDoNotEnforcePolicies switch to opt into remediating these too. Ensure-RoleAssignments'
      RBAC gap-fill always still applies regardless, since that's inert prep work, not a resource change.
      The skip is only decided AFTER checking for non-compliant resources, so a skip is always reported
      with the real count of resources being left unfixed - never a silent, uninformative "skipped".

      Returns Started and Skipped as SEPARATE flags (not conflated) - Started means a real fix was
      applied or would be (WhatIf); Skipped means non-compliant resources exist but were deliberately
      left alone due to DoNotEnforce. Callers use this to put an assignment in its own "skipped" recap
      bucket, distinct from genuine "needs action", instead of counting it as if it were actioned.
    #>
    param($Assignment, [string]$ManagementGroupId)

    $label = "Policy Assignment '$($Assignment.DisplayName)' ['$($Assignment.Name)']"
    if ($Assignment.EnforcementMode -eq 'DoNotEnforce') { $label += ' [EnforcementMode: DoNotEnforce]' }

    # ASSUMED flattened like .Scope/.PolicyDefinitionId/.IdentityType elsewhere in this script (not yet
    # independently verified) - if this property path turns out wrong, $skipDueToEnforcement is just always
    # $false and remediation runs unconditionally regardless of -FixDoNotEnforcePolicies (fails open).
    $skipDueToEnforcement = $Assignment.EnforcementMode -eq 'DoNotEnforce' -and -not $FixDoNotEnforcePolicies

    $isSet = $Assignment.PolicyDefinitionId -match '/policySetDefinitions/'
    $actions = New-Object System.Collections.Generic.List[string]

    if (-not $isSet) {
        $nonCompliant = Get-AzPolicyState -ManagementGroupName $ManagementGroupId `
            -Filter "PolicyAssignmentId eq '$($Assignment.Id)' and ComplianceState eq 'NonCompliant'"
        if ($nonCompliant) {
            if ($skipDueToEnforcement) {
                $msg = "SKIPPED: NON-COMPLIANT-COUNT: $($nonCompliant.Count) resource(s) left unremediated at SCOPE: '$ManagementGroupId' - assignment is in DoNotEnforce mode (pass -FixDoNotEnforcePolicies to include it)"
                $actions.Add($msg)
                Write-ColorLine -Color Cyan "$label -> $msg"
                return [pscustomobject]@{ Started = $false; Skipped = $true; Actions = $actions }
            }
            if ($WhatIf) {
                $msg = "WOULD START: remediation task at SCOPE: '$ManagementGroupId' for NON-COMPLIANT-COUNT: $($nonCompliant.Count) resource(s) (WhatIf - no change made)"
                $actions.Add($msg)
                Write-ColorLine -Color Yellow "$label -> $msg"
                $script:WouldFixThisRun.Add("$label -> $msg")
            } else {
                try {
                    Start-AzPolicyRemediation -Name "sweep-$($Assignment.Name)-$(Get-Date -Format yyyyMMddHHmm)" `
                        -PolicyAssignmentId $Assignment.Id -ManagementGroupId $ManagementGroupId -ErrorAction Stop | Out-Null
                    $msg = "STARTED: remediation task at SCOPE: '$ManagementGroupId' for NON-COMPLIANT-COUNT: $($nonCompliant.Count) resource(s)"
                    $actions.Add($msg)
                    Write-ColorLine -Color Yellow "$label -> $msg"
                    $script:FixesThisRun.Add("$label -> $msg")
                } catch {
                    $msg = "FAILED to start remediation at SCOPE: '$ManagementGroupId' - $($_.Exception.Message)"
                    $actions.Add($msg)
                    Write-Err "$label -> $msg"
                    $script:HadFailures = $true
                }
            }
            return [pscustomobject]@{ Started = $true; Skipped = $false; Actions = $actions }
        }
        return [pscustomobject]@{ Started = $false; Skipped = $false; Actions = $actions }
    }

    # Initiative: only remediate member policy references that actually have non-compliant resources
    $nonCompliantRefs = Get-AzPolicyState -ManagementGroupName $ManagementGroupId `
        -Filter "PolicyAssignmentId eq '$($Assignment.Id)' and ComplianceState eq 'NonCompliant'" |
        Group-Object PolicyDefinitionReferenceId

    foreach ($refGroup in $nonCompliantRefs) {
        if ($skipDueToEnforcement) {
            $msg = "SKIPPED: MEMBER-POLICY: '$($refGroup.Name)' has NON-COMPLIANT-COUNT: $($refGroup.Count) resource(s) left unremediated at SCOPE: '$ManagementGroupId' - DoNotEnforce mode (pass -FixDoNotEnforcePolicies to include it)"
            $actions.Add($msg)
            Write-ColorLine -Color Cyan "$label -> $msg"
            continue
        }
        if ($WhatIf) {
            $msg = "WOULD START: remediation task for MEMBER-POLICY: '$($refGroup.Name)' at SCOPE: '$ManagementGroupId' for NON-COMPLIANT-COUNT: $($refGroup.Count) resource(s) (WhatIf - no change made)"
            $actions.Add($msg)
            Write-ColorLine -Color Yellow "$label -> $msg"
            $script:WouldFixThisRun.Add("$label -> $msg")
        } else {
            try {
                Start-AzPolicyRemediation -Name "sweep-$($Assignment.Name)-$($refGroup.Name)-$(Get-Date -Format yyyyMMddHHmm)" `
                    -PolicyAssignmentId $Assignment.Id -ManagementGroupId $ManagementGroupId `
                    -PolicyDefinitionReferenceId $refGroup.Name -ErrorAction Stop | Out-Null
                $msg = "STARTED: remediation task for MEMBER-POLICY: '$($refGroup.Name)' at SCOPE: '$ManagementGroupId' for NON-COMPLIANT-COUNT: $($refGroup.Count) resource(s)"
                $actions.Add($msg)
                Write-ColorLine -Color Yellow "$label -> $msg"
                $script:FixesThisRun.Add("$label -> $msg")
            } catch {
                $msg = "FAILED to start remediation for MEMBER-POLICY: '$($refGroup.Name)' at SCOPE: '$ManagementGroupId' - $($_.Exception.Message)"
                $actions.Add($msg)
                Write-Err "$label -> $msg"
                $script:HadFailures = $true
            }
        }
    }

    # skipDueToEnforcement is assignment-wide (not per member-policy), so it's never a mix of
    # started-and-skipped within one assignment here - either all refs above were skipped, or none were.
    if ($skipDueToEnforcement) {
        [pscustomobject]@{ Started = $false; Skipped = ($nonCompliantRefs.Count -gt 0); Actions = $actions }
    } else {
        [pscustomobject]@{ Started = ($nonCompliantRefs.Count -gt 0); Skipped = $false; Actions = $actions }
    }
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

    $needsAction = New-Object System.Collections.Generic.List[object]
    $skippedDoNotEnforce = New-Object System.Collections.Generic.List[object]
    $noActionNeeded = New-Object System.Collections.Generic.List[string]
    # Independent counters (NOT mutually exclusive like the buckets above) - an assignment can both get a
    # role fixed AND have its remediation skipped, which the single needsAction/skipped/noAction bucketing
    # can't represent at once. These feed the summary table's separate Roles Fixed / Remediation Started /
    # Remediation Skipped columns, so that combination is never hidden inside one blended "Actioned" number.
    $rolesFixedCount = 0
    $remediationStartedCount = 0
    $remediationSkippedCount = 0

    foreach ($assignment in $assignments) {
        $label = "Policy Assignment '$($assignment.DisplayName)' ['$($assignment.Name)']"
        # Tag the label itself (not just the bucket) with enforcement mode, so it's visible even when
        # this assignment lands in "Actioned" purely from an unconditional RBAC gap-fix (independent of
        # enforcement mode) rather than from an actual remediation - otherwise a DoNotEnforce assignment
        # showing up as "Actioned" with no DoNotEnforce marker anywhere looks like a reporting mistake.
        if ($assignment.EnforcementMode -eq 'DoNotEnforce') { $label += ' [EnforcementMode: DoNotEnforce]' }
        $foundIssue = $false
        $wasSkipped = $false
        $assignmentActions = New-Object System.Collections.Generic.List[string]

        # Only the root MG has the confirmed role-assignment gap - children already work via Terraform/alzlib.
        if ($mgId -eq $RootManagementGroupId) {
            $roleResult = Ensure-RoleAssignments -Assignment $assignment
            if ($roleResult.FoundMissing) { $foundIssue = $true; $rolesFixedCount++ }
            foreach ($a in $roleResult.Actions) { $assignmentActions.Add($a) }
        }

        $remediationResult = Invoke-Remediation -Assignment $assignment -ManagementGroupId $mgId
        if ($remediationResult.Started) { $foundIssue = $true; $remediationStartedCount++ }
        if ($remediationResult.Skipped) { $wasSkipped = $true; $remediationSkippedCount++ }
        foreach ($a in $remediationResult.Actions) { $assignmentActions.Add($a) }

        # A genuine action (role-fix and/or real remediation) always wins the bucketing, even if this
        # same assignment ALSO had a skipped member policy - "needs action" is reserved for things a real
        # run actually does; "skipped" is its own bucket for things deliberately left alone, never both.
        # (This bucketing still only drives the console [ACTION]/[SKIPPED]/[OK] groups below - the
        # independent counters above are what the summary table uses instead.)
        if ($foundIssue) {
            $needsAction.Add([pscustomobject]@{ Label = $label; Actions = $assignmentActions })
        } elseif ($wasSkipped) {
            $skippedDoNotEnforce.Add([pscustomobject]@{ Label = $label; Actions = $assignmentActions })
        } else {
            Write-ColorLine -Color Green "$label - all required role assignments present, no non-compliant resources found; nothing to do"
            $noActionNeeded.Add($label)
        }
    }

    Write-ColorLine -Color Bold "Summary for '$mgId': $($assignments.Count) total, $rolesFixedCount role(s) fixed, $remediationStartedCount remediation(s) started, $remediationSkippedCount remediation(s) skipped (DoNotEnforce), $($noActionNeeded.Count) need no action"

    if ($needsAction.Count -gt 0) {
        Write-ColorLine -Color Yellow "-- [ACTION] Assignments needing action ($($needsAction.Count)) --"
        foreach ($entry in $needsAction) {
            Write-ColorLine -Color Yellow "  * $($entry.Label)"
            foreach ($a in $entry.Actions) { Write-ColorLine -Color Yellow "      -> $a" }
        }
    }
    if ($skippedDoNotEnforce.Count -gt 0) {
        Write-ColorLine -Color Cyan "-- [SKIPPED] Assignments left alone - DoNotEnforce ($($skippedDoNotEnforce.Count)) --"
        foreach ($entry in $skippedDoNotEnforce) {
            Write-ColorLine -Color Cyan "  * $($entry.Label)"
            foreach ($a in $entry.Actions) { Write-ColorLine -Color Cyan "      -> $a" }
        }
    }
    if ($noActionNeeded.Count -gt 0) {
        Write-ColorLine -Color Green "-- [OK] Assignments needing no action ($($noActionNeeded.Count)) --"
        foreach ($item in $noActionNeeded) { Write-ColorLine -Color Green "  * $item" }
    }

    $script:AllMgResults.Add([pscustomobject]@{
        ManagementGroupId  = $mgId
        Total              = $assignments.Count
        NeedsAction        = $needsAction.Count
        RolesFixed         = $rolesFixedCount
        RemediationStarted = $remediationStartedCount
        RemediationSkipped = $remediationSkippedCount
        NoActionNeeded     = $noActionNeeded.Count
        NeedsActionItems   = $needsAction
        SkippedItems       = $skippedDoNotEnforce
    })

    Write-LogGroupEnd
}

# --- Overall run summary across every MG processed - one place to look even when the
# group-by-group logs above are long, since the loop above only prints a per-MG recap. ---
$grandTotal              = ($script:AllMgResults | Measure-Object -Property Total -Sum).Sum
$grandNeedsAction        = ($script:AllMgResults | Measure-Object -Property NeedsAction -Sum).Sum
$grandRolesFixed         = ($script:AllMgResults | Measure-Object -Property RolesFixed -Sum).Sum
$grandRemediationStarted = ($script:AllMgResults | Measure-Object -Property RemediationStarted -Sum).Sum
$grandRemediationSkipped = ($script:AllMgResults | Measure-Object -Property RemediationSkipped -Sum).Sum
$grandNoAction           = ($script:AllMgResults | Measure-Object -Property NoActionNeeded -Sum).Sum
# Separate from $grandRemediationSkipped above - this counts only the SkippedItems detail entries (the
# unchanged console-recap bucket), which under-counts vs. the real independent skip count whenever an
# assignment ALSO got a role fixed (that assignment's bucket priority puts it under NeedsAction instead).
# Used only to gate/render the "skipped (detail)" bullet list below, not the table or banners.
$grandSkippedItemsCount  = ($script:AllMgResults | ForEach-Object { $_.SkippedItems.Count } | Measure-Object -Sum).Sum

Write-Host ""
if ($WhatIf) {
    if ($script:WouldFixThisRun.Count -gt 0) {
        Write-ColorLine -Color Bold "===== DRY RUN (WhatIf): would apply $($script:WouldFixThisRun.Count) action(s) across $grandNeedsAction policy assignment(s) - no changes were made ====="
        foreach ($f in $script:WouldFixThisRun) { Write-ColorLine -Color Yellow "  * $f" }
    } else {
        Write-ColorLine -Color Bold "===== DRY RUN (WhatIf): nothing would need fixing this run ====="
    }
} else {
    if ($script:FixesThisRun.Count -gt 0) {
        Write-ColorLine -Color Bold "===== Fixed this run: $($script:FixesThisRun.Count) action(s) across $grandNeedsAction policy assignment(s) ====="
        foreach ($fix in $script:FixesThisRun) { Write-ColorLine -Color Green "  * $fix" }
    } else {
        Write-ColorLine -Color Bold "===== Nothing needed fixing this run ====="
    }
}

Write-Host ""
Write-ColorLine -Color Bold "===== Overall sweep summary: $grandTotal assignment(s) across $($script:AllMgResults.Count) management group(s) - $grandRolesFixed role(s) fixed, $grandRemediationStarted remediation(s) started, $grandRemediationSkipped remediation(s) skipped (DoNotEnforce), $grandNoAction needed none ====="
foreach ($mgResult in $script:AllMgResults) {
    $flag = if ($mgResult.RolesFixed -gt 0 -or $mgResult.RemediationStarted -gt 0) { 'Yellow' } elseif ($mgResult.RemediationSkipped -gt 0) { 'Cyan' } else { 'Green' }
    Write-ColorLine -Color $flag "  $($mgResult.ManagementGroupId): $($mgResult.Total) total, $($mgResult.RolesFixed) roles fixed, $($mgResult.RemediationStarted) remediation started, $($mgResult.RemediationSkipped) skipped, $($mgResult.NoActionNeeded) none"
}

# GitHub Actions Job Summary (the run page's "Summary" tab) - a short markdown table that's easy
# to scan without scrolling the raw logs. No-ops automatically outside GitHub Actions.
if ($script:InGitHubActions -and $env:GITHUB_STEP_SUMMARY) {
    $summaryLines = New-Object System.Collections.Generic.List[string]
    $summaryLines.Add('## Policy remediation sweep summary')
    $summaryLines.Add('')

    if ($WhatIf) {
        if ($script:WouldFixThisRun.Count -gt 0) {
            $summaryLines.Add("**Dry run (WhatIf) - would apply $($script:WouldFixThisRun.Count) action(s) across $grandNeedsAction policy assignment(s); no changes were made:**")
            $summaryLines.Add("*(an assignment can need more than one action, e.g. an initiative with several non-compliant member policies - that's why the action count can be higher than the assignment count below)*")
            foreach ($f in $script:WouldFixThisRun) { $summaryLines.Add("- $f") }
        } else {
            $summaryLines.Add('**Dry run (WhatIf) - nothing would need fixing this run.**')
        }
    } else {
        if ($script:FixesThisRun.Count -gt 0) {
            $summaryLines.Add("**Fixed this run: $($script:FixesThisRun.Count) action(s) across $grandNeedsAction policy assignment(s):**")
            $summaryLines.Add("*(an assignment can need more than one action, e.g. an initiative with several non-compliant member policies - that's why the action count can be higher than the assignment count below)*")
            foreach ($fix in $script:FixesThisRun) { $summaryLines.Add("- $fix") }
        } else {
            $summaryLines.Add('**Nothing needed fixing this run.**')
        }
    }
    $summaryLines.Add('')

    # Table headers render bold automatically (GFM table-header semantics) - that's the only reliable
    # way to visually set them apart in a Job Summary; GitHub's renderer strips HTML style attributes
    # and its only native colour mechanism (Alerts, e.g. [!WARNING]) forces its own icon, which
    # conflicts with removing icons, so it isn't used here.
    # Roles Fixed and Remediation Started/Skipped are separate, independent columns (not one blended
    # "Actioned" number) - DoNotEnforce only ever gates remediation, never role-assignment gap-fill, so
    # it's called out solely on the remediation column where it actually applies. Headers are the same
    # for dry runs and full runs - WOULD FIX/WOULD START vs FIXED/STARTED is already spelled out in the
    # per-assignment action text itself, so the header doesn't need to switch too.
    $summaryLines.Add('| Management Group (Scope) | Total Assignments | Roles Fixed | Remediation Started | Remediation Skipped (DoNotEnforce) | No Action Needed |')
    $summaryLines.Add('|---|---|---|---|---|---|')
    foreach ($mgResult in $script:AllMgResults) {
        $summaryLines.Add("| $($mgResult.ManagementGroupId) | $($mgResult.Total) | $($mgResult.RolesFixed) | $($mgResult.RemediationStarted) | $($mgResult.RemediationSkipped) | $($mgResult.NoActionNeeded) |")
    }
    $summaryLines.Add("| **Total** | **$grandTotal** | **$grandRolesFixed** | **$grandRemediationStarted** | **$grandRemediationSkipped** | **$grandNoAction** |")

    if ($grandNeedsAction -gt 0) {
        $summaryLines.Add('')
        $summaryLines.Add($(if ($WhatIf) { '### Assignments that would be actioned (detail)' } else { '### Assignments actioned (detail)' }))
        foreach ($mgResult in $script:AllMgResults) {
            foreach ($entry in $mgResult.NeedsActionItems) {
                $summaryLines.Add("- **$($mgResult.ManagementGroupId)**: $($entry.Label)")
                foreach ($a in $entry.Actions) {
                    $summaryLines.Add("  - $a")
                }
            }
        }
    }

    if ($grandSkippedItemsCount -gt 0) {
        $summaryLines.Add('')
        $summaryLines.Add('### Assignments skipped - DoNotEnforce (detail)')
        $summaryLines.Add('*(non-compliant resources exist but were deliberately left alone because the assignment is in DoNotEnforce mode; pass `-FixDoNotEnforcePolicies` / the workflow'+"'"+'s `fix_do_not_enforce_policies` input to include them)*')
        foreach ($mgResult in $script:AllMgResults) {
            foreach ($entry in $mgResult.SkippedItems) {
                $summaryLines.Add("- **$($mgResult.ManagementGroupId)**: $($entry.Label)")
                foreach ($a in $entry.Actions) {
                    $summaryLines.Add("  - $a")
                }
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

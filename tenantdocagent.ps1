<#
.SYNOPSIS
  Azure / Intune / Defender / Arc documentation agent (WinForms UI).
  Focus:
    - Intune: Level 3 (deep)
    - Defender: Level 2 (mid-depth)
    - Arc: Level 2 (deep)

.NOTES
  - Run in a 64-bit PowerShell session with: 
      powershell.exe -STA -ExecutionPolicy Bypass -File .\TenantDocAgent.ps1
  - Requires:
      Az.Accounts, Az.Resources, Az.Security, Az.ConnectedMachine, Az.GuestConfiguration
      Microsoft.Graph (deviceManagement, security, etc.)
  - DOCX output requires Microsoft Word installed on this machine.
#>

# Ensure STA for WinForms
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-Warning "Restarting script in STA mode..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    [System.Diagnostics.Process]::Start($psi) | Out-Null
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Global UI references
$script:StatusBox = $null

function Write-UiLog {
    param(
        [string]$Message
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$timestamp] $Message"
    Write-Host $line
    if ($script:StatusBox -ne $null -and -not $script:StatusBox.IsDisposed) {
        $null = $script:StatusBox.AppendText("$line`r`n")
        $script:StatusBox.ScrollToCaret()
    }
}

function Ensure-Module {
    param(
        [Parameter(Mandatory)][string]$Name
    )
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-UiLog "Installing module '${Name}' from PSGallery..."
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -ErrorAction Stop
        }
        catch {
            Write-UiLog "Failed to install module '${Name}': $($_.Exception.Message)"
        }
    }
    Import-Module $Name -ErrorAction SilentlyContinue | Out-Null
    if (-not (Get-Module -Name $Name)) {
        Write-UiLog "WARNING: Module '${Name}' is not available. Some sections may be incomplete."
    }
    else {
        Write-UiLog "Module '${Name}' loaded."
    }
}

#region Basic Tenant Info (lightweight)

function Get-TenantOverview {
    Write-UiLog "Collecting tenant overview (Entra ID)..."
    try {
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $domains = Get-MgDomain -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            DisplayName       = $org.DisplayName
            TenantId          = $org.Id
            CountryLetterCode = $org.CountryLetterCode
            DefaultDomain     = ($org.VerifiedDomains | Where-Object IsDefault | Select-Object -ExpandProperty Name -First 1)
            DomainCount       = $domains.Count
            Domains           = ($domains | Select-Object Name, Id, IsVerified, IsDefault)
        }
    }
    catch {
        Write-UiLog "Error getting tenant overview: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region INTUNE – Level 3 (deep audit)

function Get-IntuneDeepAudit {
    Write-UiLog "Collecting Intune (Endpoint Manager) deep audit..."

    $result = [ordered]@{}

    # ----------------------------
    # Devices
    # ----------------------------
    try {
        Write-UiLog "  - Getting managed devices..."
        $devices = Get-MgDeviceManagementManagedDevice -All -ErrorAction SilentlyContinue
        $result.ManagedDevices = $devices | Select-Object DeviceName, OperatingSystem, OsVersion, 
            ComplianceState, ManagementAgent, UserPrincipalName, EnrolledDateTime, AzureADDeviceId
    }
    catch {
        Write-UiLog "Error getting Managed Devices: $($_.Exception.Message)"
    }

    # ----------------------------
    # Compliance policies
    # ----------------------------
    try {
        Write-UiLog "  - Getting compliance policies..."
        $policies = Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction SilentlyContinue
        $policyDetails = @()

        foreach ($p in $policies) {
            $policyObj = [ordered]@{
                DisplayName       = $p.DisplayName
                Id                = $p.Id
                Description       = $p.Description
                Platform          = $p.AdditionalProperties.'platforms'
                Version           = $p.Version
                CreatedDateTime   = $p.CreatedDateTime
                LastModifiedDateTime = $p.LastModifiedDateTime
            }

            # Assignments
            try {
                $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment `
                    -DeviceCompliancePolicyId $p.Id -ErrorAction SilentlyContinue
                $policyObj.Assignments = $assignments | Select-Object Target, Id
            }
            catch {
                Write-UiLog "    Error getting compliance policy assignments for '${($p.DisplayName)}': $($_.Exception.Message)"
            }

            # Setting state summaries
            try {
                $settingSummaries = Get-MgDeviceManagementDeviceCompliancePolicySettingStateSummary `
                    -DeviceCompliancePolicyId $p.Id -ErrorAction SilentlyContinue
                $policyObj.SettingSummaries = $settingSummaries |
                    Select-Object SettingName, PlatformType, SettingId, DeviceCompliantCount, DeviceNonCompliantCount
            }
            catch {
                Write-UiLog "    Error getting compliance setting summaries for '${($p.DisplayName)}': $($_.Exception.Message)"
            }

            $policyDetails += [PSCustomObject]$policyObj
        }

        $result.CompliancePolicies = $policyDetails
    }
    catch {
        Write-UiLog "Error getting compliance policies: $($_.Exception.Message)"
    }

    # ----------------------------
    # Device Configuration Profiles
    # ----------------------------
    try {
        Write-UiLog "  - Getting device configuration profiles..."
        $configProfiles = Get-MgDeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
        $configDetails = @()

        foreach ($cp in $configProfiles) {
            $cfg = [ordered]@{
                DisplayName     = $cp.DisplayName
                Id              = $cp.Id
                Description     = $cp.Description
                OdataType       = $cp.AdditionalProperties.'@odata.type'
                Version         = $cp.Version
                CreatedDateTime = $cp.CreatedDateTime
                LastModifiedDateTime = $cp.LastModifiedDateTime
            }

            # Assignments
            try {
                $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment `
                    -DeviceConfigurationId $cp.Id -ErrorAction SilentlyContinue
                $cfg.Assignments = $assignments | Select-Object Id, Target
            }
            catch {
                Write-UiLog "    Error getting config profile assignments for '${($cp.DisplayName)}': $($_.Exception.Message)"
            }

            # Device status summary
            try {
                $deviceStatuses = Get-MgDeviceManagementDeviceConfigurationDeviceStatus `
                    -DeviceConfigurationId $cp.Id -ErrorAction SilentlyContinue
                $cfg.DeviceStatusSummary = $deviceStatuses |
                    Group-Object Status |
                    Select-Object Name, Count
            }
            catch {
                Write-UiLog "    Error getting config profile device status for '${($cp.DisplayName)}': $($_.Exception.Message)"
            }

            $configDetails += [PSCustomObject]$cfg
        }

        $result.ConfigurationProfiles = $configDetails
    }
    catch {
        Write-UiLog "Error getting device configuration profiles: $($_.Exception.Message)"
    }

    # ----------------------------
    # Settings Catalog / Intents
    # ----------------------------
    try {
        Write-UiLog "  - Getting configuration policies (Settings Catalog / Intents)..."
        $confPolicies = Get-MgDeviceManagementConfigurationPolicy -ErrorAction SilentlyContinue
        $cpDetails = @()

        foreach ($p in $confPolicies) {
            $cpObj = [ordered]@{
                DisplayName     = $p.Name
                Id              = $p.Id
                Description     = $p.Description
                TemplateId      = $p.TemplateId
                RoleScopeTagIds = ($p.RoleScopeTagIds -join ", ")
                Platforms       = $p.Platforms
                Technologies    = $p.Technologies
                CreatedDateTime = $p.CreatedDateTime
                LastModifiedDateTime = $p.LastModifiedDateTime
            }
            $cpDetails += [PSCustomObject]$cpObj
        }

        $result.SettingsCatalogPolicies = $cpDetails
    }
    catch {
        Write-UiLog "Error getting configuration policies: $($_.Exception.Message)"
    }

    # ----------------------------
    # Apps + Win32 classification
    # ----------------------------
    try {
        Write-UiLog "  - Getting apps (including Win32)..."
        $apps = Get-MgDeviceAppManagementMobileApp -All -ErrorAction SilentlyContinue
        $appDetails = @()

        foreach ($a in $apps) {
            $type = $a.AdditionalProperties.'@odata.type'
            $appObj = [ordered]@{
                DisplayName   = $a.DisplayName
                Id            = $a.Id
                Publisher     = $a.Publisher
                OdataType     = $type
                IsFeatured    = $a.IsFeatured
                CreatedDateTime = $a.CreatedDateTime
                LastModifiedDateTime = $a.LastModifiedDateTime
            }

            if ($type -like "*win32LobApp")       { $appObj.Kind = "Win32LobApp" }
            elseif ($type -like "*microsoftStore*"){ $appObj.Kind = "StoreApp" }
            elseif ($type -like "*ios*")           { $appObj.Kind = "iOS/iPadOS" }
            elseif ($type -like "*android*")       { $appObj.Kind = "Android" }
            else                                   { $appObj.Kind = "Other" }

            $appDetails += [PSCustomObject]$appObj
        }

        $result.Apps = $appDetails
    }
    catch {
        Write-UiLog "Error getting apps: $($_.Exception.Message)"
    }

    # ----------------------------
    # Assignment Filters
    # ----------------------------
    try {
        Write-UiLog "  - Getting assignment filters..."
        $filters = Get-MgDeviceManagementAssignmentFilter -ErrorAction SilentlyContinue
        $result.AssignmentFilters = $filters | 
            Select-Object DisplayName, Id, Platform, Rule, RoleScopeTags
    }
    catch {
        Write-UiLog "Error getting assignment filters: $($_.Exception.Message)"
    }

    # ----------------------------
    # Autopilot devices + profiles
    # ----------------------------
    try {
        Write-UiLog "  - Getting Windows Autopilot devices..."
        $apDevices = Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All -ErrorAction SilentlyContinue
        $result.AutopilotDevices = $apDevices |
            Select-Object DisplayName, Id, GroupTag, SerialNumber, Manufacturer, Model, EnrollmentState
    }
    catch {
        Write-UiLog "Error getting Autopilot devices: $($_.Exception.Message)"
    }

    try {
        Write-UiLog "  - Getting Windows Autopilot deployment profiles..."
        $apProfiles = Get-MgDeviceManagementWindowsAutopilotDeploymentProfile -ErrorAction SilentlyContinue
        $result.AutopilotDeploymentProfiles = $apProfiles |
            Select-Object DisplayName, Id, Description, OutOfBoxExperienceSettings
    }
    catch {
        Write-UiLog "Error getting Autopilot deployment profiles: $($_.Exception.Message)"
    }

    # ----------------------------
    # ESP
    # ----------------------------
    try {
        Write-UiLog "  - Getting Enrollment Status Pages..."
        $esps = Get-MgDeviceManagementEnrollmentStatusPage -ErrorAction SilentlyContinue
        $result.EnrollmentStatusPages = $esps |
            Select-Object DisplayName, Id, Description, ShowInstallationProgress, AllowDeviceUseBeforeProfileAndAppInstallComplete
    }
    catch {
        Write-UiLog "Error getting ESP: $($_.Exception.Message)"
    }

    # ----------------------------
    # RBAC roles
    # ----------------------------
    try {
        Write-UiLog "  - Getting Intune RBAC roles..."
        $roles = Get-MgDeviceManagementRoleDefinition -ErrorAction SilentlyContinue
        $result.IntuneRoles = $roles |
            Select-Object DisplayName, Id, Description, IsBuiltIn, RolePermissions
    }
    catch {
        Write-UiLog "Error getting Intune roles: $($_.Exception.Message)"
    }

    # ----------------------------
    # Windows Update Rings
    # ----------------------------
    try {
        Write-UiLog "  - Getting Windows Update rings..."
        $updateRings = Get-MgDeviceManagementWindowsUpdateForBusinessConfiguration -ErrorAction SilentlyContinue
        $result.WindowsUpdateRings = $updateRings |
            Select-Object DisplayName, Id, Description, QualityUpdateDeferralPeriodInDays, FeatureUpdateDeferralPeriodInDays
    }
    catch {
        Write-UiLog "Error getting Windows Update rings: $($_.Exception.Message)"
    }

    [PSCustomObject]$result
}

#endregion

#region DEFENDER – Level 2

function Get-DefenderMidAudit {
    Write-UiLog "Collecting Defender mid-depth audit..."

    $result = [ordered]@{}

    try {
        Write-UiLog "  - Getting Defender for Cloud pricing..."
        $secPricing = Get-AzSecurityPricing -ErrorAction SilentlyContinue
        $result.DefenderForCloudPricing = $secPricing |
            Select-Object Name, PricingTier, SubPlan
    }
    catch {
        Write-UiLog "Error getting pricing: $($_.Exception.Message)"
    }

    try {
        Write-UiLog "  - Getting security contacts..."
        $secContacts = Get-AzSecurityContact -ErrorAction SilentlyContinue
        $result.DefenderSecurityContacts = $secContacts |
            Select-Object Name, Email, Phone, AlertNotifications, AlertsToAdmins
    }
    catch {
        Write-UiLog "Error getting security contacts: $($_.Exception.Message)"
    }

    try {
        Write-UiLog "  - Getting secure score..."
        $secureScores = Get-MgSecuritySecureScore -ErrorAction SilentlyContinue
        $result.SecureScore = $secureScores |
            Select-Object CreatedDateTime, CurrentScore, MaxScore, EnabledServices
    }
    catch {
        Write-UiLog "Error getting secure score: $($_.Exception.Message)"
    }

    try {
        Write-UiLog "  - Getting recent Defender alerts..."
        $alerts = Get-MgSecurityAlert -Top 100 -ErrorAction SilentlyContinue
        $result.DefenderAlerts = $alerts |
            Select-Object CreatedDateTime, Status, Severity, Category, Title, Id
    }
    catch {
        Write-UiLog "Error getting Defender alerts: $($_.Exception.Message)"
    }

    try {
        Write-UiLog "  - Getting Defender for Cloud recommendations..."
        $recommendations = Get-AzSecurityTask -ErrorAction SilentlyContinue
        $result.DefenderRecommendations = $recommendations |
            Select-Object Name, State, Severity, ResourceId, Description
    }
    catch {
        Write-UiLog "Error getting Cloud recommendations: $($_.Exception.Message)"
    }

    [PSCustomObject]$result
}

#endregion

#region ARC – Level 2

function Get-ArcDeepAudit {
    Write-UiLog "Collecting Azure Arc deep audit..."

    $result = [ordered]@{}

    try {
        Write-UiLog "  - Getting Arc machines..."
        $arcMachines = Get-AzConnectedMachine -ErrorAction SilentlyContinue
        $result.ArcMachines = $arcMachines |
            Select-Object Name, ResourceGroupName, Location, Status, SubscriptionId, Type
    }
    catch {
        Write-UiLog "Error getting Arc machines: $($_.Exception.Message)"
    }

    $gcAssignmentsAll = @()
    $extAll = @()
    $policyStatesAll = @()

    if ($arcMachines) {
        foreach ($m in $arcMachines) {
            $rg   = $m.ResourceGroupName
            $name = $m.Name
            Write-UiLog "    Processing Arc machine '${name}' in RG '${rg}'..."

            try {
                $gcAssignments = Get-AzGuestConfigurationAssignment -ResourceGroupName $rg -MachineName $name -ErrorAction SilentlyContinue
                if ($gcAssignments) {
                    $gcAssignmentsAll += $gcAssignments |
                        Select-Object MachineName, ResourceGroupName, Name, ComplianceStatus, ProvisioningState
                }
            }
            catch {
                Write-UiLog "      Error getting GC assignments for ${name}: $($_.Exception.Message)"
            }

            try {
                $exts = Get-AzConnectedMachineExtension -ResourceGroupName $rg -MachineName $name -ErrorAction SilentlyContinue
                if ($exts) {
                    $extAll += $exts |
                        Select-Object MachineName, ResourceGroupName, Name, Type, ProvisioningState, Publisher, TypeHandlerVersion
                }
            }
            catch {
                Write-UiLog "      Error getting extensions for ${name}: $($_.Exception.Message)"
            }

            try {
                $id = $m.Id
                if ($id) {
                    $policyStates = Get-AzPolicyState -Filter "resourceId eq '$id'" -ErrorAction SilentlyContinue
                    if ($policyStates) {
                        $policyStatesAll += $policyStates |
                            Select-Object ResourceId, PolicyAssignmentName, ComplianceState, PolicyDefinitionAction
                    }
                }
            }
            catch {
                Write-UiLog "      Error getting policy states for ${name}: $($_.Exception.Message)"
            }
        }
    }

    if ($gcAssignmentsAll) { $result.GuestConfigurationAssignments = $gcAssignmentsAll }
    if ($extAll)            { $result.MachineExtensions = $extAll }
    if ($policyStatesAll)   { $result.PolicyStates = $policyStatesAll }

    [PSCustomObject]$result
}

#endregion

#region HTML + DOCX Report

function New-ReportHtml {
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][hashtable]$Data
    )

    Write-UiLog "Building HTML report..."

    $sectionsHtml = New-Object System.Collections.Generic.List[string]

    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ($null -eq $value) { continue }

        $sectionsHtml.Add("<h2>${key}</h2>")

        if ($value -is [System.Collections.IDictionary] -or 
            $value.PSObject.TypeNames -contains 'System.Collections.Specialized.OrderedDictionary') 
        {
            foreach ($innerKey in $value.Keys) {
                $innerVal = $value[$innerKey]
                if ($null -eq $innerVal) { continue }
                $sectionsHtml.Add("<h3>${innerKey}</h3>")
                $sectionsHtml.Add(($innerVal | ConvertTo-Html -Fragment | Out-String))
            }
        }
        else {
            $sectionsHtml.Add(($value | ConvertTo-Html -Fragment | Out-String))
        }
    }

    $body = ($sectionsHtml -join "`r`n")

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>Tenant Documentation Report</title>
    <style>
        body { font-family: Segoe UI, Arial; font-size: 12px; margin:20px; }
        h1 { border-bottom: 2px solid #444; padding-bottom:4px; }
        h2 { margin-top:25px; border-bottom: 1px solid #999; padding-bottom:3px; }
        h3 { margin-top:15px; }
        table { border-collapse: collapse; width:100%; margin-top:10px; }
        th, td { border:1px solid #ddd; padding:4px 6px; }
        th { background:#f0f0f0; }
        tr:nth-child(even) { background:#fafafa; }
        .meta { font-size: 11px; color:#666; margin-bottom:10px; }
    </style>
</head>
<body>
<h1>Intune / Defender / Arc Tenant Documentation</h1>
<div class="meta">
    Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br/>
    Machine: $env:COMPUTERNAME<br/>
    User: $env:USERNAME
</div>
$body
</body>
</html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
    Write-UiLog "HTML report written to ${OutputPath}"
}

function Convert-HtmlToDocx {
    param(
        [Parameter(Mandatory)][string]$HtmlPath,
        [Parameter(Mandatory)][string]$DocxPath
    )

    Write-UiLog "Attempting DOCX generation via Word COM..."

    try {
        $word = New-Object -ComObject Word.Application
    }
    catch {
        Write-UiLog "Word COM unavailable. Skipping DOCX."
        return
    }

    try {
        $word.Visible = $false
        $doc = $word.Documents.Add()
        $selection = $word.Selection
        $selection.InsertFile($HtmlPath)
        $doc.SaveAs([ref]$DocxPath, [ref]16)
        $doc.Close()
        $word.Quit()
        Write-UiLog "DOCX report written to ${DocxPath}"
    }
    catch {
        Write-UiLog "Error writing DOCX: $($_.Exception.Message)"
        try { $word.Quit() } catch {}
    }
}

#endregion

#region Documentation job

function Run-DocumentationJob {
    param(
        [Parameter(Mandatory)][string]$OutputFolder,
        [Parameter(Mandatory)][bool]$CreateHtml,
        [Parameter(Mandatory)][bool]$CreateDocx
    )

    Write-UiLog "Starting documentation job..."

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $htmlPath = Join-Path $OutputFolder "TenantDocumentation-${timestamp}.html"
    $docxPath = Join-Path $OutputFolder "TenantDocumentation-${timestamp}.docx"

    $data = [ordered]@{}
    $data.TenantOverview  = Get-TenantOverview
    $data.IntuneDeep      = Get-IntuneDeepAudit
    $data.Defender        = Get-DefenderMidAudit
    $data.Arc             = Get-ArcDeepAudit

    if ($CreateHtml) {
        New-ReportHtml -OutputPath $htmlPath -Data $data
    }

    if ($CreateDocx) {
        if (-not $CreateHtml) {
            New-ReportHtml -OutputPath $htmlPath -Data $data
        }
        Convert-HtmlToDocx -HtmlPath $htmlPath -DocxPath $docxPath
    }

    Write-UiLog "Documentation job completed."
}

#endregion

#region Cloud Connection

function Connect-Cloud {
    Write-UiLog "Loading modules..."

    Ensure-Module -Name Az.Accounts
    Ensure-Module -Name Az.Resources
    Ensure-Module -Name Az.Security
    Ensure-Module -Name Az.ConnectedMachine
    Ensure-Module -Name Az.GuestConfiguration
    Ensure-Module -Name Microsoft.Graph

    Write-UiLog "Connecting to Azure..."
    try {
        Connect-AzAccount -ErrorAction Stop | Out-Null
        Write-UiLog "Connected to Azure."
    }
    catch {
        Write-UiLog "Azure connection failed: $($_.Exception.Message)"
    }

    Write-UiLog "Connecting to Graph..."
    $scopes = @(
        "Directory.Read.All",
        "Policy.Read.All",
        "AuditLog.Read.All",
        "Reports.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementApps.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "SecurityEvents.Read.All",
        "Security.Read.All"
    )

    try {
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop | Out-Null
        Write-UiLog "Connected to Graph."
    }
    catch {
        Write-UiLog "Graph connection failed: $($_.Exception.Message)"
    }
}

#endregion

# -----------------------------
# UI
# -----------------------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Intune / Defender / Arc Documentation Agent"
$form.Size = New-Object System.Drawing.Size(720, 520)
$form.StartPosition = "CenterScreen"

$labelHeader = New-Object System.Windows.Forms.Label
$labelHeader.Text = "Tenant Documentation Agent (Intune L3 / Defender L2 / Arc L2)"
$labelHeader.AutoSize = $true
$labelHeader.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($labelHeader)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = "1. Connect Azure && Graph"
$btnConnect.Size = New-Object System.Drawing.Size(200, 30)
$btnConnect.Location = New-Object System.Drawing.Point(10, 40)
$form.Controls.Add($btnConnect)

$labelOutput = New-Object System.Windows.Forms.Label
$labelOutput.Text = "2. Output folder:"
$labelOutput.AutoSize = $true
$labelOutput.Location = New-Object System.Drawing.Point(10, 85)
$form.Controls.Add($labelOutput)

$textOutput = New-Object System.Windows.Forms.TextBox
$textOutput.Size = New-Object System.Drawing.Size(520, 20)
$textOutput.Location = New-Object System.Drawing.Point(10, 105)
$textOutput.Text = [Environment]::GetFolderPath('MyDocuments')
$form.Controls.Add($textOutput)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Size = New-Object System.Drawing.Size(80, 24)
$btnBrowse.Location = New-Object System.Drawing.Point(540, 102)
$form.Controls.Add($btnBrowse)

$chkHtml = New-Object System.Windows.Forms.CheckBox
$chkHtml.Text = "Generate HTML"
$chkHtml.Checked = $true
$chkHtml.AutoSize = $true
$chkHtml.Location = New-Object System.Drawing.Point(10, 140)
$form.Controls.Add($chkHtml)

$chkDocx = New-Object System.Windows.Forms.CheckBox
$chkDocx.Text = "Generate DOCX (requires Word)"
$chkDocx.Checked = $true
$chkDocx.AutoSize = $true
$chkDocx.Location = New-Object System.Drawing.Point(150, 140)
$form.Controls.Add($chkDocx)

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "3. Run Documentation Job"
$btnRun.Size = New-Object System.Drawing.Size(220, 34)
$btnRun.Location = New-Object System.Drawing.Point(10, 175)
$form.Controls.Add($btnRun)

$labelStatus = New-Object System.Windows.Forms.Label
$labelStatus.Text = "Status / Log:"
$labelStatus.AutoSize = $true
$labelStatus.Location = New-Object System.Drawing.Point(10, 220)
$form.Controls.Add($labelStatus)

$StatusBox = New-Object System.Windows.Forms.TextBox
$StatusBox.Multiline = $true
$StatusBox.ScrollBars = "Vertical"
$StatusBox.ReadOnly = $true
$StatusBox.Size = New-Object System.Drawing.Size(680, 240)
$StatusBox.Location = New-Object System.Drawing.Point(10, 240)
$form.Controls.Add($StatusBox)

$script:StatusBox = $StatusBox

$btnConnect.Add_Click({ Connect-Cloud })
$btnBrowse.Add_Click({
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.SelectedPath = $textOutput.Text
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $textOutput.Text = $dialog.SelectedPath
    }
})

$btnRun.Add_Click({
    $outputFolder = $textOutput.Text

    if (-not $outputFolder) {
        [System.Windows.Forms.MessageBox]::Show("Please specify an output folder.")
        return
    }

    Run-DocumentationJob `
        -OutputFolder $outputFolder `
        -CreateHtml:$($chkHtml.Checked) `
        -CreateDocx:$($chkDocx.Checked)
})

[System.Windows.Forms.Application]::EnableVisualStyles()
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()

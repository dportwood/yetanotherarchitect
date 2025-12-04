<#!
.SYNOPSIS
Generates a flattened CSV of NTFS permissions for every item within a share.

.DESCRIPTION
Iterates the specified path on the local server hosting the share and captures
user and group permissions for each file and directory. The output CSV is ready
for pivoting or filtering in Excel by user, group, file, or directory.

.EXAMPLE
./SharePermissionsReport.ps1 -Path "D:\Shares\Finance" -OutputPath "FinancePerms.csv"

.PARAMETER Path
Root path of the share to inspect. Must be accessible from the local server.

.PARAMETER OutputPath
Destination CSV path. Defaults to ./SharePermissions.csv.

.PARAMETER IncludeInherited
Include inherited permissions in the report. By default only explicit entries
are exported.

.PARAMETER FollowJunctions
Follow directory junctions and symlinks. By default they are skipped to avoid
unexpected recursion.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "./SharePermissions.csv",

    [Parameter()]
    [switch]$IncludeInherited,

    [Parameter()]
    [switch]$FollowJunctions
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "The path '$Path' does not exist or cannot be accessed."
}

Write-Host "Collecting items under $Path ..." -ForegroundColor Cyan

$gciParams = @{ LiteralPath = $Path; Force = $true; Recurse = $true }
if (-not $FollowJunctions) {
    $gciParams["Attributes"] = "!ReparsePoint"
}

$items = @()
$items += Get-Item -LiteralPath $Path -Force
$items += Get-ChildItem @gciParams

$total = $items.Count
if ($total -eq 0) {
    Write-Warning "No items found under $Path."
}

$rows = foreach ($index in 0..($total - 1)) {
    $item = $items[$index]
    $percent = [int](($index + 1) / $total * 100)
    Write-Progress -Activity "Reading ACLs" -Status $item.FullName -PercentComplete $percent

    try {
        $acl = Get-Acl -LiteralPath $item.FullName
    }
    catch {
        Write-Warning "Skipping $($item.FullName): $($_.Exception.Message)"
        continue
    }

    foreach ($access in $acl.Access) {
        if (-not $IncludeInherited -and $access.IsInherited) {
            continue
        }

        [PSCustomObject]@{
            Path               = $item.FullName
            ItemType           = if ($item.PSIsContainer) { "Directory" } else { "File" }
            Identity           = $access.IdentityReference.Value
            AccessType         = $access.AccessControlType
            Rights             = $access.FileSystemRights
            IsInherited        = $access.IsInherited
            InheritanceFlags   = $access.InheritanceFlags
            PropagationFlags   = $access.PropagationFlags
        }
    }
}

$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
Write-Host "Permission report written to $OutputPath" -ForegroundColor Green

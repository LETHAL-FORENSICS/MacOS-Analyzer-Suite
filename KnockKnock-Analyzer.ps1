# KnockKnock-Analyzer v0.1
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-03-16
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
# jq v1.8.1 (2025-07-01)
# https://jqlang.org/ --> jq-windows-amd64.exe
# https://github.com/stedolan/jq
#
# VirusTotal-CLI v1.3.0 (2026-02-17)
# https://github.com/VirusTotal/vt-cli --> Windows64.zip
#
# yq v4.52.4 (2026-02-14)
# https://github.com/mikefarah/yq --> yq_windows_amd64.zip
#
#
# Changelog:
# Version 0.1
# Release Date: 2026-03-16
# Initial Release
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.5
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  KnockKnock-Analyzer v0.1 - Automated Forensic Analysis of KnockKnock Findings for DFIR

.DESCRIPTION
  KnockKnock-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of KnockKnock results (KnockKnock_Results_yyyy-MM-dd.json).

  https://objective-see.org/products/knockknock.html
  https://github.com/objective-see/KnockKnock

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\KnockKnock-Analyzer".

  Note: The subdirectory 'KnockKnock-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (KnockKnock_Results_yyyy-MM-dd.json).

.PARAMETER skipVT
  Do not query VirusTotal with item hashes.

.EXAMPLE
  PS> .\KnockKnock-Analyzer.ps1

.EXAMPLE
  PS> .\KnockKnock-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\KnockKnock_Results_2026-03-13.json"

.EXAMPLE
  PS> .\KnockKnock-Analyzer.ps1 -Path "H:\macos-collector\KnockKnock\KnockKnock_Results_2026-03-13.json" -OutputDir "H:\MacOS-Analyzer-Suite"

.EXAMPLE
  PS> .\KnockKnock-Analyzer.ps1 -Path "H:\macos-collector\KnockKnock\KnockKnock_Results_2026-03-13.json" -OutputDir "H:\MacOS-Analyzer-Suite" --skipVT

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CmdletBinding

[CmdletBinding()]
Param(
    [String]$Path,
    [String]$OutputDir,
    [Switch]$skipVT
)

#endregion CmdletBinding

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\KnockKnock-Analyzer" # Default
}
else
{
    if ($OutputDir -cnotmatch '.+(?=\\)') 
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = "$OutputDir\KnockKnock-Analyzer" # Custom
    }
}

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Tools

# jq
$script:jq = "$SCRIPT_DIR\Tools\jq\jq-windows-amd64.exe"

# VirusTotal-CLI
$script:vt = "$SCRIPT_DIR\Tools\VirusTotal-CLI\vt.exe"

# yq
$script:yq = "$SCRIPT_DIR\Tools\yq\yq_windows_amd64.exe"

# Configuration File (JSON)
if(!(Test-Path "$PSScriptRoot\Config.json"))
{
    Write-Host "[Error] Config.json NOT found." -ForegroundColor Red
    Exit
}
else
{
    $Config = Get-Content "$PSScriptRoot\Config.json" | ConvertFrom-Json

    # BackgroundColor
    if ($Config.ImportExcel.BackgroundColor)
    {
        if ($Config.ImportExcel.BackgroundColor -cnotmatch '^(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5])),(([0-1]?[0-9]?[0-9])|([2][0-4][0-9])|(25[0-5]))$') # <0-255>,<0-255>,<0-255>
        {
            Write-Host "[Error] You must provide a valid RGB Color Code." -ForegroundColor Red
            Return
        }
    }

    # Excel - Color Scheme
    $script:BackgroundColor = [System.Drawing.Color]$Config.ImportExcel.BackgroundColor
    $script:FontColor       = $Config.ImportExcel.FontColor

    # VirusTotal CLI - API Key
    $script:APIKey = $Config.VirusTotal.APIKey
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$script:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "KnockKnock-Analyzer v0.1 - Automated Forensic Analysis of KnockKnock Findings for DFIR"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
}

# Check if PowerShell module 'ImportExcel' is installed
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] Please install 'ImportExcel' PowerShell module." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://github.com/dfinke/ImportExcel"
    Exit
}

# Check if jq-windows-amd64.exe exists
if (!(Test-Path "$($jq)"))
{
    Write-Host "[Error] jq-windows-amd64.exe NOT found." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Function Get-FileSize
Function Get-FileSize()
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

Function Test-Csv {

<#
.SYNOPSIS
  Test-Csv - Fast Check if CSV is NOT empty

.DESCRIPTION
  The Test-Csv cmdlet checks if the rows of your CSV file are NOT empty.

.PARAMETER Path
  Specifies the path to the CSV file.

.PARAMETER MaxLines
  Specifies the maximum of lines to read from CSV file.

.PARAMETER NoHeader (Optional)
  If this switch is specified, function will NOT skip first line of the file. 

.EXAMPLE
  Test-Csv -Path <CSV> -MaxLines 2

.EXAMPLE
  Test-Csv -Path <CSV> -MaxLines 1 -NoHeader

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

Param
(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$MaxLines,

    [Parameter(ValueFromPipelineByPropertyName = $true)]
    [switch]$NoHeader
)

Begin
{
    $Quotes    = '"'
    $Delimiter = ','
    $Regex     = "$Delimiter(?=(?:[^$Quotes]|$Quotes[^$Quotes]*$Quotes)*$)"
}

Process
{
    $Reader = New-Object -TypeName System.IO.StreamReader -ArgumentList $Path -ErrorAction Stop

    $CsvRawLinesCount  = 0
    $CsvDataLinesCount = 0

    while($null -ne ($Line = $Reader.ReadLine()))
    {
        $CsvRawLinesCount++

        if(!$NoHeader -and ($CsvRawLinesCount -eq 1))
        {
            continue
        }

        if($CsvRawLinesCount -gt $MaxLines)
        {
            break
        }

        if($Line -match $Regex)
        {
            $CsvDataLinesCount++
        }
    }
}

End
{
    $Reader.Close()
    $Reader.Dispose()

    if($CsvDataLinesCount -gt 0)
    {
        $true
    }
    else
    {
        $false
    }
}

}

# Select JSON File (KnockKnock_Results_yyyy-MM-dd.json) --> Default Report and Detailed Report (-verbose) supported
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "KnockKnock|KnockKnock_Results_*.json|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
    }

    $Result = Get-LogFile

    if($Result -eq "OK")
    {
        $script:LogFile = $Result[1]
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:LogFile = $Path
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER\Transcript.txt"

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "KnockKnock-Analyzer v0.1 - Automated Forensic Analysis of KnockKnock Findings for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Create HashTable and import 'WhitelistedFiles.csv'
$script:WhitelistedFiles_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Tools\KnockKnock\Whitelists\WhitelistedFiles.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Tools\KnockKnock\Whitelists\WhitelistedFiles.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Tools\KnockKnock\Whitelists\WhitelistedFiles.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $WhitelistedFiles_HashTable[$_.MD5] = $_.Info }

        # Count Ingested Properties
        $Count = $WhitelistedFiles_HashTable.Count
        Write-Output "[Info]  Initializing 'WhitelistedFiles.csv' Lookup Table ($Count) ..."
    }
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# KnockKnock - Like AutoRuns ...but for macOS!
# https://objective-see.org/products/knockknock.html

# Notarized
# Notarization is the term Apple gives to the process of uploading an asset to Apple for inspection.
# In order to help safeguard and control their software ecoysystems. Apple imposes requirements that applications and installers be inspected by Apple before they are allowed to run on Apple operating systems - either at all or without scary warning signs.

# Check if JSON File exists
if (!(Test-Path "$($LogFile)"))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".json" ))
{
    Write-Host "[Error] No JSON File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($LogFile)
Write-Output "[Info]  Processing KnockKnock Findings ($FileName) ..."

# MD5 Hash
$MD5 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm MD5).Hash
Write-Output "[Info]  MD5 Hash: $MD5"

# SHA1 Hash
$SHA1 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm SHA1).Hash
Write-Output "[Info]  SHA1 Hash: $SHA1"

# SHA256 Hash
$SHA256 = (Get-FileHash -LiteralPath "$LogFile" -Algorithm SHA256).Hash
Write-Output "[Info]  SHA256 Hash: $SHA256"

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of JSON (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing KnockKnock Findings (KnockKnock_Results_yyyy-MM-dd.json)
New-Item "$OUTPUT_FOLDER\KnockKnock\JSON" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\KnockKnock\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\KnockKnock\XLSX" -ItemType Directory -Force | Out-Null

# Check for KnockKnock Pretty Format
if ($Count -eq "1")
{
    # Check for KnockKnock Verbose Information (Detailed Report)
    if (Get-Content "$LogFile" | Select-String -Pattern "Starting KnockKnock scan..." -CaseSensitive -Quiet)
    {
        # Import JSON (from last line)
        $Data = Get-Content "$LogFile" -Tail 1 | ConvertFrom-Json
        $JSON = Get-Content "$LogFile" -Tail 1
    }
    else
    {
        # Import JSON
        $Data = Get-Content "$LogFile" | ConvertFrom-Json
        $JSON = Get-Content "$LogFile"
    }
}
else
{
    # Check for KnockKnock Verbose Information (Detailed Report)
    if (Get-Content "$LogFile" | Select-String -Pattern "Starting KnockKnock scan..." -CaseSensitive -Quiet)
    {
        # Import JSON (and exclude Verbose Information)
        $Content = Get-Content "$LogFile" -Raw
        $JSON    = if ($Content -match "{(?s)(.*)") {$Matches[0]}
        $Data    = $JSON | ConvertFrom-Json
    }
    else
    {
        # Import JSON
        $Data = Get-Content "$LogFile" | ConvertFrom-Json
        $JSON = Get-Content "$LogFile"
    }
}

# Total Entries
$Total = $JSON | & $jq 'map(length) | add'
Write-Output "[Info]  $Total Persistent Item(s) found"

# Check if VirusTotal Lookup was enabled
if (Get-Content "$LogFile" | Select-String -Pattern "VT detection" -CaseSensitive -Quiet)
{
    $ExcludeApple = $JSON | & $jq -r 'map(.[] | select(.""signature(s)"" | ."signatureSigner" != "1")) | .[]'
    [int]$FlaggedItems = ($JSON | & $jq -r '.[] | .[] | .""VT detection"" | select( . != null )' | Select-String -Pattern "^0" -NotMatch | Measure-Object).Count
    [int]$UnknownItems = ($ExcludeApple | & $jq -r '.""VT detection""' | Select-String -Pattern "^0/0" | Measure-Object).Count

    if ($FlaggedItems = "0")
    {
        Write-Host "[Info]  $FlaggedItems Flagged Item(s)" -ForegroundColor Green
    }
    else
    {
        Write-Host "[ALERT] $FlaggedItems Flagged Item(s)" -ForegroundColor Red
    }

    Write-Host "[Info]  $UnknownItems Unknown Item(s)" -ForegroundColor Yellow
}
else
{
    Write-Host "[Info]  VirusTotal Results: N/A (Disabled)" -ForegroundColor Yellow
}

# MD5 Hash List
$MD5 = $JSON | & $jq -r '.[] | map(."hashes" | .md5) | .[] | select( . != null )' | Sort-Object -Unique
($MD5 | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\KnockKnock\MD5.txt"
$Count = ($MD5 | Measure-Object).Count
Write-Output "[Info]  $Count MD5 Hashes found ($Total)"

# Check if 'WhitelistedFiles.csv' contains MD5
$Whitelisted=0
foreach ($FileHash in $MD5) {
    if(!($WhitelistedFiles_HashTable.Contains("$FileHash")))
    {
        Write-Output "$FileHash" | Out-File "$OUTPUT_FOLDER\KnockKnock\Unknown_MD5.txt" -Append
    }
    else
    {
        # Whitelist
        # https://github.com/objective-see/KnockKnock/tree/main/WhiteList
        Write-Output "$FileHash" | Out-File "$OUTPUT_FOLDER\KnockKnock\Whitelisted_MD5.txt" -Append
        $Whitelisted++
    }
}

Write-Output "[Info]  $Whitelisted whitelisted MD5 Hashes found ($Count)"

# SHA1 Hash List
($JSON | & $jq -r '.[] | map(."hashes" | .sha1) | .[] | select( . != null )' | Sort-Object -Unique | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\KnockKnock\SHA1.txt"

# SHA256 Hash List
($JSON | & $jq -r '.[] | map(."hashes" | .sha256) | .[] | select( . != null )' | Sort-Object -Unique | Out-String).Trim() | Out-File "$OUTPUT_FOLDER\KnockKnock\SHA256.txt"

# Categories (Overview)
$JSON | & $jq -r 'keys | .[]' | Out-File "$OUTPUT_FOLDER\KnockKnock\Categories.txt" -Encoding UTF8
$Total = ($JSON | & $jq -r 'keys | .[]' | Measure-Object).Count
$Count = ($JSON | & $jq -r 'with_entries(select(.value != [])) | keys | .[]' | Measure-Object).Count
Write-Output "[Info]  $Count Categories found ($Total)"

if ($Total -gt "20")
{
    Write-Host "[Info]  New Category found. Please check!" -ForegroundColor Yellow
}

# KnockKnock v4.0.3
#  1. Authorization Plugins
#  2. Background Managed Tasks
#  3. Browser Extensions
#  4. Cron Jobs
#  5. Dir. Services Plugins
#  6. Dock Tiles Plugins
#  7. Event Rules
#  8. Extensions and Widgets
#  9. Kernel Extensions
# 10. Launch Items
# 11. Library Inserts
# 12. Library Proxies
# 13. Login Items
# 14. Login/Logout Hooks
# 15. Periodic Scripts
# 16. Quicklook Plugins
# 17. Shell Configuration Files
# 18. Spotlight Importers
# 19. Startup Scripts
# 20. System Extensions

# Categories

# JSON
$Data.'Authorization Plugins' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\1-AuthorizationPlugins.json" -Encoding UTF8
$Data.'Background Managed Tasks' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\2-BackgroundManagedTasks.json" -Encoding UTF8
$Data.'Browser Extensions' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\3-BrowserExtensions.json" -Encoding UTF8
$Data.'Cron Jobs' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\4-CronJobs.json" -Encoding UTF8
$Data.'Dir. Services Plugins' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\5-DirectoryServicesPlugins.json" -Encoding UTF8
$Data.'Dock Tiles Plugins' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\6-DockTilesPlugins.json" -Encoding UTF8
$Data.'Event Rules' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\7-EventRules.json" -Encoding UTF8
$Data.'Extensions and Widgets' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\8-ExtensionsWidgets.json" -Encoding UTF8
$Data.'Kernel Extensions' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\9-KernelExtensions.json" -Encoding UTF8
$Data.'Launch Items' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\10-LaunchItems.json" -Encoding UTF8
$Data.'Library Inserts' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\11-LibraryInserts.json" -Encoding UTF8
$Data.'Library Proxies' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\12-LibraryProxies.json" -Encoding UTF8
$Data.'Login Items' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\13-LoginItems.json" -Encoding UTF8
$Data.'Login/Logout Hooks' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\14-LoginLogoutHooks.json" -Encoding UTF8
$Data.'Periodic Scripts' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\15-PeriodicScripts.json" -Encoding UTF8
$Data.'Quicklook Plugins' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\16-QuicklookPlugins.json" -Encoding UTF8
$Data.'Shell Configuration Files' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\17-ShellConfigurationFiles.json" -Encoding UTF8
$Data.'Spotlight Importers' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\18-SpotlightImporters.json" -Encoding UTF8
$Data.'Startup Scripts' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\19-StartupScripts.json" -Encoding UTF8
$Data.'System Extensions' | ConvertTo-Json -Depth 5 | Out-File "$OUTPUT_FOLDER\KnockKnock\JSON\20-SystemExtensions.json" -Encoding UTF8

# Stats
if ($PSEdition -eq "Core")
{
    $AuthorizationPlugins     = $JSON | & $jq '."Authorization Plugins" | length'
    $BackgroundManagedTasks   = $JSON | & $jq '."Background Managed Tasks" | length'
    $BrowserExtensions        = $JSON | & $jq '."Browser Extensions" | length'
    $CronJobs                 = $JSON | & $jq '."Cron Jobs" | length'
    $DirectoryServicesPlugins = $JSON | & $jq '."Dir. Services Plugins" | length'
    $DockTilesPlugins         = $JSON | & $jq '."Dock Tiles Plugins" | length'
    $EventRules               = $JSON | & $jq '."Event Rules" | length'
    $ExtensionsWidgets        = $JSON | & $jq '."Extensions and Widgets" | length'
    $KernelExtensions         = $JSON | & $jq '."Kernel Extensions" | length'
    $LaunchItems              = $JSON | & $jq '."Launch Items" | length'
    $LibraryInserts           = $JSON | & $jq '."Library Inserts" | length'
    $LibraryProxies           = $JSON | & $jq '."Library Proxies" | length'
    $LoginItems               = $JSON | & $jq '."Login Items" | length'
    $LoginLogoutHooks         = $JSON | & $jq '."Login/Logout Hooks" | length'
    $PeriodicScripts          = $JSON | & $jq '."Periodic Scripts" | length'
    $QuicklookPlugins         = $JSON | & $jq '."Quicklook Plugins" | length'
    $ShellConfigurationFiles  = $JSON | & $jq '."Shell Configuration Files" | length'
    $SpotlightImporters       = $JSON | & $jq '."Spotlight Importers" | length'
    $StartupScripts           = $JSON | & $jq '."Startup Scripts" | length'
    $SystemExtensions         = $JSON | & $jq '."System Extensions" | length'
}
else
{
    $AuthorizationPlugins     = $JSON | & $jq '.""Authorization Plugins"" | length'
    $BackgroundManagedTasks   = $JSON | & $jq '.""Background Managed Tasks"" | length'
    $BrowserExtensions        = $JSON | & $jq '.""Browser Extensions"" | length'
    $CronJobs                 = $JSON | & $jq '.""Cron Jobs"" | length'
    $DirectoryServicesPlugins = $JSON | & $jq '.""Dir. Services Plugins"" | length'
    $DockTilesPlugins         = $JSON | & $jq '.""Dock Tiles Plugins"" | length'
    $EventRules               = $JSON | & $jq '.""Event Rules"" | length'
    $ExtensionsWidgets        = $JSON | & $jq '.""Extensions and Widgets"" | length'
    $KernelExtensions         = $JSON | & $jq '.""Kernel Extensions"" | length'
    $LaunchItems              = $JSON | & $jq '.""Launch Items"" | length'
    $LibraryInserts           = $JSON | & $jq '.""Library Inserts"" | length'
    $LibraryProxies           = $JSON | & $jq '.""Library Proxies"" | length'
    $LoginItems               = $JSON | & $jq '.""Login Items"" | length'
    $LoginLogoutHooks         = $JSON | & $jq '.""Login/Logout Hooks"" | length'
    $PeriodicScripts          = $JSON | & $jq '.""Periodic Scripts"" | length'
    $QuicklookPlugins         = $JSON | & $jq '.""Quicklook Plugins"" | length'
    $ShellConfigurationFiles  = $JSON | & $jq '.""Shell Configuration Files"" | length'
    $SpotlightImporters       = $JSON | & $jq '.""Spotlight Importers"" | length'
    $StartupScripts           = $JSON | & $jq '.""Startup Scripts"" | length'
    $SystemExtensions         = $JSON | & $jq '.""System Extensions"" | length'
}

Write-Output ""
Write-Output "[Info]  Authorization Plugins:      $AuthorizationPlugins"
Write-Output "[Info]  Background Managed Tasks:   $BackgroundManagedTasks"
Write-Output "[Info]  Browser Extensions:         $BrowserExtensions"
Write-Output "[Info]  Cron Jobs:                  $CronJobs"
Write-Output "[Info]  Directory Services Plugins: $DirectoryServicesPlugins"
Write-Output "[Info]  Dock Tiles Plugins:         $DockTilesPlugins"
Write-Output "[Info]  Event Rules:                $EventRules"
Write-Output "[Info]  Extensions and Widgets:     $ExtensionsWidgets"
Write-Output "[Info]  Kernel Extensions:          $KernelExtensions"
Write-Output "[Info]  Launch Items:               $LaunchItems"
Write-Output "[Info]  Library Inserts:            $LibraryInserts"
Write-Output "[Info]  Library Proxies:            $LibraryProxies"
Write-Output "[Info]  Login Items:                $LoginItems"
Write-Output "[Info]  Login/Logout Hooks:         $LoginLogoutHooks"
Write-Output "[Info]  Periodic Scripts:           $PeriodicScripts"
Write-Output "[Info]  Quicklook Plugins:          $QuicklookPlugins"
Write-Output "[Info]  Shell Configuration Files:  $ShellConfigurationFiles"
Write-Output "[Info]  Spotlight Importers:        $SpotlightImporters"
Write-Output "[Info]  Startup Scripts:            $StartupScripts"
Write-Output "[Info]  System Extensions:          $SystemExtensions"

# Signature Signer --> Tells you "who signed it".
$SignerKeys = @{
    0 = "None"
    1 = "Apple"
    2 = "App Store"
    3 = "Developer ID"
    4 = "AdHoc"
}

# Signature Status --> Tells you if the code signing checks passed. A non-zero value will be the error returned by the OS.
# Note: Check Unknown Error Code --> https://www.osstatus.com/
# https://eclecticlight.co/2022/09/17/how-to-check-an-apps-signature/
$StatusKeys = @{
         0 = "Valid"                   # Error Name
    -67007 = "WeakResourceEnvelope"    # errSecCSWeakResourceEnvelope
    -67008 = "UnsealedFrameworkRoot"   # errSecCSUnsealedFrameworkRoot
    -67013 = "WeakResourceRules"       # errSecCSWeakResourceRules
    -67021 = "BadNestedCode"           # errSecCSBadNestedCode
    -67023 = "ResourceDirectoryFailed" # errSecCSResourceDirectoryFailed
    -67028 = "BadBundleFormat"         # errSecCSBadBundleFormat
    -67029 = "NoMainExecutable"        # errSecCSNoMainExecutable
    -67030 = "InfoPlistFailed"         # errSecCSInfoPlistFailed
    -67049 = "BadObjectFormat"         # errSecCSBadObjectFormat
    -67050 = "RequirementsFailed"      # errSecCSReqFailed
    -67051 = "RequirementsUnsupported" # errSecCSReqUnsupported
    -67052 = "RequirementsInvalid"     # errSecCSReqInvalid
    -67053 = "ResourceRulesInvalid"    # errSecCSResourceRulesInvalid
    -67054 = "BadResource"             # errSecCSBadResource
    -67055 = "ResourcesInvalid"        # errSecCSResourcesInvalid
    -67056 = "ResourcesNotFound"       # errSecCSResourcesNotFound
    -67057 = "ResourcesNotSealed"      # errSecCSResourcesNotSealed
    -67058 = "BadDictionaryFormat"     # errSecCSBadDictionaryFormat
    -67059 = "Unsupported"             # errSecCSSignatureUnsupported
    -67060 = "NotVerifiable"           # errSecCSSignatureNotVerifiable
    -67061 = "Invalid"                 # errSecCSSignatureFailed
    -67062 = "Unsigned"                # errSecCSUnsigned
    -67072 = "Unimplemented"           # errSecCSUnimplemented
}

# Signature Flags --> Code Signing Attributes (CodeSignAttrs)
# https://docs.hdoc.io/hdoc/llvm-project/e9A2AC4ABC3B174A7.html
# https://newosxbook.com/code/xnu-3789.70.16/bsd/sys/codesign.h
[Flags()] enum SignatureFlags
{
    CS_VALID                  = 1          # dynamically valid
    CS_ADHOC                  = 2          # ad hoc signed
    CS_GET_TASK_ALLOW         = 4          # has get-task-allow entitlement
    CS_INSTALLER              = 8          # has installer entitlement
    CS_FORCED_LV              = 16
    CS_INVALID_ALLOWED        = 32
    CS_HARD                   = 256        # don't load invalid pages
    CS_KILL                   = 512        # kill process if it becomes invalid
    CS_CHECK_EXPIRATION       = 1024       # force expiration checking
    CS_RESTRICT               = 2048       # tell dyld to treat restricted
    CS_ENFORCEMENT            = 4096       # require enforcement
    CS_REQUIRE_LV             = 8192       # require library validation
    CS_ENTITLEMENTS_VALIDATED = 16384      # code signature permits restricted entitlements
    CS_NVRAM_UNRESTRICTED     = 32768
    CS_RUNTIME                = 65536
    CS_LINKER_SIGNED          = 131072
    CS_ALLOWED_MACHO          = 212738
    CS_EXEC_SET_HARD          = 1048576    # set CS_HARD on any exec'ed process
    CS_EXEC_SET_KILL          = 2097152    # set CS_KILL on any exec'ed process
    CS_EXEC_SET_ENFORCEMENT   = 4194304    # set CS_ENFORCEMENT on any exec'ed process
    CS_EXEC_INHERIT_SIP       = 8388608    # set CS_INSTALLER on any exec'ed process
    CS_KILLED                 = 16777216   # was killed by kernel for invalidity
    CS_DYLD_PLATFORM          = 33554432   # dyld used to load this is a platform binary
    CS_PLATFORM_BINARY        = 67108864   # this is a platform binary
    CS_PLATFORM_PATH          = 134217728  # platform binary by the fact of path
    CS_DEBUGGED               = 268435456  # process is currently or has previously been debugged and allowed to run with invalid pages
    CS_SIGNED                 = 536870912  # process has a signature (may have gone invalid)
    CS_DEV_CODE               = 1073741824 # code is dev signed, cannot be loaded into prod signed code
}

#############################################################################################################################################################################################

# CSV / XLSX

# Check if VirusTotal Lookup was enabled
if (Get-Content "$LogFile" | Select-String -Pattern "VT detection" -CaseSensitive -Quiet)
{
    # 1. Authorization Plugins
    $Records = $Data.'Authorization Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $SignatureAuthorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\1-AuthorizationPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Authorization Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 2. Background Managed Tasks
    $Records = $Data.'Background Managed Tasks'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes                = $Record | Select-Object -ExpandProperty hashes
        $Signatures            = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities  = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\2-BackgroundManagedTasks.xlsx" -NoNumberConversion * -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Background Managed Tasks" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["D:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }

    # 3. Browser Extensions
    $Records = $Data.'Browser Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Line = [PSCustomObject]@{
        "Name"       = $Record.name
        "Path"       = $Record.path
        "Identifier" = $Record.identifier
        "Details"    = $Record.details
        "Browser"    = $Record.browser
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\3-BrowserExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-E
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # 4. Cron Jobs
    $Records = $Data.'Cron Jobs'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Line = [PSCustomObject]@{
        "Command"= $Record.command
        "File"   = $Record.file
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\4-CronJobs.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Cron Jobs" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            }
        }
    }

    # 5. Directory Services Plugins
    # TODO

    # 6. Dock Tiles Plugins
    $Records = $Data.'Dock Tiles Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq 0)
        {
            $Flags = "Not Signed"
        }
        else
        {
            $Flags = [SignatureFlags] $Signatures.signingFlags
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\6-DockTilesPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Dock Tiles Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 7. Event Rules
    # TODO

    # 8. Extensions and Widgets
    $Records = $Data.'Extensions and Widgets'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq 0)
        {
            $Flags = "Not Signed"
        }
        else
        {
            $Flags = [SignatureFlags] $Signatures.signingFlags
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\8-ExtensionsWidgets.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Extensions and Widgets" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }

    # 9. Kernel Extensions
    $Records = $Data.'Kernel Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if($Signatures.signingFlags)
        {
            if ($Signatures.signingFlags -eq 0)
            {
                $Flags = "Not Signed"
            }
            else
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
        }
        else
        {
            $Flags = "N/A"
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\9-KernelExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kernel Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }

    # 10. Launch Items
    $Records = $Data.'Launch Items'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = ""
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\10-LaunchItems.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Launch Items" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["D:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }

    # 11. Library Inserts
    # TODO

    # 12. Library Proxies
    # TODO

    # 13. Login Items
    $Records = $Data.'Login Items'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = ""
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\13-LoginItems.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Login Items" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }

    # 14. Login/Logout Hooks
    # TODO

    # 15. Periodic Scripts
    $Records = $Data.'Periodic Scripts'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signature Status"      = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\15-PeriodicScripts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Periodic Scripts" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-H
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            }
        }
    }

    # 16. Quicklook Plugins
    $Records = $Data.'Quicklook Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = ""
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\16-QuicklookPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Quicklook Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 17. Shell Configuration Files
    $Records = $Data.'Shell Configuration Files'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"       = $Record.name
        "Path"       = $Record.path
        "Plist"      = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"        = $Hashes.md5
        "SHA1"       = $Hashes.sha1
        "SHA256"     = $Hashes.sha256
        "VirusTotal" = $Record."VT detection"
        "Error Code" = $Signatures.signatureStatus
        "Error Name" = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\17-ShellConfigurationFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shell Configuration Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-I
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:I"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Status Description
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -FontColor Red
            }
        }
    }

    # 18. Spotlight Importers
    $Records = $Data.'Spotlight Importers'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = ""
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\18-SpotlightImporters.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Spotlight Importers" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 19. Startup Scripts
    $Records = $Data.'Startup Scripts'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signature Status"      = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\19-StartupScripts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Startup Scripts" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-H
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            }
        }
    }

    # 20. System Extensions
    $Records = $Data.'System Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = ""
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "VirusTotal"            = $Record."VT detection"
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\20-SystemExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "System Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-L
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:L"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - VirusTotal
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' '(ISERROR(FIND("0/",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0/",$G1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$H1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$H1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$I1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$K1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$K1)))' -BackgroundColor $Orange
            }
        }
    }
}
else
{
    # VirusTotal Results: N/A (Disabled)

    # 1. Authorization Plugins
    $Records = $Data.'Authorization Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\1-AuthorizationPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\1-AuthorizationPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Authorization Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$I1)))' -BackgroundColor $Orange
            }
        }
    }

    # 2. Background Managed Tasks
    $Records = $Data.'Background Managed Tasks'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes                = $Record | Select-Object -ExpandProperty hashes
        $Signatures            = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities  = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\2-BackgroundManagedTasks.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\2-BackgroundManagedTasks.xlsx" -NoNumberConversion * -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Background Managed Tasks" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["D:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 3. Browser Extensions
    $Records = $Data.'Browser Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Line = [PSCustomObject]@{
        "Name"       = $Record.name
        "Path"       = $Record.path
        "Identifier" = $Record.identifier
        "Details"    = $Record.details
        "Browser"    = $Record.browser
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\3-BrowserExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\3-BrowserExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-E
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # 4. Cron Jobs
    $Records = $Data.'Cron Jobs'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Line = [PSCustomObject]@{
        "Command"= $Record.command
        "File"   = $Record.file
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\4-CronJobs.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\4-CronJobs.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Cron Jobs" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            }
        }
    }

    # 5. Directory Services Plugins
    # TODO

    # 6. Dock Tiles Plugins
    $Records = $Data.'Dock Tiles Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\6-DockTilesPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\6-DockTilesPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Dock Tiles Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$I1)))' -BackgroundColor $Orange
            }
        }
    }

    # 7. Event Rules
    # TODO

    # 8. Extensions and Widgets
    $Records = $Data.'Extensions and Widgets'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq 0)
        {
            $Flags = "Not Signed"
        }
        else
        {
            $Flags = [SignatureFlags] $Signatures.signingFlags
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\8-ExtensionsWidgets.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\8-ExtensionsWidgets.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Extensions and Widgets" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 9. Kernel Extensions
    $Records = $Data.'Kernel Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if($Signatures.signingFlags)
        {
            if ($Signatures.signingFlags -eq 0)
            {
                $Flags = "Not Signed"
            }
            else
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
        }
        else
        {
            $Flags = "N/A"
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\9-KernelExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\9-KernelExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Kernel Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 10. Launch Items
    $Records = $Data.'Launch Items'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\10-LaunchItems.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\10-LaunchItems.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Launch Items" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and D-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["D:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 11. Library Inserts
    # TODO

    # 12. Library Proxies
    # TODO

    # 13. Login Items
    $Records = $Data.'Login Items'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\13-LoginItems.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\13-LoginItems.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Login Items" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }

    # 14. Login/Logout Hooks
    # TODO

    # 15. Periodic Scripts
    $Records = $Data.'Periodic Scripts'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signature Status"      = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\15-PeriodicScripts.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\15-PeriodicScripts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Periodic Scripts" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-G
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:H"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$G1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$G1)))' -BackgroundColor Red
            }
        }
    }

    # 16. Quicklook Plugins
    $Records = $Data.'Quicklook Plugins'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\16-QuicklookPlugins.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\16-QuicklookPlugins.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Quicklook Plugins" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-J
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$I1)))' -BackgroundColor $Orange
            }
        }
    }

    # 17. Shell Configuration Files
    $Records = $Data.'Shell Configuration Files'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"       = $Record.name
        "Path"       = $Record.path
        "Plist"      = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"        = $Hashes.md5
        "SHA1"       = $Hashes.sha1
        "SHA256"     = $Hashes.sha256
        "Error Code" = $Signatures.signatureStatus
        "Error Name" = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\17-ShellConfigurationFiles.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\17-ShellConfigurationFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shell Configuration Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-I
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:I"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Error Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -FontColor Red
            }
        }
    }

    # 18. Spotlight Importers
    $Records = $Data.'Spotlight Importers'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\18-SpotlightImporters.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\18-SpotlightImporters.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Spotlight Importers" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange        
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$H1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$H1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$I1)))' -BackgroundColor $Orange
            }
        }
    }

    # 19. Startup Scripts
    $Records = $Data.'Startup Scripts'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signature Status"      = $Status
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\19-StartupScripts.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\19-StartupScripts.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Startup Scripts" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-G
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:G"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$G1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$G1)))' -BackgroundColor Red
            }
        }
    }

    # 20. System Extensions
    $Records = $Data.'System Extensions'
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Records)
    {
        $Hashes               = $Record | Select-Object -ExpandProperty hashes
        $Signatures           = $Record | Select-Object -ExpandProperty "signature(s)"
        $SignatureAuthorities = ($Signatures | Select-Object -ExpandProperty signatureAuthorities -ErrorAction SilentlyContinue) -join ", "

        # Flags
        if ($Signatures.signingFlags -eq "0")
        {
            $Flags = "0"
        }
        else
        {
            if ($Signatures.signingFlags)
            {
                $Flags = [SignatureFlags] $Signatures.signingFlags
            }
            else
            {
                $Flags = "Not Signed"
            }
        }

        # IsNotarized
        if ($Signatures.notarized -eq "True")
        {
            $IsNotarized = "True"
        }
        else
        {
            $IsNotarized = "False"
        }

        # Status
        if($StatusKeys.ContainsKey($Signatures.signatureStatus))
        {
            $Status = $StatusKeys[$Signatures.signatureStatus]
        }
        else
        {
            $Status = "Unknown"
        }

        # Signer
        if ($Signatures.signatureSigner)
        {
            if($SignerKeys.ContainsKey($Signatures.signatureSigner))
            {
                $Signer = $SignerKeys[$Signatures.signatureSigner]
            }
            else
            {
                $Signer = "Unknown"
            }
        }
        else
        {
            $Signer = "N/A"
        }

        # Identifier
        if($Signatures.signatureIdentifier)
        {
            $Identifier = $Signatures.signatureIdentifier
        }
        else
        {
            $Identifier = "N/A"
        }

        # Authorities
        if($SignatureAuthorities)
        {
            $Authorities = $SignatureAuthorities
        }
        else
        {
            $Authorities = "N/A"
        }

        $Line = [PSCustomObject]@{
        "Name"                  = $Record.name
        "Path"                  = $Record.path
        "Plist"                 = $Record.plist | ForEach-Object { $_.Replace("n/a","N/A") }
        "MD5"                   = $Hashes.md5
        "SHA1"                  = $Hashes.sha1
        "SHA256"                = $Hashes.sha256
        "Signing Flags"         = $Flags
        "IsNotarized"           = $IsNotarized
        "Signature Status"      = $Status
        "Signature Signer"      = $Signer
        "Signature Identifier"  = $Identifier
        "Signature Authorities" = $Authorities 
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv")
    {
        if(Test-Csv -Path "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -MaxLines 2)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\KnockKnock\CSV\20-SystemExtensions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\KnockKnock\XLSX\20-SystemExtensions.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "System Extensions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:L1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-A and C-K
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:K"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Signing Flags
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Not Signed",$G1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CS_ADHOC",$G1)))' -BackgroundColor $Orange
            # ConditionalFormatting - IsNotarized
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$H1)))' -BackgroundColor $Green
            # ConditionalFormatting - Signature Status
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Valid",$I1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Unsigned",$I1)))' -BackgroundColor Red
            # ConditionalFormatting - Signing Signer
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Apple",$J1)))' -BackgroundColor $Green
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AdHoc",$J1)))' -BackgroundColor $Orange
            }
        }
    }
}

# Categories

# 1. Authorization Plugins
# These are libraries that can be used to customize or extend the login experience. You can read more about them in Apple's "Extending authorization services with plug-ins" document.
# https://developer.apple.com/documentation/security/extending-authorization-services-with-plug-ins?

# 2. Background Managed Tasks
# Recently Apple has begun to organize disparate persistence items into a central database. Items in this database include login items, launch agents, launch daemons, and more. Collectively they are referred to as "Background Managed Tasks". You can learn all about Background Managed Task in Demystifying macOS's Background Task Management".

# 3. Browser Extensions
# These are programs or add-ons designed to extend the functionality of web browsers. Generally they are hosted by the browser. You're probably familiar with ad blockers, which run as browser extensions.

# 4. Cron Jobs
# Cron jobs are scheduled tasks executed automatically at specified intervals. They are commonly used for automating repetitive tasks, such as backups, updates, or running scripts, based on time-based schedules defined in a crontab file.

# 5. Directory Service Plugins
# These plugins, used by the Directory Services framework enable macOS to interact with various directory services or authentication systems. These plugins facilitate communication between macOS and external directory servers, such as Active Directory, LDAP, or local authentication systems, providing functionalities like user authentication, group management, and centralized directory lookups. By using plugins, macOS supports a wide range of directory service protocols, enabling seamless integration with diverse network environments.

# 6. Dock Tile Plugins
# Dock tile plugins allow applications to enhance their Dock tile with dynamic content or custom interactions. They provide a way to display additional information or controls directly on the app's Dock icon, such as live status updates, progress indicators, or interactive elements.

# 7. Event Rules
# Event rules in macOS, managed by the Event Monitor Daemon (emond), are a mechanism for responding to specific system events based on predefined rules. The emond daemon watches for events, such as file system changes, system log messages, or other system activity, and executes corresponding actions when those events match the criteria defined in rule files.
# As of macOS Ventura (13), emond has been removed from the operating system.

# 8. Extensions and Widgets
# Extensions and Widgets are modular components packaged as *.appex bundles within an app. They provide additional functionality or user-facing features that integrate seamlessly into the macOS environment (for example, as "Finder Syncs"), enhancing system-wide or app-specific capabilities.

# 9. Kernel Extensions
# Known as KEXTs, these run in the kernel space to extend or modify the core functionality of the macOS kernel (XNU). They allow developers to interact directly with hardware or system resources, providing features such as device drivers, file systems, or security tools. On recent versions of macOS, 3rd-party KEXTs have largely been deprecated.

# 10. Launch Items
# Launch Items are programs that can be started automatically at boot, login, or based on specific conditions. They include Launch Agents and Launch Daemons, which are managed by the macOS launchd system. Launch items are one of the most popular ways that legitimate software (and malware!) persists.

# 11. Library Inserts
# In order to inject code into unprotected applications, the DYLD_INSERT_LIBRARIES environmental variable can be (ab)used. This approach can also be abused to gain persistence (assuming the targeted program is either automatically or often launched). Rarely are inserted libraries legitimate.

# 12. Library Proxies
# To subvert applications and to gain persistence (assuming the targeted item is either automatically or often launched), libraries can be planted that forward their exports to a legitimate library. You can learn more about this approach in "Dylib hijacking on OS X"
# https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x

# 13. Login Items
# Login Items on macOS are applications or scripts configured to automatically launch when a user logs in. In the context of persistence, they are often used by legitimate apps and malware alike to ensure they run every time the user logs in.

# 14. Login/Logout Hooks
# Via a login or logout hook, a scripts can be set to execute automatically when a user logs in or out. They were traditionally used for system management tasks like setting up environments or cleaning temporary files. They have been deprecated in modern macOS versions due to security concerns and are largely replaced by Launch Agents and Launch Daemons.

# 15. Periodic Scripts
# These are legacy Unix-style scripts that can be specified to run regular intervals (daily, weekly, or monthly) using the periodic subsystem. They are executed automatically by the system at the specified intervals, typically for maintenance tasks like cleaning logs or rotating files. While still supported, Launch Daemons and launchd have largely replaced periodic scripts for more flexible and precise scheduling.

# 16. Quicklook Plugins
# Quicklook Plugins are extensions that enable Finder and other macOS applications to generate previews for specific file types without opening them. These plugins allow users to see a quick preview of a file's content by pressing the spacebar or using the Quick Look feature in Finder. Though largely used by legitimate software, they could be (ab)used by malware as a means to gain persistence.

# 17. Shell Configuration Files
# Shell configuration files such as ~/.zshrc are parsed each time the shell starts, and any commands they contain are automatically executed. Malware is known to add extra commands to these files to maintain persistence via the shell.

# 18. Spotlight Importers
# Spotlight Importers are plugins (.mdimporter files) that enable the Spotlight 'search engine' to index and search the contents of specific file types. They extract metadata from non-standard or proprietary file formats, making them searchable through Spotlight and accessible via Finder's search functionality. Though largely used by legitimate software, they could be used and abused by malware as a means to gain persistence.

# 19. Startup Scripts
# Several rc.* script files located in /etc are automatically executed by macOS when the system starts. Malware could potentially add extra commands to these scripts to maintain persistence.

# 20. System Extensions
# System Extensions are the replacements for legacy kernel extensions (KEXTs), running in user space for improved security and stability. They enable developers to extend system functionality, such as network filtering or endpoint security, without requiring direct access to the kernel. Though unlikely, malware may be able to install a malicious System Extension that is automatically started, thus gaining persistence.

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 0.5

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region VirusTotal

# VirusTotal Lookup

# Check if VirusTotal Lookup is skipped
if (!($skipVT.IsPresent))
{
    $Title   = "VirusTotal-Analyzer"
    $Prompt  = "Do you want to check the item hashes on VirusTotal?"
    $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
    $Default = 0

    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)

    switch($Choice)
    {
        # Yes
	    0 {
            # Check if MD5 Hash List exists
            if (Test-Path "$OUTPUT_FOLDER\KnockKnock\MD5.txt")
            {
                # Check if MD5 Hash List is nor empty
                if ((Get-Item "$OUTPUT_FOLDER\KnockKnock\MD5.txt").Length -gt 0kb)
                {
                    if (Test-Path "$PSScriptRoot\VirusTotal-Analyzer.ps1")
                    {
                        New-Item "$OUTPUT_FOLDER\VirusTotal" -ItemType Directory -Force | Out-Null
                        & "$PSScriptRoot\VirusTotal-Analyzer.ps1" -Path "$OUTPUT_FOLDER\KnockKnock\MD5.txt" -OutputDir "$OUTPUT_FOLDER\VirusTotal"
                    }
                }
            }
	    }

	    # No
	    1 {
            Exit
	    }
    }
}

#endregion VirusTotal

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbKl4oSpx4HvmTei5SIM257Bg
# clKggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQw
# DQYJKoZIhvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBD
# QSBSMzYwHhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQG
# EwJHQjEXMBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBT
# aWduZXIgUjM2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6k
# U3jyPRBLeBIHPNyUgVNnYayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5J
# IjKNf75QBha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc
# 6BbsNBzjHTt7FngNfhfJoYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5
# tJD92iFAIbKHQWGbCQNYplqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe
# 60vzvrk0HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D
# 40GofV7O8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH
# 0MmGzlBUylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcm
# YaOBZKlwPP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw
# 3lHACnLilGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0
# KdRZHPcuSL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVb
# ySnXnkujjhIh+oaatsk/oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQY
# MBaAFF9Y7UwxeqJhQo1SgLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx
# 0Iz9LALOTzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8E
# DDAKBggrBgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsG
# AQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0f
# BEMwQTA/oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# VGltZVN0YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcw
# AoY5aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1w
# aW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNv
# bTANBgkqhkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu
# 6r7vmzXXLpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrus
# Dh9NgYwiGDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM
# 4WXA3ZHcNHB4V42zi7Jk3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQX
# PgMqvzodgQJEkxaION5XRCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0M
# Ot3ccgwn4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jO
# Q66Fhk3NWbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ0
# 26JxHhr2fuJ0mV68AluFr9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWw
# i4hmpylUfygtYLEdLQukNEX1jiOKMIIGazCCBNOgAwIBAgIRAIxBnpO/K86siAYo
# O3YZvTwwDQYJKoZIhvcNAQEMBQAwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1Nl
# Y3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWdu
# aW5nIENBIFIzNjAeFw0yNDExMTQwMDAwMDBaFw0yNzExMTQyMzU5NTlaMFcxCzAJ
# BgNVBAYTAkRFMRYwFAYDVQQIDA1OaWVkZXJzYWNoc2VuMRcwFQYDVQQKDA5NYXJ0
# aW4gV2lsbGluZzEXMBUGA1UEAwwOTWFydGluIFdpbGxpbmcwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQDRn27mnIzB6dsJFLMexQQNRd8aMv73DTla68G6
# Q8u+V2TY1JQ/Z4j2oCI9ATW3K3P7NAPdlE0QmtdjC0F/74jsfil/i8LwxuyT034w
# abViZKUcodmKsEFhM9am8W5kUgLuC5FIK4wNOq5TfzYdHTyJu1eR2XuSDoMp0wg4
# 5mOuFNBbYB8DVBtHxobvWq4eCs3lUxX07wR3Qr2Utb92w8eU2vKr2Ss9xIh/YvM4
# UxgBpO1I6O+W2tAB5mmynIgoCfX7mu6iD3A+AhpQ9Gv209G83y8FPrFJIWU77TTe
# hErbPjZ074xXwrlEkhnGUCk1w+KiNtZHaSn0X+vnhqJ7otBxQZQAESlhWXpDKCun
# nnVnVgwvVWtccAhxZO95eif6Vss/UhCaBZ26szlneGtFeTClI4+k3mqfWuodtXjH
# c8ohAclWp7XVywliwhCFEsAcFkpkCyivey0sqEfrwiMnRy1elH1S37XcQaav5+bt
# 4KxtIXuOVEx3vM9MHdlraW0y1on5E8i4tagdI45TH0LU080ubc2MKqq6ZXtplTu1
# wdF2Cgy3hfSSLkJscRWApvpvOO6Vtc4jTG/AO6iqN5M6Swd+g40XtsxBD/gSk9kM
# qkgJ1pD1Gp5gkHnP1veut+YgJ9xWcRDJI7vcis9qsXwtVybeOCh56rTQvC/Tf6BJ
# tiieEQIDAQABo4IBszCCAa8wHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhek
# zQwwHQYDVR0OBBYEFIxyZAmEHl7uAfEwbB4nzI8MCCLbMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEw
# NQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5j
# b20vQ1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNl
# Y3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5Bggr
# BgEFBQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20v
# U2VjdGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdo
# dHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAoBgNVHREEITAfgR1td2lsbGluZ0BsZXRo
# YWwtZm9yZW5zaWNzLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAZ0dBMMwluWGb+MD1
# rGWaPtaXrNZnlZqOZxgbdrMLBKAQr0QGcILCVIZ4SZYaevT5yMR6jFGSAjgaFtnk
# 8ZpbtGwig/ed/C/D1Ne8SZyffdtALns/5CHxMnU8ks7ut7dsR6zFD4/bmljuoUoi
# 55W6/XU/1pr+tqRaZGJvjSKJQCN9MhFAvXSpPPqRsj27ze1+KYIBF1/L0BW0HS0d
# 9ZhGSUoEwqMDLpQf2eqJFyyyzWt21VVhLF6mgZ1dE5tCLZY7ERzx6/h5N7F0w361
# oigizMbCMdST29XOc5mB8q6Cye7OmEfM2jByRWa+cd4RycsN2p2wHRukpq48iX+t
# PVKmHwNKf+upuKPDQAeV4J7gUCtevIsOtoyiC2+amimu81o424Dl+NsAyCLz0SXv
# NAhVvtU73H61gtoPa/SWouem2S+bzp7oGvGPop/9mh4CXki6LVeDH3hDM8hZsJg/
# EToIWiDozTc2yWqwV4Ozyd4x5Ix8lckXMgWuyWcxmLK1RmKpMIIGgjCCBGqgAwIB
# AgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4w
# HAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVz
# dCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcN
# MzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJv
# b3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d
# 6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5i
# hkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awq
# KggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqs
# tbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimg
# HUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDo
# I7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDG
# AvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZ
# wZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2
# oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911c
# RxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3g
# EFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaA
# FFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/Q
# Cj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAK
# BggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/
# aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRp
# b25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0
# cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1o
# RLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxto
# LQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdY
# OdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRM
# Ri/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7
# Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9F
# VJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFz
# bSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhO
# Fuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa
# 1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3U
# OTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7P
# o0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8xggYxMIIGLQIBATBpMFQxCzAJBgNV
# BAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzApBgNVBAMTIlNlY3Rp
# Z28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYCEQCMQZ6TvyvOrIgGKDt2Gb08
# MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3
# DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEV
# MCMGCSqGSIb3DQEJBDEWBBQzjESG1GH36r8/9AY0qdtmL7YT1TANBgkqhkiG9w0B
# AQEFAASCAgA+/J996ybh7byAJqF6mqDaURcduP3DSB8xtk7bExJ8EbYS8TflUIZL
# aLB9TJ/eJ9LEjfl1ZLoHa9VzH8TlY1YAB2M4gzzDZ5bwjWJS2Gk+ZAIhV32CM+Oj
# luV4LbP5JiCtQqs0DRh2INdKRmI+Yvz5RM/mO3j70LDe9nomFf35TBKirfNcGzga
# 5meDpyJTw0ubTVyNSGs+uPjPc+n3dRslkqCH6UHRHCKo37pLNvXQx8WUgYXCl/Ih
# IIpbUFhUOYhOBUGwo1L14seWBc6oI+RzG8l1KXc7GZqUKvYOtMUGZ/A7NiA+pXnY
# 9edv0nynVVD+RdwN6H3Bl6kz4NsijWQEquVceI4nd/4RYugyuI6Y5+bQVEN/hnrn
# LOc7BKzBjjjmmvJaRAWFs1ls42nGSkWWy9CujnTz04urTb++GI+V6sK5oK3Is+nT
# dq7WaP0X0mD8Hn8o/yStmgfePFunwLs0bKvwo/sSjgGPta4cNgEiTz4fqy4+1SzN
# Gh/pMG2i5qhYW+ylLF9PDHJSfKunzX+0YU90NqmaCKsaU2bLGkXwSkecPeWHtkQe
# RZRbaVzuotTVPxdRx9prw22RNL0CEWL2rEhqVEuD8SzZB0s4Qb3YKIekMnnUn/rq
# 6/gCvkAni2A2llhQIjrzLtJEhgSA0wTM0nhhhCGLxKm5IuMd5JoOh6GCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDMxNjA2NDUwNFowPwYJKoZIhvcNAQkEMTIEMFIYAS5TezaEzstjKT/yC5NFx9Js
# g8FYDOR/FtqKlhyKHlY2gNKX9uErMXswvCK8zjANBgkqhkiG9w0BAQEFAASCAgA4
# ZHxmrrC37hlbg/2/7qHMbrhOVyqzwlI1jTdJSgdc5/dNLQEpiratDWhBC3hhTGh4
# IR4sxwP0s8/I6JFGJM3H+/MoV/gg1D3R6D8yP5Lw2Zh4vNgVDUWZH0bmRggjjkOV
# kuY45q6PLtAHUJuAO4S1TBW9eJ85wx0GegxDrniCn7TVimxVNZWPBQPGNd5SHzQO
# X24XGCFdrncW3b1w6Svd1dCPRjab2jNQGjEc4KprOHd7q5Fv//wigFcdFUel38Db
# IidUzteqEqxI8yqtT/ds5EwA83VdQJ3FrrvonSLaND0vJY8ia7BRqIT2h9LZbdMZ
# cuUBhoWG/e9Jq/qqRKHlOm6TcFuU2lsZHPj7SSz7C+L8q6v5Qqa5fd9edynMyemr
# yvsf7atPE3qTGIHjIHPwcE08QIff0RDrl8mO7ZuGVINm/WEau/+BK5X1bO/ACJQ7
# viYwhmNbuDtLlIYYzcqZlwulTlzJaD2+6Ask02w2HcokI1JTl26HbXdL3Bz1sUIP
# zfK/G9mE6ZUmzHh4Rp7wROjx4yFz+spSYQwRuQOkz7vjBmELHiZtyRMTt8GacoZj
# vbQJvecrMwF/FUqyS8sGTXmHqqhd7lrEvoKt9E5eRjjfbuNDGmCHTWESMNwr653O
# w7Hz6OujqnzjBZXGQfN9h69WmSMTNLg/pZza77Kp6A==
# SIG # End signature block

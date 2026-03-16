# TCC-Analyzer v0.1
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
# jq v1.7.1 (2023-12-13)
# https://github.com/stedolan/jq
#
# SQLite Tools for Windows v3.50.4 (2025-07-30)
# https://sqlite.org/download.html --> Command-line tools for Windows x64 --> sqlite-tools-win-x64-3500400.zip
#
#
# Changelog:
# Version 0.1
# Release Date: 2025-11-10
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
  TCC-Analyzer v0.1 - Automated Forensic Analysis of macOS TCC database file(s) for DFIR

.DESCRIPTION
  TCC-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the macOS TCC.db.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\TCC-Analyzer".

  Note: The subdirectory 'TCC-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input directory.

.EXAMPLE
  PS> .\TCC-Analyzer.ps1

.EXAMPLE
  PS> .\TCC-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\tcc_<USERNAME>"

.EXAMPLE
  PS> .\TCC-Analyzer.ps1 -Path "H:\macos-collector\Aftermath_Collection\tcc_<USERNAME>" -OutputDir "H:\MacOS-Analyzer-Suite"

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
    [String]$OutputDir
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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\TCC-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\TCC-Analyzer" # Custom
    }
}

# Tools

# jq
$script:jq = "$SCRIPT_DIR\Tools\jq\jq-windows-amd64.exe"

# SQLite3
$script:SQLite3 = "$SCRIPT_DIR\Tools\SQLite\sqlite3.exe"

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
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "TCC-Analyzer v0.1 - Automated Forensic Analysis of macOS TCC database file(s) for DFIR"

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

# Select Log File (TCC.db)
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "TCC Database|tcc_*|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
    }

    $Result = Get-LogFile

    if($Result -eq "OK")
    {
        $script:DatabaseFile = $Result[1]
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:DatabaseFile = $Path
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
Write-Output "TCC-Analyzer v0.1 - Automated Forensic Analysis of macOS TCC database file(s) for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# TCC - Transparency, Consent, and Control (macOS)

# A framework for regulating applications permissions by managing their access to user data.

# TCC Database(s)

# System-wide database
# /Library/Application Support/com.apple.TCC/TCC.db --> global one (root-level)

# User-specific database
# /Users/<username>/Library/Applicatio0n Support/com.apple.TCC/TCC.db (per-user)

# Note: These TCC datbase(s) are protected from editing with SIP (System Integrity Protection), but you can read them by granting your terminal application or editor full disk access.

# Aftermath Source:
# Aftermath_Collection\Aftermath_<SERIAL_NUMBER>.zip\Artifatcs\raw\tcc_<USERNAME>

# Check if Database File exists
if (!(Test-Path "$($DatabaseFile)"))
{
    Write-Host "[Error] $DatabaseFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check Signature (Magic Number)
if ($PSEdition -eq "Core")
{
    $Bytes = (Get-Content -Path $DatabaseFile -AsByteStream -ReadCount 1 -TotalCount 16) # PowerShell 7
}
else
{
    $Bytes = (Get-Content -Path $DatabaseFile -Encoding Byte -ReadCount 1 -TotalCount 16) # PowerShell 5.1
}

$Signature = ([System.BitConverter]::ToString($Bytes)).Replace("-"," ") # SQLite format 3

if (!($Signature -eq "53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00")) # Magic Bytes
{
    Write-Host "[Error] No SQLite3 Database File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if sqlite3.exe exists
if (!(Test-Path "$($SQLite3)"))
{
    Write-Host "[Error] sqlite3.exe NOT found." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($DatabaseFile)
Write-Output "[Info]  Processing Transparency, Consent, and Control Database ($FileName) ..."

# MD5 Hash
$MD5 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm MD5).Hash
Write-Output "[Info]  MD5 Hash: $MD5"

# SHA1 Hash
$SHA1 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm SHA1).Hash
Write-Output "[Info]  SHA1 Hash: $SHA1"

# SHA256 Hash
$SHA256 = (Get-FileHash -LiteralPath "$DatabaseFile" -Algorithm SHA256).Hash
Write-Output "[Info]  SHA256 Hash: $SHA256"

# Input Size
$InputSize = Get-FileSize((Get-Item "$DatabaseFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count Rows of SQLite3 Database (w/ thousands separators)
[int]$Count = (& $SQLite3 -readonly $DatabaseFile 'SELECT COUNT(*) FROM ACCESS')
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing TCC.db
New-Item "$OUTPUT_FOLDER\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null

# ACCESS Table

# CSV
& $SQLite3 -readonly -header -csv $DatabaseFile 'SELECT * FROM ACCESS' | Out-File "$OUTPUT_FOLDER\CSV\Untouched.csv" -Encoding UTF8

# Count columns of 'Untouched.csv' --> Track Changes --> Adjust SQL Query if needed
[int]$Columns = ((Get-Content "$OUTPUT_FOLDER\CSV\Untouched.csv")[1] -split ",").Count
if ($Columns -ne 17)
{
    Write-Host "[Info]  $Columns columns found (17 columns expected). Please check ACCESS Table." -ForegroundColor Red
}

# macOS 15.3.2 = 17 columns

# XLSX
if (Test-Path "$OUTPUT_FOLDER\CSV\Untouched.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\Untouched.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\CSV\Untouched.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\Untouched.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Access" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $ColumnNumber = $WorkSheet.Dimension.End.Column
        $ColumnName = (Get-ExcelColumnName $ColumnNumber).ColumnName
        Set-Format -Address $WorkSheet.Cells["A1:$($ColumnName)1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-Q
        $WorkSheet.Cells["A:$($ColumnName)"].Style.HorizontalAlignment="Center"
        }
    }
}

# SQL Query
$SQL = 
"
SELECT 
	DATETIME(last_modified,'UNIXEPOCH') AS 'Last Modified',
	service AS 'Service',
	client AS 'Name',
	CASE auth_value 
		WHEN 0 THEN 'Denied'
		WHEN 1 THEN 'Unknown'
		WHEN 2 THEN 'Allowed'
		WHEN 3 THEN 'Limited'
        WHEN 4 THEN 'Add Only'
        WHEN 5 THEN 'Single Boot Allowed' -- allowed for a unique boot_uuid
	END AS 'Auth Value',
	CASE auth_reason
        WHEN 0 THEN 'Inherited'
		WHEN 1 THEN 'Error'
		WHEN 2 THEN 'User Consent'
		WHEN 3 THEN 'User Set'
		WHEN 4 THEN 'System Set'
		WHEN 5 THEN 'Service Policy'
		WHEN 6 THEN 'MDM Policy'
		WHEN 7 THEN 'Override Policy'
		WHEN 8 THEN 'Missing Usage String'
		WHEN 9 THEN 'Prompt Timeout'
		WHEN 10 THEN 'Preflight Unknown'
		WHEN 11 THEN 'Entitled'
		WHEN 12 THEN 'App Type Policy'
		END AS 'Auth Reason',
    CASE client_type
        WHEN 0 THEN 'Bundle Identifier'
        WHEN 1 THEN 'Absolute Path'
    END AS 'Client Type'
FROM ACCESS
"

# Execute SQL Query
$Results = @(& $SQLite3 -readonly -separator '**' $DatabaseFile $SQL |
ConvertFrom-String -Delimiter '\u002A\u002A' -PropertyNames "Last Modified","Service","Name","Auth Value","Auth Reason","Client Type")

# CSV
$Output = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Results)
{
    $CreatedDateTime = $Record | Select-Object -ExpandProperty "Last Modified"

    $Line = [PSCustomObject]@{
    "Last Modified" = (Get-Date $CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss") 
    "Service"       = $Record.Service
    "Name"          = $Record.Name
    "Auth Value"    = $Record."Auth Value"
    "Auth Reason"   = $Record."Auth Reason"
    "Client Type"   = $Record."Client Type"
    }

    $Output.Add($Line)
}

$Output | Export-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\CSV\TCC.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_."Last Modified" -as [datetime] } -Descending
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\TCC.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TCC" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-F
        $WorkSheet.Cells["A:F"].Style.HorizontalAlignment="Center"
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\XLSX\TCC.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\XLSX\TCC.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Create HashTable and import 'TCC-Services.csv'
$Services_HashTable = @{}
if (Test-Path "$SCRIPT_DIR\Config\TCC-Services.csv")
{
    if(Test-Csv -Path "$SCRIPT_DIR\Config\TCC-Services.csv" -MaxLines 2)
    {
        Import-Csv "$SCRIPT_DIR\Config\TCC-Services.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $Services_HashTable[$_.Service] = $_.Description,$_.Category }

        # Count Ingested Properties
        $Count = $Services_HashTable.Count
        Write-Output "[Info]  Initializing 'TCC-Services.csv' Lookup Table ($Count) ..."
    }
}

# Extended
if (Test-Path "$OUTPUT_FOLDER\CSV\TCC.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -MaxLines 2)
    {
        $Records = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8

        # CSV
        $Results = [Collections.Generic.List[PSObject]]::new()

        ForEach($Record in $Records)
        {
            # Service
            $Service = $Record.Service

            # Check if HashTable contains Service
            if($Services_HashTable.ContainsKey("$Service"))
            {
                $Description = $Services_HashTable["$Service"][0]
                $Category    = $Services_HashTable["$Service"][1]
            }
            else
            {
                $Description = "Unknown"
                $Category    = "Unknown"
            }

            $Line = [PSCustomObject]@{
                "Last Modified" = $Record."Last Modified" 
                "Service"       = $Record.Service
                "Description"   = $Description
                "Category"      = $Category
                "Name"          = $Record."Name"
                "Auth Value"    = $Record."Auth Value"
                "Auth Reason"   = $Record."Auth Reason"
                "Client Type"   = $Record."Client Type"
            }

            $Results.Add($Line)
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -NoTypeInformation -Encoding UTF8
    }
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -MaxLines 2)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_."Last Modified" -as [datetime] } -Descending
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\TCC-Extended.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TCC" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B, D and F-H
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["D:D"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["F:H"].Style.HorizontalAlignment="Center"
        }
    }
}

# Ckeck for "Unknown" Services
if (Test-Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -MaxLines 2)
    {
        $Unknown = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -Delimiter "," | Where-Object { $_."Service" -eq "Unknown" } | Measure-Object).Count
        if ($Unknown -ge 1)
        {
            Write-Host "[Info]  'Unknown' Service found. Please check and update 'TCC-Services.csv' database." -ForegroundColor Red
        }
    }
}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Statistics

# Stats
New-Item "$OUTPUT_FOLDER\Stats" -ItemType Directory -Force | Out-Null

# Time Frame
$TCC = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_."Last Modified" -as [datetime] }
$LastModified = $TCC | Select-Object "Last Modified"
$StartDateTime = $LastModified | Select-Object -First 1 | Select-Object -ExpandProperty "Last Modified"
$EndDateTime = $LastModified | Select-Object -Last 1 | Select-Object -ExpandProperty "Last Modified"
Write-Output "[Info]  Log data from $StartDateTime UTC until $EndDateTime UTC"

# TCC Permissions
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Select-Object Service | Measure-Object).Count
$Permissions = '{0:N0}' -f $Count
Write-Output "[Info]  $Permissions TCC Permissions found"

# User Consent + Allowed
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object { $_."Auth Reason" -eq "User Consent" } | Measure-Object).Count
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object { $_."Auth Reason" -eq "User Consent" } | Where-Object { $_."Auth Value" -eq "Allowed" } | Measure-Object).Count
Write-Output "[Info]  $Count TCC Permissions allowed by User ($Total)"

# User Consent + Denied
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object { $_."Auth Reason" -eq "User Consent" } | Measure-Object).Count
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object { $_."Auth Reason" -eq "User Consent" } | Where-Object { $_."Auth Value" -eq "Denied" } | Measure-Object).Count
Write-Output "[Info]  $Count TCC Permissions denied by User ($Total)"

# Service (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Select-Object Service | Measure-Object).Count
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Select-Object Service -Unique | Measure-Object).Count
$Service = '{0:N0}' -f $Count
Write-Output "[Info]  $Service TCC Services found ($Total)"

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Group-Object Service | Select-Object @{Name='Service'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Service.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Service" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# Service / Description (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -Delimiter "," | Select-Object Service | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -Delimiter "," | Group-Object Service,Description | Select-Object @{Name='Service'; Expression={ $_.Values[0] }},@{Name='Description'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Service-Extended.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Services" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns C-D
    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
    }
}

# Auth Value (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Select-Object "Auth Value" | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Group-Object "Auth Value" | Select-Object @{Name='Auth Value'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Auth-Value.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Auth Value" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Auth Reason (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Select-Object "Auth Reason" | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Group-Object "Auth Reason" | Select-Object @{Name='Auth Reason'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Auth-Reason.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Auth Reason" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Auth Reason / Auth Value (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object {$_."Auth Reason" -ne ""}| Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8 | Group-Object "Auth Reason","Auth Value" | Select-Object @{Name='Auth Reason'; Expression={ $_.Values[0] }},@{Name='Auth Value'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\AuthReason-AuthValue.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Auth Reason - Auth Value" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    }
}

# Client Type (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Where-Object {$_."Client Type" -ne ""} | Measure-Object).Count

if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," | Group-Object "Client Type" | Select-Object @{Name='Client Type'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\ClientType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Client Type" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Exclude Apple System Processes
$NonApple = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_."Name" -notmatch "^com.apple.*$" }
$Total = ($NonApple | Measure-Object).Count
$Count = ($NonApple | Sort-Object Name -Unique | Measure-Object).Count
Write-Output "[Info]  $Count Third-Party Application(s) found ($Total)"

if ($Total -ge 1)
{
    $NonApple | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\TCC-ThirdParty.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "3rd-Party Apps" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    Set-Format -Address $WorkSheet.Cells["A1:H1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
    # HorizontalAlignment "Center" of columns A-B and D-H
    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["D:H"].Style.HorizontalAlignment="Center"
    }
}

# Permissions Count by Name (Bundle Identifier)
$Stats = Import-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8 | Group-Object "Name" | Select-Object @{Name='Name'; Expression={ $_.Values[0] }},@{Name='Permissions'; Expression={ $_.Count }} | Sort-Object Permissions -Descending
$Stats | Export-Excel -Path "$OUTPUT_FOLDER\Stats\Permissions.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Permissions" -CellStyleSB {
param($WorkSheet)
# BackgroundColor and FontColor for specific cells of TopRow
Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
# HorizontalAlignment "Center" of column B
$WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
# ConditionalFormatting - Permissions requested by Bundle Identifier >= 5
$LastRow = $WorkSheet.Dimension.End.Row
Add-ConditionalFormatting -Address $WorkSheet.Cells["B2:B$LastRow"] -WorkSheet $WorkSheet -RuleType GreaterThan -ConditionValue 4 -BackgroundColor "Red"
}

# Count of Permissions by Name >= 5
[int]$Count = ($Stats | Where-Object { $_."Permissions" -ge "5" } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Application(s) detected: >=5 Application Permissions requested ($Count)" -ForegroundColor Yellow
}

# Bundle Identifier
if (Test-Path "$OUTPUT_FOLDER\CSV\TCC.csv")
{
    if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC.csv" -MaxLines 2)
    {
        New-Item "$OUTPUT_FOLDER\TXT" -ItemType Directory -Force | Out-Null
        $BundleIds = (Import-Csv "$OUTPUT_FOLDER\CSV\TCC.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_."Client Type" -eq "Bundle Identifier" } | Where-Object { $_."Name" -notmatch "^com.apple.*$" } | Select-Object "Name" -Unique | Sort-Object "Name")."Name"
        $BundleIds | Out-File "$OUTPUT_FOLDER\TXT\BundleIds.txt" -Encoding UTF8
    }
}

#endregion Statistics

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region AppStore

Function Get-iTunesInfo {

# iTunes Search API
# https://developer.apple.com/library/archive/documentation/AudioVideo/Conceptual/iTuneSearchAPI/LookupExamples.html
$Total = (Get-Content "$OUTPUT_FOLDER\TXT\BundleIds.txt" | Measure-Object).Count
$BundleIds = Get-Content "$OUTPUT_FOLDER\TXT\BundleIds.txt"

# Internet Connectivity Check
$NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

# Offline
if (!($NetworkListManager -eq "True"))
{
    Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
}

# Online
if ($NetworkListManager -eq "True")
{
    # Check if itunes.apple.com is reachable
    if ((Test-NetConnection -ComputerName itunes.apple.com -Port 443).TcpTestSucceeded)
    {
        # Estimated Time (Average: 12 requests per minute)
        [int]$TotalSeconds = $Total / 0.2
        $TimeSpan = [TimeSpan]::FromSeconds($TotalSeconds)
        $EstimatedTime = ('{1} min {2} sec' -f $TimeSpan.Hours, $TimeSpan.Minutes, $TimeSpan.Seconds)

        Write-Output "[Info]  Data Enrichment w/ iTunes Search API ($Total) ..."
        Write-Output "[Info]  Estimated Time: $EstimatedTime ..."
        New-Item "$OUTPUT_FOLDER\iTunes-Lookup\JSON" -ItemType Directory -Force | Out-Null

        # https://itunes.apple.com/lookup?bundleId=$BundleId

        # Apple Store DE
        # https://itunes.apple.com/de/lookup?bundleId=$BundleId
        # https://itunes.apple.com/lookup?bundleId=$BundleId&country=de
        $Country = "de" # ISO Country Code (ISO 3166-1 alpha-2) - https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

        # Österreich: at
        # Schweiz: ch
        # USA: us

        Foreach ($BundleId in $BundleIds)
        {
            $iTunesUrl = "https://itunes.apple.com/lookup?bundleId=$BundleId&country=$Country"
            $Response = Invoke-WebRequest -Uri $iTunesUrl
            $Response.Content | & $jq . | Out-File "$OUTPUT_FOLDER\iTunes-Lookup\JSON\$BundleId.json"
            Start-Sleep -Seconds 5
        }

        # CSV
        Write-Output "[Info]  Creating iTunes Search Report ..."
        Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue "$OUTPUT_FOLDER\iTunes-Lookup\JSON" | Foreach-Object FullName | Foreach-Object {

            $FilePath = $_
                
            if ((Get-Item "$FilePath").Length -gt 0kb)
            {
                $bundleId  = $_ | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.json")[0]}
                $trackName = & $jq -r '.results[0].trackName' "$FilePath" 2> $null

                if ("$trackName" -eq "null")
                {
                    $trackName = ""
                }

                $trackId = & $jq -r '.results[0].trackId' "$FilePath" 2> $null

                if ("$trackId" -eq "null")
                {
                    $trackId = ""
                }

                $artistName = & $jq -r '.results[0].artistName' "$FilePath" 2> $null

                if ("$artistName" -eq "null")
                {
                    $artistName = ""
                }

                $artistId = & $jq -r '.results[0].artistId' "$FilePath" 2> $null

                if ("$artistId" -eq "null")
                {
                    $artistId = ""
                }

                $description = & $jq -r '.results[0].description' "$FilePath" 2> $null

                if ("$description" -eq "null")
                {
                    $description = ""
                }

                $sellerUrl = & $jq -r '.results[0].sellerUrl' "$FilePath" 2> $null

                if ("$sellerUrl" -eq "null")
                {
                    $sellerUrl = ""
                }

                $trackViewUrl = & $jq -r '.results[0].trackViewUrl' "$FilePath" 2> $null

                if ("$trackViewUrl" -eq "null")
                {
                    $trackViewUrl = ""
                }

                $formattedPrice = & $jq -r '.results[0].formattedPrice' "$FilePath" 2> $null

                if ("$formattedPrice" -eq "null")
                {
                    $formattedPrice = ""
                }

                $currency = & $jq -r '.results[0].currency' "$FilePath" 2> $null

                if ("$currency" -eq "null")
                {
                    $currency = ""
                }

                $primaryGenreName = & $jq -r '.results[0].primaryGenreName' "$FilePath" 2> $null

                if ("$primaryGenreName" -eq "null")
                {
                    $primaryGenreName = ""
                }

                $primaryGenreId = & $jq -r '.results[0].primaryGenreId' "$FilePath" 2> $null

                if ("$primaryGenreId" -eq "null")
                {
                    $primaryGenreId = ""
                }

                $genres = & $jq -r '.results[0].genres[]?' "$FilePath" 2> $null

                if ("$genres" -eq "null")
                {
                    $genres = ""
                }

                $genreIds = & $jq -r '.results[0].genreIds[]?' "$FilePath" 2> $null

                if ("$genreIds" -eq "null")
                {
                    $genreIds = ""
                }

                $languageCodesISO2A = & $jq -r '.results[0].languageCodesISO2A[]?' "$FilePath" 2> $null

                if ("$languageCodesISO2A" -eq "null")
                {
                    $languageCodesISO2A = ""
                }

                $contentAdvisoryRating = & $jq -r '.results[0].contentAdvisoryRating' "$FilePath" 2> $null

                if ("$contentAdvisoryRating" -eq "null")
                {
                    $contentAdvisoryRating = ""
                }

                $averageUserRating = & $jq -r '.results[0].averageUserRating' "$FilePath" 2> $null

                if ("$averageUserRating" -eq "null")
                {
                    $averageUserRating = ""
                }

                $userRatingCount = & $jq -r '.results[0].userRatingCount' "$FilePath" 2> $null

                if ("$userRatingCount" -eq "null")
                {
                    $userRatingCount = ""
                }

                $releaseDate = & $jq -r '.results[0].releaseDate' "$FilePath" 2> $null

                if ("$releaseDate" -eq "null")
                {
                    $releaseDate = ""
                }


                $currentVersionReleaseDate = & $jq -r '.results[0].currentVersionReleaseDate' "$FilePath" 2> $null

                if ("$currentVersionReleaseDate" -eq "null")
                {
                    $currentVersionReleaseDate = ""
                }

                $version = & $jq -r '.results[0].version' "$FilePath" 2> $null

                if ("$version" -eq "null")
                {
                    $version = ""
                }

                $minimumOsVersion = & $jq -r '.results[0].minimumOsVersion' "$FilePath" 2> $null

                if ("$minimumOsVersion" -eq "null")
                {
                    $minimumOsVersion = ""
                }

                $fileSizeBytes = & $jq -r '.results[0].fileSizeBytes' "$FilePath" 2> $null

                if ("$fileSizeBytes" -eq "null")
                {
                    $fileSizeBytes = ""
                }

                $FileSize = Get-FileSize($fileSizeBytes)
            }

            New-Object –TypeName PSObject -Property ([ordered]@{
                "Bundle Identifier"         = $bundleId
                "Application Name"          = $trackName
                "App ID"                    = $trackId
                "Developer"                 = $artistName
                "Developer ID"              = $artistId
                "Description"               = $description | Out-String
                "Support URL"               = $sellerUrl
                "App Store URL"             = $trackViewUrl
                "Price"                     = $formattedPrice
                "Currency"                  = $currency
                "Primary Category"          = $primaryGenreName
                "Primary Category ID"       = $primaryGenreId
                "Categories"                = ($genres) -join ", "
                "Category IDs"              = ($genreIds) -join ", "
                "Languages"                 = ($languageCodesISO2A) -join ", "
                "Content Rating"            = $contentAdvisoryRating
                "Average Rating"            = $averageUserRating
                "UserRatingCount"           = $userRatingCount
                "Release Date"              = $releaseDate
                "Last Updated"              = $currentVersionReleaseDate
                "Current Version"           = $version
                "Minimum OS Version"        = $minimumOsVersion
                "Bytes"                     = $fileSizeBytes
                "File Size"                 = $FileSize
            })

        } | ConvertTo-Csv -Delimiter "," -NoTypeInformation | Out-File "$OUTPUT_FOLDER\iTunes-Lookup\iTunes-Report.csv"

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\iTunes-Lookup\iTunes-Report.csv")
            {
                if(Test-Csv -Path "$OUTPUT_FOLDER\CSV\TCC-Extended.csv" -MaxLines 2)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\iTunes-Lookup\iTunes-Report.csv" -Delimiter "," -Encoding UTF8
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\iTunes-Lookup\iTunes-Report.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Report" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
                    # HorizontalAlignment "Center" of columns B-E and G-X
                    $WorkSheet.Cells["B:E"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["G:X"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # App Store Apps
        $Count = (Import-Csv -Path "$OUTPUT_FOLDER\iTunes-Lookup\iTunes-Report.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_."App ID" -ne "" } | Measure-Object).Count
        Write-Output "[Info]  $Count Application(s) on Apple App Store found ($Total)"
    }
    else
    {
        Write-Host "[Error] itunes.apple.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
    }
}

}

Get-iTunesInfo

#endregion AppStore

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

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxSFGYw4NvPecJCP+wooVSvcI
# GyiggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBRdSEepUUyC/v1bd2Ht2Xbdimv5STANBgkqhkiG9w0B
# AQEFAASCAgAw32GfnXYp325r27bK/RB3JY5fXYbOHvgkw3aswhzGw893Pz36OXz5
# Q2V24OjnK2/GI2ZlOrFYYtXP7c95LSz5ew9VU1Vp6/jgTMG+6siwzWOfDxogngYn
# N1EjMVp5iq4iH+61MRno9u3KGoH+6h5Yo6qQZIHtiKE8B+T22xhLKe9SQnyM1et+
# pktndRZ3Cx1io6K8HP22ds7pWIv0IVq8rbjkIRxD5AfTtD+Chx4Uc84vO/m2tGHJ
# oaaEEshqfXhNODBQ6HOuo/Dioz5O1aPf7bUYcBpI6z31TIBLHHzIvmFSw9/kD+OB
# 5j2zPd6KFH2IcihscwcTyEDSxDBwD8TcfwVb1W4MpNoJKEZJ4RpC1r59vXRuhVfE
# CEmO3kkBTTjOcZ0ETlf6FvE6FfWRzoCWvKgRnrg+Fcdkm8tcW89EYH/fiUUfZMWc
# p/EzYkR829lXYJIygUmzl+RKvxF+TWSdguRlw7VRHqCt6aozLg+xCtiQEMEp4W0D
# liRTIinJON9LKyGgkhsjrGZ0xlYXpZpzw0g5/V5leDM2ruYtMACAVrgzyyi9h69y
# 3YrEVVGDtYwwnVd1hQpu2duaZ2r6ZMPvt7qK3/6Lx89odycv6TQtw9VzaXna0NzA
# egXAGL4fsTe4DSaXXJzds5iFjwgVzsyob5Se3A4gE3GOsgtAAovTnaGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDMxNjA2NDUxNFowPwYJKoZIhvcNAQkEMTIEMKMAIMCiVK6Ap/SDxFUOQHfM7gKi
# JbaS0rOxvtEE9/Fo5izJIN+9P3owlQgqcDmrZDANBgkqhkiG9w0BAQEFAASCAgC+
# kwkAGnaTnzTDhGSoIp0mNHq9IFIpV+HcIe509SmSX7mFij6Hnqu7zURX+lN0Dvg8
# dryRrqve/OEF67Uyf28ILhpkqycRapLtXfB0vNUZN4LXLQjN73inf9A9o2DUYD3P
# QWSIyUXUjedPExcXp1bjQd+S+tLkE5x8tL9zdEQjfzGDGB6yutVhNRgq19oO1j9i
# 1dFF7zr9MDOuqHQ+VDQjP8OQ4MLoVGXUSiN+F9o1RVKWZ0F68wYFUOVbW/QOL6YR
# sZ3N/59k/maCuI+cV7+Ha8bNidlJL93F/XzO0A8Wp3uaqwiQMYM+a/pq2jFS6Qxc
# 22J9t2CGX8x6wLcOUwMw9YQKG6qmwQJxTeJObD0hrPcnNMuvA0+vwxtZ+3R9ux77
# UzgLFodJezE6G2EDrxWai5ovDbLIB3R0u1whhL8dQDMCKMNu97QtqJn6ws7zuEQG
# 4rGoq5DM5acC+WJl9eO7UuE8B59uHoNvZBPSIpj/3QLaggPRlcTbraJDJ20WRMMa
# AnRVhvD4pBhUlkN7paMuw+sBkdDbrs/g8wjKX8mdpdf7RzZT9AY8M3V8H3tocIav
# cT2UFghIt9EiV2DO7BQa/J+ZTlzKFUbjRuJzYMPMaAyg37SJMKwaCoFG+/UsfYua
# 2Y7UnrsqiwEGz9AzM7aMneG6DhVrlpDBB0846JaLVQ==
# SIG # End signature block

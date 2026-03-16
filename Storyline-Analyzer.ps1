# Storyline-Analyzer v0.1
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
# SQLite Tools for Windows v3.50.4 (2025-07-30)
# https://sqlite.org/download.html --> Command-line tools for Windows x64 --> sqlite-tools-win-x64-3500400.zip
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
#
# Changelog:
# Version 0.1
# Release Date: 2025-11-20
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
  Storyline-Analyzer v0.1 - Automated Forensic Analysis of Aftermath Storyline

.DESCRIPTION
  Storyline-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Aftermath Storyline (storyline.csv) to potentially track down the infection vector.

  https://github.com/jamf/aftermath

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\Storyline-Analyzer".

  Note: The subdirectory 'Storyline-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input file (storyline.csv).

.EXAMPLE
  PS> .\Storyline-Analyzer.ps1

.EXAMPLE
  PS> .\Storyline-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\storyline.csv"

.EXAMPLE
  PS> .\Storyline-Analyzer.ps1 -Path "H:\macos-collector\Aftermath_Analysis\storyline.csv" -OutputDir "H:\MacOS-Analyzer-Suite"

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

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Storyline-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\Storyline-Analyzer" # Custom
    }
}

# Tools

# SQLite3
$script:SQLite3 = "$SCRIPT_DIR\Tools\SQLite\sqlite3.exe"

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

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

Function Header {

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Storyline-Analyzer v0.1 - Automated Forensic Analysis of Aftermath Storyline"

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

# Check if sqlite3.exe exists
if (!(Test-Path "$($SQLite3)"))
{
    Write-Host "[Error] sqlite3.exe NOT found." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check if xsv.exe exists
if (!(Test-Path "$($xsv)"))
{
    Write-Host "[Error] xsv.exe NOT found." -ForegroundColor Red
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
Function script:Get-FileSize
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Select Aftermath Storyline File (storyline.csv)
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Storyline|storyline.csv|All Files (*.*)|*.*"
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
$script:startTime = (Get-Date)

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
Write-Output "Storyline-Analyzer v0.1 - Automated Forensic Analysis of Aftermath Storyline for DFIR"
Write-Output "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Aftermath Storyline

Function Invoke-Processing {

$StartTime_Processing = (Get-Date)

# Input-Check
if (!(Test-Path "$LogFile" -PathType Leaf))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".csv" ))
{
    Write-Host "[Error] No CSV File provided." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$FileName = [IO.Path]::GetFileName($LogFile)
Write-Output "[Info]  Processing Aftermath Storyline ($FileName) ..."
New-Item "$OUTPUT_FOLDER\CSV" -ItemType Directory -Force | Out-Null

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

# Count rows of CSV (w/ thousands separators)
[int]$TotalLines = 0
$Reader = New-Object IO.StreamReader "$LogFile"
while($Reader.ReadLine() -ne $null){ $TotalLines++ }
($Reader.Dispose())
$Rows = '{0:N0}' -f $TotalLines | ForEach-Object {$_ -replace ' ','.'}
Write-Output "[Info]  Total Lines: $Rows" # Duplicates

# Create SQLite Database
Write-Output "[Info]  Initializing SQLite Database. Please wait ..."
New-Item "$OUTPUT_FOLDER\SQLite" -ItemType Directory -Force | Out-Null

$script:DBPath = "$OUTPUT_FOLDER\SQLite\Storyline.db"

$Table = 
"
CREATE TABLE Aftermath (
    Timestamp TEXT,
    Type TEXT,
    Path TEXT,
    Other TEXT
);
"

$SQL = 
"
CREATE TABLE Storyline (
    Timestamp TEXT,
    Type TEXT,
    Path TEXT,
    Other TEXT
);
INSERT INTO Storyline
SELECT
    strftime('%Y-%m-%d %H:%M:%S',Timestamp) AS Timestamp,
    Type,
    Path,
    Other
FROM Aftermath
ORDER BY Timestamp DESC;
DROP TABLE Aftermath;
VACUUM;
"

# Import Aftermath Storyline
& $SQLite3 "$DBPath" "$Table" ".mode csv" ".import $LogFile Aftermath" ".exit"

# Create SQLite Database
& $SQLite3 $DBPath $SQL

# CSV
& $SQLite3 -readonly -header -csv $DBPath "SELECT * FROM Storyline" | Out-File "$OUTPUT_FOLDER\CSV\Storyline.csv" -Encoding UTF8

# Get End Time
$EndTime_Processing = (Get-Date)

# Duration Processing
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('Duration CSV Creation:     {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

# Count Rows of SQLite3 Database (w/ thousands separators)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline")
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Rows: $Rows" # Unique Records

# Time Frame (ISO 8601)
$Start = & $SQLite3 -readonly $DBPath "SELECT Timestamp FROM Storyline WHERE Timestamp NOT LIKE '21%' ORDER BY Timestamp DESC LIMIT 1"
$End = & $SQLite3 -readonly $DBPath "SELECT Timestamp FROM Storyline WHERE Timestamp NOT LIKE '%1970-01-01 00:00:00%' ORDER BY Timestamp ASC LIMIT 1"
Write-Output "[Info]  Log data from $Start UTC until $End UTC"

}

#############################################################################################################################################################################################

Function Get-DatabaseViews {

# Get Start Time
$StartTime_Views = (Get-Date)

# Creating Views
Write-Output "[Info]  Creating Views ..."
$Files = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\Storyline-Analyzer" -Filter "*.sql").FullName
ForEach($File in $Files)
{
    # Build SQL Query
    $Name = (Get-Item $File).BaseName
    [array]$Prefix = "CREATE VIEW $Name AS" + "`n"
    [array]$Select = Get-Content "$File"
    $Query = $Prefix + $Select
    $Query | & $SQLite3 $DBPath

    # Cleaning up
    $Count = & $SQLite3 $DBPath "SELECT count(*) FROM $Name"
    if ($Count -eq 0)
    {
        & $SQLite3 $DBPath "DROP VIEW $Name"
    }
}

# Get End Time
$EndTime_Views = (Get-Date)

# Duration Views
$Time_Views = ($EndTime_Views-$StartTime_Views)
('Duration Views Creation:   {0} h {1} min {2} sec' -f $Time_Views.Hours, $Time_Views.Minutes, $Time_Views.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################

Function Get-Reports {

# Get Start Time
$StartTime_Reports = (Get-Date)

# Event Reports
Write-Output "[Info]  Creating Event Reports ..."
New-Item "$OUTPUT_FOLDER\Reports\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\Reports\XLSX" -ItemType Directory -Force | Out-Null

# BashActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\BashActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\BashActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\BashActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\BashActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\BashActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\BashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Bash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# BrowserActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\BrowserActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\BrowserActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\BrowserActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\BrowserActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\BrowserActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\BrowserActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageBoxActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\CloudStorageBoxActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\CloudStorageBoxActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\CloudStorageBoxActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\CloudStorageBoxActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\CloudStorageBoxActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\CloudStorageBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Box Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageDropBoxActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\CloudStorageDropBoxActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\CloudStorageDropBoxActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\CloudStorageDropBoxActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\CloudStorageDropBoxActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\CloudStorageDropBoxActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\CloudStorageDropBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DropBox Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# DownloadsActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\DownloadsActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\DownloadsActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\DownloadsActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\DownloadsActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\DownloadsActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\DownloadsActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# DSStoreActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\DSStoreActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\DSStoreActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\DSStoreActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\DSStoreActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\DSStoreActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\DSStoreActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".DS_Store" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# EmailAttachments
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\EmailAttachments.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\EmailAttachments.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\EmailAttachments.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\EmailAttachments.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\EmailAttachments.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\EmailAttachments.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email Attachments" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# FailedPasswordActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\FailedPasswordActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\FailedPasswordActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\FailedPasswordActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\FailedPasswordActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\FailedPasswordActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\FailedPasswordActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed Password Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# GuestAccountActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\GuestAccountActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\GuestAccountActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\GuestAccountActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\GuestAccountActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\GuestAccountActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\GuestAccountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Guest Account Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# iCloudSyncronizationActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\iCloudSyncronizationActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\iCloudSyncronizationActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\iCloudSyncronizationActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\iCloudSyncronizationActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\iCloudSyncronizationActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\iCloudSyncronizationActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "iCloud Syncronization" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# MountActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\MountActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\MountActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\MountActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\MountActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\MountActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\MountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mount Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# OutlookTempActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\OutlookTempActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\OutlookTempActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\OutlookTempActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\OutlookTempActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\OutlookTempActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\OutlookTempActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Outlook Temp Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# RootShellActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\RootShellActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\RootShellActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\RootShellActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\RootShellActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\RootShellActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\RootShellActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Root Shell Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# SavedApplicationState
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\SavedApplicationState.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\SavedApplicationState.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\SavedApplicationState.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\SavedApplicationState.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\SavedApplicationState.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\SavedApplicationState.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Saved Application State" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# SharedFileLists
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\SharedFileLists.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\SharedFileLists.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\SharedFileLists.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\SharedFileLists.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\SharedFileLists.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\SharedFileLists.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shared File Lists" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# SudoUsageActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\SudoUsageActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\SudoUsageActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\SudoUsageActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\SudoUsageActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\SudoUsageActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\SudoUsageActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sudo Usage Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# TempDirectoryActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\TempDirectoryActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\TempDirectoryActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\TempDirectoryActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\TempDirectoryActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\TempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\TempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Temp Directory Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# Trash Activity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\TrashActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\TrashActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\TrashActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\TrashActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\TrashActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\TrashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Trash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# UserProfileActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\UserProfileActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\UserProfileActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\UserProfileActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\UserProfileActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\UserProfileActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\UserProfileActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Profile Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersDocumentTypeFiles
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersDocumentTypeFiles.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersDocumentTypeFiles.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\UsersDocumentTypeFiles.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\UsersDocumentTypeFiles.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\UsersDocumentTypeFiles.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\UsersDocumentTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Document Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersPictureTypeFiles
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersPictureTypeFiles.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersPictureTypeFiles.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\UsersPictureTypeFiles.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\UsersPictureTypeFiles.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\UsersPictureTypeFiles.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\UsersPictureTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Picture Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersTempDirectoryActivity
if (Test-Path "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersTempDirectoryActivity.sql")
{
    Get-Content "$SCRIPT_DIR\Queries\Storyline-Analyzer\UsersTempDirectoryActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\Reports\CSV\UsersTempDirectoryActivity.csv" -Encoding UTF8
    
    if([int](& $xsv count "$OUTPUT_FOLDER\Reports\CSV\UsersTempDirectoryActivity.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\Reports\CSV\UsersTempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\Reports\XLSX\UsersTempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Temp Directory" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# Count Event Reports
$Total = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\Storyline-Analyzer" -Filter "*.sql" | Measure-Object).Count
$Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\Reports\XLSX" -Filter "*.xlsx" | Measure-Object).Count
Write-Output "[Info]  $Count Event Reports created ($Total)"

# Get End Time
$EndTime_Reports = (Get-Date)

# Duration Reports
$Time_Reports = ($EndTime_Reports-$StartTime_Reports)
('Duration Reports Creation: {0} h {1} min {2} sec' -f $Time_Reports.Hours, $Time_Reports.Minutes, $Time_Reports.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################

Function Invoke-Excel {

# Get Start Time
$StartTime_XLSX = (Get-Date)

# XLSX
if([int](& $xsv count "$OUTPUT_FOLDER\CSV\Storyline.csv") -gt 0)
{
    [int]$Count = & $xsv count "$OUTPUT_FOLDER\CSV\Storyline.csv"

    if ($Count -gt "1048576")
    {
        Write-Output "[Info]  ImportExcel: Storyline.csv will be splitted [time-consuming task] ..."
        New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null
        & $xsv split -s 1000000 "$OUTPUT_FOLDER\CSV" --filename "Storyline-{}.csv" --delimiter "," "$OUTPUT_FOLDER\CSV\Storyline.csv"

        [array]$Files = (Get-ChildItem -Path "$OUTPUT_FOLDER\CSV" | Where-Object {$_.Name -match "Storyline-[0-9].*\.csv"}).FullName

        ForEach( $File in $Files )
        {
            $FileName = $File | ForEach-Object{($_ -split "\\")[-1]} | ForEach-Object{($_ -split "\.")[0]}
            $Import = Import-Csv "$File" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\$FileName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Storyline" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A-B
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            }
        }
    }
    else
    {
        New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null
        $Import = Import-Csv "$OUTPUT_FOLDER\CSV\Storyline.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_."Timestamp" -as [datetime] } -Descending
        $Import | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\Storyline.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Storyline" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-B
        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\XLSX\Storyline.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\XLSX\Storyline.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Get End Time
$EndTime_XLSX = (Get-Date)

# Duration XLSX
$Time_XLSX = ($EndTime_XLSX-$StartTime_XLSX)
('Duration XLSX Creation:    {0} h {1} min {2} sec' -f $Time_XLSX.Hours, $Time_XLSX.Minutes, $Time_XLSX.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Statistics

Function Get-Statistics {

# Get Start Time
$script:StartTime_Stats = (Get-Date)

# File Metadata
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE (Type LIKE '%birth%' OR Type LIKE '%accessed%' OR Type LIKE '%modified%')")
$FileMeta = '{0:N0}' -f $Count
Write-Output "[Info]  $FileMeta File Metadata Change(s) found"

# Install Logs (Aftermath Collection: \Artifacts\raw\logs\system_logs\install.log)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%INSTALL%'")
$INSTALL = '{0:N0}' -f $Count
Write-Output "[Info]  $INSTALL Install Log Record(s) found"

# System Logs (Aftermath Collection: \Artifacts\raw\logs\system_logs\system.log)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%SYSLOG%'")
$SYSLOG = '{0:N0}' -f $Count
Write-Output "[Info]  $SYSLOG System Log Record(s) found"

# Safari History (Aftermath Collection: \Browser\Safari\history_output.csv)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%safari_history%'")
$SafariHistory = '{0:N0}' -f $Count
Write-Output "[Info]  $SafariHistory Safari History Record(s) found"

# Transparency, Consent, and Control (TCC)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%tcc_%'")
$TCC = '{0:N0}' -f $Count
Write-Output "[Info]  $TCC TCC Database Change(s) found"

# XProtect Behavioral Service (XBS)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%xpdb_%'")
$XPDB = '{0:N0}' -f $Count
Write-Output "[Info]  $XPDB XProtect Behavioral Service Record(s) found"

# XProtect Remediator Logs (Aftermath Collection: \UnifiedLog\xprotect_remediator.txt)
[int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM Storyline WHERE Type LIKE '%XPROTECT_REMEDIATOR%'")
$XPR = '{0:N0}' -f $Count
Write-Output "[Info]  $XPR XProtect Remediator Record(s) found"

# Get End Time
$EndTime_Stats = (Get-Date)

# Duration Stats
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('Duration Stats Creation:   {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Statistics

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

Function Footer {

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

# MessageBox UI
$MessageBody = "Status: Aftermath Storyline Analysis completed."
$MessageTitle = "Storyline-Analyzer.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    # Reset Progress Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Header
Invoke-Processing
Get-DatabaseViews
Get-Reports
Invoke-Excel
Get-Statistics
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyGtjcAeB8kt5c812MHYmjpv0
# HzeggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBRGcJPf6HmXPOmhN6Iiq4ZRKEleyjANBgkqhkiG9w0B
# AQEFAASCAgBGkTHwAcPe8105EKTk0bDLUGx8OpQU4mSQGC009fYXHoMdRSWOFpFv
# tDAZHpA/zC+AMYrIG5rPtJstGFCoyFYrfexkANvokQfjDoISY1llRKOwycmcNHfi
# rX4SuPPXKYRzTjWd5mBvxzf3ZlEMZreYJgeNppCmaiQHqXxJSXAPdg0m2dXaO6LD
# 9BE75ArMWJfPL0z4WT51Fb+HBvVjw3TfUqM4u8hejl/Hp/EwgdzwiJBenV+sCDMm
# N705nS5tkmMXilx+h3Mg5lOYtw6I2stLh3Js0ZokFxFDJpc59pGYzab8cj7w2tq8
# LepLe+U0oQEGtFy1N5WB7ZojZIXgd+RVgeh5Fvqh5VXCvd5kQLh3B/wKQX/P9K/C
# 2DeYDAV1YpaDTTjVAxwLaQR+4PoO2noE4TjJV8EHbiZYoN9h/6gdgFynFuWC0xLP
# wZvFcKbSn6RqFscyNsG7KailEa9kFt0DOFkBratSL/hmkaKpaEaPk6dPaFFKzvTW
# TXAy3apYhgvtIt6AxDaPPmqwa0Fc1gbFiPtxC+2OKg1wjO8wZYYN/TGxtNV07wMZ
# QC9BEdUZCbvbsqGKUrhoiqqYz2Mo4Tt4EACagLNC3R9WYwWqzaglK65FrcCaejD6
# 5v2QkyYXbagdIhO/0+OKUVb/7p2rHrtnEXdpfawgXonAglplHvgGjaGCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDMxNjA2NDUxMVowPwYJKoZIhvcNAQkEMTIEMNDYjBM5wyKd6/YdexboiMEevao7
# pRn7OiMFnmzF2jXSwFUajcFOnBu2NRZ/Gxb7DDANBgkqhkiG9w0BAQEFAASCAgBB
# QDbMtp/jX/4rtQ+UozMj21dH6Rfqh1/ko3XL6VTTNreO70WcjIc+mRPw6F5CjKkq
# wSIymKYA4j7+rS4x8HW3z0le1LRgMIjZZErFSGWZb483WB36TSC8nVfkhLJ3umG8
# lyaos+hXVSa24DPIVaA3Up2Vk22AhqtDWNnbt2pHc20IP0Q2DSkPRwUU45OfXK1k
# Iusro2o1Xs2wEBPODPdSfMbHGJ/eGtNENNicHl+4Y0PU+lRCJgOw8QHKvpdlcu54
# Yj2TO9uqtDj1vXvmKdp3TzjDeErqND02RHfFVL0RUosKPaZyG/AkGlC1Yunirft1
# Sw+4L8PyaCJ0PolffFoEetO/JAp38/4s/71heYbaXJzGAm7LnxMnvvka94JvKuaR
# l8JhdP7HnRzs/Peq0LrnKjgR/iUdt386KOev+Wk0h+e9vWUpC4B51t2QB6aeFfu3
# WGlRERqE4OufmClF0LKN5B8sw59tS7LPwiWKwh+Ic7QiydcDo1B3U+ObSVNJa/vt
# s/OS2qKDhvYXC6n2mzuzNFlcOIhWtdpl006PSf+BcXeGA1zKVkhBjByelzvlLmvA
# i2NTNQJPHHR5sSx9Rez/JuVPDCxXVksDYeAU+25eulT5sZSSztk2Z0wEGWT1yw4U
# I5cfgoBhMes71bI/EPVtmly3hZ9b7R78P2jrWyJyyA==
# SIG # End signature block

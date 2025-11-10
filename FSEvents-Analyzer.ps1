# FSEvents-Analyzer v0.1
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-11-10
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
# FSEventsParser v4.1 (2024-12-04)
# https://github.com/dlcowen/FSEventsParser
#
# fsevents_parser_rs v0.1.1 (2024-07-20)
# https://github.com/Houwenda/FSEventsParser-rs
#
# ImportExcel v7.8.10 (2024-10-21)
# https://github.com/dfinke/ImportExcel
#
# Python 3
# https://www.python.org/downloads/
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
# Release Date: 2025-11-10
# Initial Release
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 5.1 (5.1.19041.6456)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.6456) and PowerShell 7.5.4
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvent Logs for DFIR

.DESCRIPTION
  FSEvents-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the macOS File System Event Logs (FsEvents).
  
  FSEvent Logs are written to disk by macOS APIs and contain historical records of file system activity that occurred for a particular volume.

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\FSEvents-Analyzer".

  Note: The subdirectory 'FSEvents-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the input directory.

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1 -InputDir "$env:USERPROFILE\Desktop\FSEvents_Data\.fseventsd"

.EXAMPLE
  PS> .\FSEvents-Analyzer.ps1 -InputDir "H:\MacOS-Analyzer-Suite\FSEvents_Data\.fseventsd" -OutputDir "H:\MacOS-Analyzer-Suite"

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
    [String]$InputDir,
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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\FSEvents-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\FSEvents-Analyzer" # Custom
    }
}

# Tools

# FSEventsParser by David Cowen and Nicole Ibrahim
$script:ReportQueries = "$SCRIPT_DIR\Tools\FSEventsParser\report_queries.json"

# FSEventsParser-rs
$script:FSEventsParser = "$SCRIPT_DIR\Tools\FSEventsParser-rs\fsevents_parser_rs.exe"

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
$Host.UI.RawUI.WindowTitle = "FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvent Logs for DFIR"

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

# Select folder containing FSEvent Data
if(!($InputDir))
{
    Function Get-FolderPath($InitialDirectory)
    {
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $script:OpenFolderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $OpenFolderDialog.Description = 'Select a folder containing FSEvent Data'
        $OpenFolderDialog.ShowNewFolderButton = $false
        $OpenFolderDialog.RootFolder = "MyComputer"
        $Topmost = New-Object System.Windows.Forms.Form
        $Topmost.TopMost = $True
        $Topmost.MinimizeBox = $True
        $OpenFolderDialog.ShowDialog($Topmost)
    }

    $Result = Get-FolderPath

    if($Result -eq "OK")
    {
        $script:FolderPath = $OpenFolderDialog.SelectedPath
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:FolderPath = $InputDir
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
Write-Output "FSEvents-Analyzer v0.1 - Automated Forensic Analysis of FSEvents Logs for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Input-Check
if (!(Test-Path "$FolderPath"))
{
    Write-Host "[Error] $FolderPath does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}
else
{
    if (!(Get-Item $FolderPath) -is [System.IO.DirectoryInfo])
    {
        Write-Host "[Error] No Folder Path provided." -ForegroundColor Red
        Write-Host ""
        Stop-Transcript
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}

# Count GZIP Archive Files
[int]$GZip = "0"
$Files = (Get-ChildItem $FolderPath -Exclude "fseventsd-uuid").FullName
ForEach ($File in $Files)
{
    if ($PSEdition -eq "Core")
    {
        $Bytes = (Get-Content -Path $File -AsByteStream -ReadCount 1 -TotalCount 2) # PowerShell 7
    }
    else
    {
        $Bytes = (Get-Content -Path $File -Encoding Byte -ReadCount 1 -TotalCount 2) # PowerShell 5.1
    }

    $Signature = ([System.BitConverter]::ToString($Bytes)).Replace("-"," ")
    if ($Signature -eq "1F 8B") # Magic Bytes
    {
        $GZip++
    }
}

Write-Output "[Info]  Processing $GZip FSEvent Log Files ..."

# Input Size
$InputSize = Get-FileSize((Get-ChildItem -Path "$FolderPath" -Exclude "fseventsd-uuid" | Measure-Object Length -Sum).Sum)
Write-Output "[Info]  Total Input Size: $InputSize"

}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# FSEvents

# FSEvents are a critical macOS forensic artifact that logs file system changes, such as creation, deletion, and modification, within the ./fseventsd directory.
# Forensic investigators use FSEvents to reconstruct user activity, track file movements, identify deleted files, and detect unauthorized operations, even in cases where other logs may be cleared. 

# https://github.com/libyal/dtformats/blob/main/documentation/MacOS%20File%20System%20Events%20Disk%20Log%20Stream%20format.asciidoc

Function Invoke-FSEventsParser {

$StartTime_FSEventsParser = (Get-Date)

# FSEventsParser-rs by Houwenda
if (Test-Path "$($FSEventsParser)")
{
    Write-Output "[Info]  Parsing FSEvents Data w/ FSEventsParser-rs ..."
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs" -ItemType Directory -Force | Out-Null

    # SQLite
    & $FSEventsParser -i "$FolderPath" -o "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite" -f sqlite > "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser-rs.txt"

    $SQL = 
    "
    CREATE TABLE 'FSEventsParser'
    (
        'Event ID' TEXT NOT NULL,
        'Full Path' TEXT,
        'Record Flags' TEXT,
        'Creation Time' INTEGER,
        'Last Modified Time' INTEGER,
        'Source' TEXT NOT NULL
    );
    INSERT INTO 'FSEventsParser'
    SELECT
	id AS 'Event ID',
	path as 'Full Path',
	flags AS 'Record Flags',
	DATETIME(create_ts,'UNIXEPOCH') AS 'Creation Time',
	DATETIME(modify_ts,'UNIXEPOCH') AS 'Last Modified',
	source AS Source
    FROM record;
    DROP TABLE 'record';
    VACUUM;
    "

    & $SQLite3 "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite" $SQL

    # CSV
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\CSV" -ItemType Directory -Force | Out-Null
    $DBPath = "$OUTPUT_FOLDER\FSEventsParser-rs\FSEventsParser.sqlite"
    & $SQLite3 -readonly -header -csv $DBPath "SELECT * FROM FSEventsParser" | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv" -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv")
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\CSV\FSEventsParser.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FSEvents" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A, C-F
        $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
        }
    }

    # Stats

    # Count Rows of SQLite3 Database (w/ thousands separators)
    [int]$Count = (& $SQLite3 -readonly $DBPath "SELECT COUNT(*) FROM FSEventsParser")
    $Rows = '{0:N0}' -f $Count
    Write-Output "[Info]  Total Records: $Rows"

    # File Size (XLSX)
    if (Test-Path "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx")
    {
        $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\FSEventsParser-rs\XLSX\FSEventsParser.xlsx").Length)
        Write-Output "[Info]  File Size (XLSX): $Size"
    }

    # Creating Views
    Write-Output "[Info]  Creating Views ..."
    $Files = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer" -Filter "*.sql").FullName
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
    
    # Event Reports
    Write-Output "[Info]  Creating Event Reports ..."
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX" -ItemType Directory -Force | Out-Null

    # BashActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BashActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BashActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BashActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\BashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Bash Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # BrowserActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BrowserActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\BrowserActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\BrowserActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\BrowserActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # CloudStorageBoxActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageBoxActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageBoxActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageBoxActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\CloudStorageBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Box Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # CloudStorageDropBoxActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageDropBoxActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\CloudStorageDropBoxActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\CloudStorageDropBoxActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\CloudStorageDropBoxActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DropBox Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # DownloadsActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DownloadsActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DownloadsActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DownloadsActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\DownloadsActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # DSStoreActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DSStoreActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\DSStoreActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\DSStoreActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\DSStoreActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".DS_Store" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # EmailAttachments (Apple Mail)
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\EmailAttachments.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\EmailAttachments.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\EmailAttachments.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\EmailAttachments.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email Attachments" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # FailedPasswordActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\FailedPasswordActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\FailedPasswordActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\FailedPasswordActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\FailedPasswordActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed Password Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # GuestAccountActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\GuestAccountActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\GuestAccountActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\GuestAccountActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\GuestAccountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Guest Account Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # iCloudSyncronizationActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\iCloudSyncronizationActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\iCloudSyncronizationActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\iCloudSyncronizationActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\iCloudSyncronizationActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "iCloud Syncronization" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # MountActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\MountActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\MountActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\MountActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\MountActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mount Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # OutlookTempActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\OutlookTempActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\OutlookTempActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\OutlookTempActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\OutlookTempActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Outlook Temp Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # RootShellActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\RootShellActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\RootShellActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\RootShellActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\RootShellActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Root Shell Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SavedApplicationState
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SavedApplicationState.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SavedApplicationState.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SavedApplicationState.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SavedApplicationState.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Saved Application State" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SharedFileLists
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SharedFileLists.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SharedFileLists.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SharedFileLists.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SharedFileLists.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shared File Lists" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # SudoUsageActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SudoUsageActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\SudoUsageActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\SudoUsageActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\SudoUsageActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sudo Usage Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # TempDirectoryActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TempDirectoryActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TempDirectoryActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\TempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Temp Directory Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Trash Activity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TrashActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\TrashActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\TrashActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\TrashActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Trash Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UserProfileActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UserProfileActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UserProfileActivity.sql" | & $SQLite3 -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UserProfileActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UserProfileActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Profile Activity" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersDocumentTypeFiles
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersDocumentTypeFiles.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersDocumentTypeFiles.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersDocumentTypeFiles.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersDocumentTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Document Type Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersPictureTypeFiles
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersPictureTypeFiles.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersPictureTypeFiles.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersPictureTypeFiles.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersPictureTypeFiles.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Picture Type Files" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # UsersTempDirectoryActivity
    if (Test-Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersTempDirectoryActivity.sql")
    {
        Get-Content "$SCRIPT_DIR\Queries\FSEvents-Analyzer\UsersTempDirectoryActivity.sql" | & $SQLite3 -readonly -header -csv $DBPath | Out-File "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv" -Encoding UTF8
    
        if([int](& $xsv count "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\CSV\UsersTempDirectoryActivity.csv" -Delimiter "," -Encoding UTF8
            $Import | Export-Excel -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX\UsersTempDirectoryActivity.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Temp Directory" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
            # HorizontalAlignment "Center" of columns A, C-F
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:F"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Count Event Reports
    $Total = (Get-ChildItem -Path "$SCRIPT_DIR\Queries\FSEvents-Analyzer" -Filter "*.sql" | Measure-Object).Count
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\FSEventsParser-rs\Reports\XLSX" -Filter "*.xlsx" | Measure-Object).Count
    Write-Output "[Info]  $Count Event Reports created ($Total)"
}
else
{
    Write-Host "[Error] fsevents_parser_rs.exe NOT found." -ForegroundColor Red
}

$EndTime_FSEventsParser = (Get-Date)
$Time_FSEventsParser = ($EndTime_FSEventsParser-$StartTime_FSEventsParser)
('FSEventsParser duration: {0} h {1} min {2} sec' -f $Time_FSEventsParser.Hours, $Time_FSEventsParser.Minutes, $Time_FSEventsParser.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################

Function Invoke-FSEParser {

$StartTime_FSEParser = (Get-Date)

# FSEventsParser by David Cowen and Nicole Ibrahim
Write-Output "[Info]  Parsing FSEvents Data w/ FSEParser ..."
New-Item "$OUTPUT_FOLDER\FSEParser" -ItemType Directory -Force | Out-Null

# Python 3
if (Test-Path "$SCRIPT_DIR\Tools\FSEventsParser\FSEParser_V4.1.py")
{
    if (Get-Command python -ErrorAction SilentlyContinue)
    {
        python "$SCRIPT_DIR\Tools\FSEventsParser\FSEParser_V4.1.py" -s "$FolderPath" -t folder -o "$OUTPUT_FOLDER\FSEParser" -q "$ReportQueries" > "$OUTPUT_FOLDER\FSEParser\FSEParser.txt"
    }
    else
    {
        Write-Host "[Error] Python 3 NOT found." -ForegroundColor Red
    }
}
else
{
    Write-Host "[Error] FSEParser_V4.1.py NOT found." -ForegroundColor Red
}

# Stats
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSEParser.txt")
{
    $LogFile = Get-Content "$OUTPUT_FOLDER\FSEParser\FSEParser.txt"
    $Attempts = $LogFile | Select-String -Pattern "All Files Attempted:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Parsed = $LogFile | Select-String -Pattern "All Parsed Files:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Errors = $LogFile | Select-String -Pattern "Files with Errors:" | ForEach-Object{($_ -split "\s+")[-1]}
    [int]$Count = $LogFile | Select-String -Pattern "All Records Parsed:" | ForEach-Object{($_ -split "\s+")[-1]}
    $Records = '{0:N0}' -f $Count
    Write-Output "[Info]  All Files Attempted: $Attempts"
    Write-Output "[Info]  All Parsed Files: $Parsed"

    if ($Errors -eq 0)
    {
        Write-Host "[Info]  Files with Errors: 0" -ForegroundColor Green
    }
    else
    {
        Write-Host "[Info]  Files with Errors: $Errors" -ForegroundColor Red
    }

    Write-Output "[Info]  All Records Parsed: $Records"
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\All_FSEVENTS.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "All_FSEVENTS" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\All_FSEVENTS.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Reports

# BashActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BashActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\BashActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Bash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# BrowserActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\BrowserActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\BrowserActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageBoxActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageBoxActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\CloudStorageBoxActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Box Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# CloudStorageDropBoxActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\CloudStorageDropBoxActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\CloudStorageDropBoxActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DropBox Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# DownloadsActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DownloadsActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\DownloadsActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Downloads Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# DSStoreActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\DSStoreActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\DSStoreActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname ".DS_Store Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# EmailAttachments.tsv (Apple Mail)
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\EmailAttachments.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\EmailAttachments.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Email Attachments" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# FailedPasswordActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\FailedPasswordActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\FailedPasswordActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed Password Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# GuestAccountActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\GuestAccountActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\GuestAccountActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Guest Account Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# iCloudSyncronizationActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\iCloudSyncronizationActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\iCloudSyncronizationActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "iCloud Syncronization" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# MountActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\MountActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\MountActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Mount Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# RootShellActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\RootShellActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\RootShellActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Root Shell Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SavedApplicationState.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SavedApplicationState.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SavedApplicationState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Saved Application State" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SharedFileLists.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SharedFileLists.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SharedFileLists.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Shared File Lists" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# SudoUsageActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\SudoUsageActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\SudoUsageActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sudo Usage Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# TrashActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\TrashActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\TrashActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Trash Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UserProfileActivity.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UserProfileActivity.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UserProfileActivity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Profile Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersDocumentTypeFiles.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersDocumentTypeFiles.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UsersDocumentTypeFiles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Document Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# UsersPictureTypeFiles.tsv
if (Test-Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv")
{
    if([int](& $xsv count -d "`t" "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\FSEParser\FSE_Reports\UsersPictureTypeFiles.tsv" -Delimiter "`t" -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX\UsersPictureTypeFiles.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Users Picture Type Files" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor $FontColor
        # HorizontalAlignment "Center" of columns A-C and E-I
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["E:I"].Style.HorizontalAlignment="Center"
        }
    }
}

# Count Event Reports
if (Test-Path "$ReportQueries")
{
    $Total = (Get-Content "$ReportQueries" | ConvertFrom-Json | Select-Object -ExpandProperty process_list | Measure-Object).Count
    $Count = (Get-ChildItem -Path "$OUTPUT_FOLDER\FSEParser\FSE_Reports\XLSX" -Exclude "All_FSEVENTS.xlsx" | Measure-Object).Count
    Write-Output "[Info]  $Count Event Reports created ($Total)"
}

$EndTime_FSEParser = (Get-Date)
$Time_FSEParser = ($EndTime_FSEParser-$StartTime_FSEParser)
('FSEParser duration:      {0} h {1} min {2} sec' -f $Time_FSEParser.Hours, $Time_FSEParser.Minutes, $Time_FSEParser.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analysis

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
$MessageBody = "Status: FSEvents Analysis completed."
$MessageTitle = "FSEvents-Analyzer.ps1 (https://lethal-forensics.com/)"
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
Invoke-FSEventsParser
Invoke-FSEParser
Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# SIG # Begin signature block
# MIIrywYJKoZIhvcNAQcCoIIrvDCCK7gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUVtqXd08E/hK5zjjtmCjkUVE
# YzqggiUEMIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# MCMGCSqGSIb3DQEJBDEWBBQwfaqa72HJMaIwtg1olMmbMNSi5DANBgkqhkiG9w0B
# AQEFAASCAgCCdX8ewNfg4jvWIQnbG4Z4FHa+yTDp7NgWfG3x/qmqYGdRl1ESpaMH
# EzPg+GyhI5cTwjTlI2gHg3sZ+bx/lVed5T3KjZ5xdKdsc9Ew/UKXMJJ8wOxzCwwv
# GOVPX1zngs9OqzAAMTsE8iwJPLGM92HqhVG9MdtkcQrc2xvIGRbuhp6ldiPqEkXl
# qj/7M3W0TeXWJ2GH/FBfi2VMa+/YXT0nGD+YGcJ6KWnxkhBg9sqmHQaiqN7t+U3g
# m4XF+8jCRyK/Stwt9ZgF//U6uT6UgjhPyj77KXxva5SitSrFm+uLKI5oojjBWXwL
# 2U0nff7ycUez8/X5mNdmXbHtaASOuvHJjy/f65NQZHYjZEe4uJNFvrdhVmLiIk0Y
# Tgv/eVFeBR+y0DKVTAeOJThAzvZlfvdoMJ5nrXO8AZg+7E/oyoGJaxLEeQDoL6S9
# Wzn0yUZY1R0pN2N0cQWthReNc/sfEqgICM35Bivj2U0nLFSR8LqRi9XkISEmmtxz
# UeeX7BMRKBzBKYZrxQjqsEl8opD5W/Vd2+BmrH1vEBvgx5t+aGPa9yKaZWmgKE89
# 7pX28zZljQfSLUlmAc0+B8Xr4m45gLCqbv/po5Pff1F0Poxq7WUqSwokdxaPoG74
# XWjCknU8OwIwapYJUkZEp4vlzlntJNrRG+n9Gd5za+n5/oSZ2BnOa6GCAyMwggMf
# BgkqhkiG9w0BCQYxggMQMIIDDAIBATBqMFUxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLDAqBgNVBAMTI1NlY3RpZ28gUHVibGljIFRpbWUg
# U3RhbXBpbmcgQ0EgUjM2AhEApCk7bh7d16c0CIetek63JDANBglghkgBZQMEAgIF
# AKB5MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1
# MTExMDA2MDgxM1owPwYJKoZIhvcNAQkEMTIEMMBrOewblki0mVqHzZxBGOYbwbxE
# nr4Opcy6vFnw03YES0lkpUZyzhSsi3onqbqwJTANBgkqhkiG9w0BAQEFAASCAgA9
# SUjYFQFrkdD7EKll8N93PgfqoiSF45V9S+vXa/RSGL19W4L0Fro/e6KsE4V+ctUN
# aMZK/2aKKDYdkXLm1WCqJYoLJXLva/vJ665WzhubgmJcoJkUUq9UFLZiS4MEL65F
# Y30Igl9UffEwcTZYXziq9U7VOxsoWGP7CgBl9mNErVgbo8+iHop7OJ3Sb2REK/a5
# kEaCUK8EVApRpqhJy92Tf7WwwONkijkyzxgb3iqw1xtrtvBb9yGTel19yN4HQpCy
# m4mgV+tYItxAm2xf9miVDK551nub4K4+ry2v2aaQURsR99A3Lzr21YotdHT5o31i
# TcGaom1/w1uDeyitvWOQUEH/TC4p5xHqKGXZdbSOELs71mLCXfUU5yFdCQ+1b1EP
# qAYbbppGOlzYyw30OxliEcQzViuIKbPDD+ge5mb1mc5RrOqOnk9xeJGukW1ZECdo
# is4OcGFCyQLRrJKCVSW6zezRZoKjoaHQh8KMB/whN3IfBSNkMEs8nnsIqOlgMFf0
# 02d6EV+rfNEFMZKLY7QBD7Bd8x1VI4cnV6b5hspOgqqhl1Wxd2NHGrevknG1IkQ7
# 80XsmpDL6qsay3zuc4L/txI0mmNfAyFDXNO9m1caqrL62WLQq4rTSXAFhXWaTG9c
# 4kOH/R8xKfP+VAB/461qgQ9AMRNHmxBOF31DxmWh1Q==
# SIG # End signature block

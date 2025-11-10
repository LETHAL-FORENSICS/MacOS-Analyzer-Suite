<p align="center"><a href="https://github.com/PowerShell/PowerShell"><img src="https://img.shields.io/badge/Language-Powershell-blue" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/Operating System-Windows-blue" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>  

# MacOS-Analyzer-Suite
A collection of PowerShell scripts for analyzing macOS Forensic Artifacts

## The following MacOS Forensic Artifacts are supported yet:

  * FSEvent Logs &#8594; FSEvents-Analyzer  
  * LSQuarantine database file(s) &#8594; Quarantine-Analyzer  
  * TCC database file(s) &#8594; TCC-Analyzer  
  * XProtect Behavioral Service database file(s) &#8594; XProtect-Analyzer  

<br>

> [!NOTE]
> MacOS-Analyzer-Suite includes all external tools by default.  

## Prerequisites  
1. Windows PowerShell 5.1 or newer.  

## Setup  
1. Download the latest version of the <b>MacOS-Analyzer-Suite</b> from the Releases section.
2. Install [ImportExcel](https://github.com/dfinke/ImportExcel) PowerShell module to import/export Excel spreadsheets, without Excel.  

   ```powershell
   Install-Module -Name ImportExcel
   ```  
3. Run the specific script in PowerShell (e.g. TCC-Analyzer.ps1). 

## Usage  
Open PowerShell and navigate to the directory containing e.g. TCC-Analyzer.ps1 and run the script with following command:  

`.\TCC-Analyzer.ps1`

![File-Browser](https://github.com/user-attachments/assets/0718a242-cae2-4236-b3d4-fd25e31fb8f5)  
**Fig 1:** Select your TCC Database file     

You can skip the file selection dialog and provide the file path to your log file with following command:  
`.\TCC-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\tcc_<USERNAME>"`  

You can specify the output directory with following command (Default is "$env:USERPROFILE\Desktop\TCC-Analyzer"):   
`.\TCC-Analyzer.ps1 -Path "H:\macos-collector\Aftermath_Collection\tcc_<USERNAME>" -OutputDir "H:\MacOS-Analyzer-Suite"`  

> [!NOTE]
> The subdirectory 'TCC-Analyzer' is automatically created.  

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

## Links  
[Aftermath by Jamf Threat Labs](https://github.com/jamf/aftermath)  
[macos-collector by LETHAL-FORENSICS](https://github.com/LETHAL-FORENSICS/macos-collector)  

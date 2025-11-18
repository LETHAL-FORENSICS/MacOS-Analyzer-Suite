<p align="center"><a href="https://github.com/PowerShell/PowerShell"><img src="https://img.shields.io/badge/Language-Powershell-blue" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/Operating System-Windows-blue" style="text-align:center;display:block;"> <a href="https://github.com/LETHAL-FORENSICS/MacOS-Analyzer-Suite/releases/latest"><img src="https://img.shields.io/github/v/release/LETHAL-FORENSICS/MacOS-Analyzer-Suite?label=Release" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Digital%20Signature-Valid-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>  

# MacOS-Analyzer-Suite
A collection of PowerShell scripts for analyzing macOS Forensic Artifacts

## The following MacOS Forensic Artifacts are supported yet:

  * Aftermath Storyline &#8594; Storyline-Analyzer (WIP)
  * .DS_Store file(s) &#8594; DSStore-Analyzer (WIP)  
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
1. Download the latest version of the **MacOS-Analyzer-Suite** from the [Releases](https://github.com/LETHAL-FORENSICS/MacOS-Analyzer-Suite/releases/latest) section.
2. Install [ImportExcel](https://github.com/dfinke/ImportExcel) PowerShell module to import/export Excel spreadsheets, without Excel.  

   ```powershell
   Install-Module -Name ImportExcel
   ```  
3. Install [Python 3](https://www.python.org/downloads/windows/) and add it to your PATH environment variable.
4. Run the specific script in PowerShell (e.g. TCC-Analyzer.ps1). 
5. Optional: Edit `Config.json` to choose your own Excel color scheme. 

## Usage  
Open PowerShell and navigate to the directory containing e.g. TCC-Analyzer.ps1 and run the script with following command: `.\TCC-Analyzer.ps1`

![File-Browser](https://github.com/user-attachments/assets/0718a242-cae2-4236-b3d4-fd25e31fb8f5)  
**Fig 1:** Select your TCC Database file     

You can skip the file selection dialog and provide the file path to your log file with following command:  
`.\TCC-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\tcc_<USERNAME>"`  

You can specify the output directory with following command:   
`.\TCC-Analyzer.ps1 -Path "H:\macos-collector\tcc_<USERNAME>" -OutputDir "H:\MacOS-Analyzer-Suite"`  

> [!NOTE]
> Default output directory is `$env:USERPROFILE\Desktop\TCC-Analyzer`  
> The subdirectory 'TCC-Analyzer' is automatically created.  

<br>

![FSEvents-Analyzer](https://github.com/user-attachments/assets/5b6446f4-9814-464c-bcd9-44e7869b498b)  
**Fig 1:** FSEvents-Analyzer  

![MessageBox](https://github.com/user-attachments/assets/e425e413-90ca-452d-af15-cc68922e7157)  
**Fig 2:** MessageBox  

![Quarantine-Analyzer](https://github.com/user-attachments/assets/73b68c19-87be-4f1e-9ca6-45fb939c484f)  
**Fig 3:** Quarantine-Analyzer  

![TCC-Analyzer](https://github.com/user-attachments/assets/142b76a0-d46c-40b3-8d29-574f7f8e3bb8)  
**Fig 4:** TCC-Analyzer  

![XProtect-Analyzer](https://github.com/user-attachments/assets/3a9cccb9-20cc-4f10-8b90-ca04034a331a)  
**Fig 5:** XProtect-Analyzer  

![XProtect-BehaviorService](https://github.com/user-attachments/assets/1aa06ba6-1385-48be-8eae-4160becde5af)  
**Fig 6:** XProtect Behavior Service  

![Bastion-Rules](https://github.com/user-attachments/assets/a5664093-eda5-4dea-bea3-e2dee857e8ac)  
**Fig 7:** Bastion-Rules.xlsx (Stats)  

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

## Links  
[Aftermath by Jamf Threat Labs](https://github.com/jamf/aftermath)  
[macos-collector by LETHAL-FORENSICS](https://github.com/LETHAL-FORENSICS/macos-collector)  
[Arsenal Image Mounter (AIM)](https://arsenalrecon.com/products/arsenal-image-mounter)  
[APFS for Windows by Paragon Software](https://www.paragon-software.com/home/apfs-windows/)  

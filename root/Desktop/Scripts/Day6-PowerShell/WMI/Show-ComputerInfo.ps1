##############################################################################
#  Script: Show-ComputerInfo.ps1
#    Date: 30.May.2007
# Version: 1.0
#  Author: Jason Fossen (www.WindowsPowerShellTraining.com)
# Purpose: Demo a sampling of the kinds of information queryable through WMI.
#   Legal: Script provided "AS IS" without warranties or guarantees of any
#          kind.  USE AT YOUR OWN RISK.  Public domain, no rights reserved.
##############################################################################

"`n"
"----------------------------------------------------------"
"   Computer Information"
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_ComputerSystem" |
select-object Name,Domain,Description,Manufacturer,Model,NumberOfProcessors,`
TotalPhysicalMemory,SystemType,PrimaryOwnerName,UserName


"----------------------------------------------------------"
"   BIOS Information"
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_BIOS" |
select-object Name,Version,SMBIOSBIOSVersion


"----------------------------------------------------------"
"   CPU Information"
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_Processor" |
select-object Manufacturer,Name,CurrentClockSpeed,L2CacheSize


"----------------------------------------------------------"
"   Operating System Information"
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_OperatingSystem" | 
select-object Caption,BuildNumber,Version,SerialNumber,ServicePackMajorVersion,InstallDate


"----------------------------------------------------------"
"   Admin Accounts "
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_UserAccount" |
where-object {$_.SID -match '-500$'} | 
select-object Name


"----------------------------------------------------------"
"   Installed Hotfixes"
"----------------------------------------------------------"
get-wmiobject -query "SELECT * FROM Win32_QuickFixEngineering" |
select-object HotFixID


### This next one can take a while to run, not fun for demos...
# "----------------------------------------------------------"
# "   Installed Applications"
# "----------------------------------------------------------"
# get-wmiobject -query "SELECT * FROM Win32_Product" |
# select-object Name,Vendor,Version


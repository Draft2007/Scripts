##############################################################################
#  Script: Create-ProcessWithWMI.ps1
#    Date: 21.May.2007
# Version: 1.0
#  Author: Jason Fossen (www.WindowsPowerShellTraining.com)
# Purpose: Demo how to launch processes on remote computers with WMI.
#   Legal: Script provided "AS IS" without warranties or guarantees of any
#          kind.  USE AT YOUR OWN RISK.  Public domain, no rights reserved.
##############################################################################

param ($computer = ".", $commandline = "cmd.exe /k whoami.exe")


function Remote-Execute ($computer = ".", $commandline = $(throw "Enter the command to execute.") ) 
{
    $ProcessClass = get-wmiobject -query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -computername $computer
    $results = $ProcessClass.Create( $commandline )

    if ($results.ReturnValue -eq 0) { $results.ProcessID }  # Or just return $true if you don't want the PID.
    else { $false }
}


remote-execute -computer $computer -commandline $commandline





# Notes:
# Unlike PowerShell remoting, though, this method of remote command 
# execution does not return output data over the network back to you.
# The command "cmd.exe /k" opens a shell but does not terminate it.



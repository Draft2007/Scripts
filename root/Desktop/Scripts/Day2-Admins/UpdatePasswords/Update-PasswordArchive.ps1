####################################################################################
#.Synopsis 
#    Resets the password of a local user account with a random password which is 
#    then encrytped with your pubic key certificate. The plaintext password is 
#    displayed with the Recover-PasswordArchive.ps1 script. 
#
#.Description 
#    Resets the password of a local user account with a 15-25 character, random, 
#    complex password, which is encrytped with your own pubic key certificate. 
#    Recovery of the encrypted password from the file requires possession of the
#    private key corresponding to the chosen public key certificate.  The password
#    is never transmitted or stored in plaintext anywhere. The plaintext password 
#    is recovered with the companion Recover-PasswordArchive.ps1 script.  The
#    script must be run with administrative or local System privileges.  
#
#.Parameter CertificateFilePath 
#    The local or UNC path to the .CER file containing the public key 
#    certificate which will be used to encrypt the password.  The .CER
#    file can be DER- or Base64-encoded.  Any certificate with any
#    purpose(s) from any template can be used.
#
#.Parameter LocalUserName
#    Name of the local user account on the computer where this script is run
#    whose password should be reset to a 15-25 character, complex, random password.
#    Do not include a "\" or "@" character, only local accounts are supported.
#    Defaults to "Guest", but any name can be specified.
#
#.Parameter PasswordArchivePath
#    The local or UNC path to the folder where the archive files containing
#    encrypted passwords will be stored.
#
#.Parameter MinimumPasswordLength
#    The minimum length of the random password.  Default is 15.  The exact length
#    used is randomly chosen to increase the workload of an attacker who can see
#    the contents of this script.  Maximum password length defaults to 25.  The
#    smallest acceptable minimum length is 4 due to complexity requirements.
#
#.Parameter MaximumPasswordLength
#    The maximum length of the random password.  Default is 25.  Max is 127.
#    The minimum and maximum values can be identical.    
#
#.Example 
#    .\Update-PasswordArchive.ps1 -CertificateFilePath C:\certificate.cer -PasswordArchivePath C:\folder
#
#    Resets the password of the Guest account, encrypts that password 
#    with the public key in the certificate.cer file, and saves the encrypted
#    archive file in C:\folder.  Choose a different account with -LocalUserName.
#
#.Example 
#    .\Update-PasswordArchive.ps1 -CertificateFilePath \\server\share\certificate.cer -PasswordArchivePath \\server\share
#
#    UNC network paths can be used instead of local file system paths.  Password 
#    is not reset until after network access to the shared folder is confirmed.
#    The certificate and archive folders do not have to be the same.
#
#.Example 
#    .\Update-PasswordArchive.ps1 -LocalUserName HelpDeskUser -CertificateFilePath \\server\share\certificate.cer -PasswordArchivePath \\server\share
#
#    The local Guest account's password is reset by default, but any
#    local user name can be specified instead.
#
#
#Requires -Version 2.0 
#
#.Notes 
#  Author: Jason Fossen, Enclave Consulting (http://www.sans.org/windows-security/)  
# Version: 4.0
# Updated: 16.Nov.2013
#   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
#          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
#          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
#          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
#          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
#          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
####################################################################################


Param ($CertificateFilePath = ".\PublicKeyCert.cer", $LocalUserName = "Guest", $PasswordArchivePath = ".\", $MinimumPasswordLength = 15, $MaximumPasswordLength = 25) 


####################################################################################
# Function Name: Generate-RandomPassword
#   Argument(s): Integer for the desired length of password.
#       Returns: Pseudo-random complex password that has at least one of each of the 
#                following character types: uppercase letter, lowercase letter, 
#                number, and legal non-alphanumeric for a Windows password.
#         Notes: If the argument/password is less than 4 characters long, the 
#                function will return a 4-character password anyway.  Otherwise, the
#                complexity requirements won't be satisfiable.  Integers are 
#                generated, converted to Unicode code points (chars), and then
#                encoded as a UTF16LE string so that the function can be easily 
#                modified by users who are not using US-EN keyboards.  For the
#                sake of script compatibility, various characters are excluded
#                even though this reduces randomness.  
####################################################################################
function Generate-RandomPassword ($length = 15) 
{
    If ($length -lt 4) { $length = 4 }   #Password must be at least 4 characters long in order to satisfy complexity requirements.

    Do {
        [byte[]] $password = $null 

        $hasupper =     $false    #Has uppercase letter character flag.
        $haslower =     $false    #Has lowercase letter character flag.
        $hasnumber =    $false    #Has number character flag.
        $hasnonalpha =  $false    #Has non-alphanumeric character flag.
        $isstrong =     $false    #Assume password is not complex until tested otherwise.
        
        For ($i = $length; $i -gt 0; $i--)
        {
            [Int32] $x = get-random -min 33 -max 126      #Random Unicode code point numbers, currently set for US-ASCII, feel free to modify.
                                                          #This range eliminates the space character, which causes problems in other scripts.        
            If ($x -eq 34) { $x-- }                       #Eliminates double-quote.  This is also how it is possible to get "!" in a password character.
            If ($x -eq 39) { $x-- }                       #Eliminates single-quote, causes problems in scripts.
            If ($x -eq 47) { $x-- }                       #Eliminates the forward slash, causes problems for net.exe.
            If ($x -eq 96) { $x-- }                       #Eliminates the backtick, causes problems for PowerShell.
            If ($x -eq 48 -or $x -eq 79) { $x++ }         #Eliminates zero and capital O, which causes problems for humans. 
            
            $password += [System.BitConverter]::GetBytes( [System.Char] $x ) 

            If ($x -ge 65 -And $x -le 90)  { $hasupper = $true }   #Non-USA users may wish to customize the Unicode code point numbers by hand 
            If ($x -ge 97 -And $x -le 122) { $haslower = $true }   #instead of relying on the built-in IsLower, IsUpper, etc. functions.
            If ($x -ge 48 -And $x -le 57)  { $hasnumber = $true } 
            If (($x -ge 33 -And $x -le 47) -Or ($x -ge 58 -And $x -le 64) -Or ($x -ge 91 -And $x -le 96) -Or ($x -ge 123 -And $x -le 126)) { $hasnonalpha = $true } 
            If ($hasupper -And $haslower -And $hasnumber -And $hasnonalpha) { $isstrong = $true } 
        } 
    } While ($isstrong -eq $false)

    ([System.Text.Encoding]::Unicode).GetString($password) #No ambiguity, make sure output is encoded as UTF16LE. 
}




####################################################################################
# Returns true if password reset accepted, false if there is an error.
# Only works on local computer, but can be modified to work remotely too.
####################################################################################
Function Reset-LocalUserPassword ($UserName, $NewPassword)
{
    Try 
    {
        $ADSI = [ADSI]("WinNT://" + $env:ComputerName + ",computer")
        $User = $ADSI.PSbase.Children.Find($UserName)
        $User.PSbase.Invoke("SetPassword",$NewPassword)
        $User.PSbase.CommitChanges()
        $User = $null 
        $ADSI = $null
        $True
    }
    Catch
    { $False } 
}



####################################################################################
# Writes to console, writes to Application event log, optionally exits.
# Event log: Application, Source: "PasswordArchive", Event ID: 9013
####################################################################################
function Write-StatusLog ( $Message, [Switch] $Exit )
{
    # Define the Source attribute for when this script writes to the Application event log.
    New-EventLog -LogName Application -Source PasswordArchive -ErrorAction SilentlyContinue

    "`n" + $Message + "`n"

#The following here-string is written to the Application log only when there is an error, 
#but it contains information that could be useful to an attacker with access to the log.
#The data is written for troubleshooting purposes, but feel free change it if concerned.
#It does not contain any passwords of course.
$ErrorOnlyLogMessage = @"
$Message 

CurrentPrincipal = $($CurrentPrincipal.Identity.Name)

CertificateFilePath = $CertificateFilePath 

LocalUserName = $LocalUserName

PasswordArchivePath = $PasswordArchivePath

ArchiveFileName = $filename
"@

    if ($Exit)
    { write-eventlog -logname Application -source PasswordArchive -eventID 9013 -message $ErrorOnlyLogMessage -EntryType Error }
    else
    { write-eventlog -logname Application -source PasswordArchive -eventID 9013 -message $Message -EntryType Information }

    if ($Exit) { exit } 
}


# Sanity check the two password lengths:
if ($MinimumPasswordLength -le 3) { $MinimumPasswordLength = 4 } 
if ($MaximumPasswordLength -gt 127) { $MaximumPasswordLength = 127 } 
if ($MinimumPasswordLength -gt 127) { $MinimumPasswordLength = 127 } 
if ($MaximumPasswordLength -lt $MinimumPasswordLength) { $MaximumPasswordLength = $MinimumPasswordLength }



# Confirm that this process has administrative privileges to reset a local password.
$CurrentWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = new-object System.Security.Principal.WindowsPrincipal($CurrentWindowsID)
if (-not $? -or -not $CurrentPrincipal.IsInRole("Administrators")) 
   { write-statuslog -m "ERROR: This process lacks the privileges necessary to reset a password." -exit }



# Confirm that the target local account exists and that ADSI is accessible.
if ($LocalUserName -match '[\\@]')  { write-statuslog -m "ERROR: This script can only be used to reset the passwords of LOCAL user accounts, please specify a simple username without an '@' or '\' character in it." -exit }  
try 
{ 
    $ADSI = [ADSI]("WinNT://" + $env:ComputerName + ",computer") 
    $User = $ADSI.PSbase.Children.Find($LocalUserName)
    $User = $null
    $ADSI = $null 
}
catch 
{ write-statuslog -m "ERROR: Local user does not exist: $LocalUserName" -exit } 



# Get the public key certificate.
if (Resolve-Path -Path $CertificateFilePath)
{ $CertificateFilePath = $(Resolve-Path -Path $CertificateFilePath).Path }
else
{ write-statuslog -m "ERROR: Cannot resolve path to certificate file: $CertificateFilePath" -exit }


if ($CertificateFilePath -ne $null -and $(test-path -path $CertificateFilePath))
{
    [Byte[]] $certbytes = get-content -encoding byte -path $CertificateFilePath 
    $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certbytes)
    if (-not $? -or ($cert.GetType().fullname -notlike "*X509*")) 
       { write-statuslog -m "ERROR: Invalid or corrupt certificate file: $CertificateFilePath" -exit }  
}
else
{ write-statuslog -m "ERROR: Could not find the certificate file: $CertificateFilePath" -exit }



# Construct name of the archive file, whose name will also be used as a nonce.
# Ticks string will be 18 characters, certificate SHA* hash will be at least 40 characters, plus some user/computer name bytes.
$filename = $env:computername + "+" + $LocalUserName + "+" + $(get-date).ticks + "+" + $cert.thumbprint
if ($filename.length -le 60) { write-statuslog -m "ERROR: The archive file name is invalid (too short): $filename " -exit } 


# Generate and test new random password with min and max lengths.
$newpassword = "ConfirmThatNewPasswordIsRandom"

if ($MinimumPasswordLength -eq $MaximumPasswordLength)
{  
    $newpassword = Generate-RandomPassword -Length $MaximumPasswordLength
} 
else
{ 
    $newpassword = Generate-RandomPassword -Length $(Get-Random -Minimum $MinimumPasswordLength -Maximum $MaximumPasswordLength) 
}

# Users outside USA might modify the Generate-RandomPassword function, hence this check.
if ($newpassword -eq "ConfirmThatNewPasswordIsRandom") 
{ write-statuslog -m "ERROR: Password generation failure, password not reset." -exit } 


# Construct the array of bytes to be hashed and then encrypted.
# Prepend first 60 characters of the $filename as a nonce to the new password.
# This is done for the sake of integrity checking later in the Recover-PasswordArchive.ps1 script.
[byte[]] $bytes = @() 
$bytes += [System.Text.Encoding]::Unicode.GetBytes( $filename.substring(0,60) ) 
$bytes += [System.Text.Encoding]::Unicode.GetBytes( $newpassword ) 


# Get the SHA256 hash of the bytes to be encrypted and prepend them to $bytes array.
$SHA256Hasher = [System.Security.Cryptography.SHA256]::Create()
[Byte[]] $hash = $SHA256Hasher.ComputeHash( $bytes )  #Produces 32 bytes.
$bytes = ($hash += $bytes) 
$SHA256Hasher.Dispose()


# Hence, the $bytes array at this point now has this format:
#     32 bytes : SHA256 hash of the rest of the bytes.
#    120 bytes : Computer+User+Ticks+Thumbprint (60 two-byte chars = 120 bytes).
#     ?? bytes : All remaining bytes are for the UTF16 password, which is variable in length.


# Encrypt $bytes with 256-bit Rijnael key (can't use AES directly, it requires .NET 3.5 or later).
$Rijndael = New-Object -TypeName System.Security.Cryptography.RijndaelManaged
$Rijndael.GenerateKey()
$Rijndael.GenerateIV()
$Rijndael.Padding = [System.Security.Cryptography.PaddingMode]::ISO10126 
$Encryptor = $Rijndael.CreateEncryptor()
$MemoryStream = New-Object -TypeName System.IO.MemoryStream
$StreamMode = [System.Security.Cryptography.CryptoStreamMode]::Write  
$CryptoStream = New-Object -TypeName System.Security.Cryptography.CryptoStream -ArgumentList $MemoryStream,$Encryptor,$StreamMode
$CryptoStream.Write($bytes, 0, $bytes.Length) #Fill MemoryStream with encrypted bytes.
$CryptoStream.Dispose() #Must come after the Write() or else "padding error" when decrypting.
[byte[]] $EncryptedBytes = $MemoryStream.ToArray() 
$MemoryStream.Dispose()


# Encrypt the Rijndael key and IV (32 + 16 bytes) with the public key, then
# append the Rijndael-encrypted payload to the end of it:
[byte[]] $cipherbytes = $cert.publickey.key.encrypt(($Rijndael.Key + $Rijndael.IV),$false) #Must be $false for smart card to work.
if (-not $? -or $cipherbytes.count -lt 40) { write-statuslog -m "ERROR: Encryption of symmetric key failed, password not reset." -exit } 
$cipherbytes = $cipherbytes + $EncryptedBytes
if (-not $? -or $cipherbytes.count -lt 280) { write-statuslog -m "ERROR: Encryption of payload failed, password not reset." -exit } 


# Hence, the $cipherbytes array at this point now has this format (280 byte min):
#     ?? bytes : Encrypted Rijndael key and IV, variable in length, same size as public key, but at least 128 bytes for 1024-bit pub key.
#     32 bytes : SHA256 hash of the rest of the bytes.
#    120 bytes : Computer+User+Ticks+Thumbprint (60 two-byte chars = 120 bytes).
#     ?? bytes : All remaining bytes are for the UTF16 password, which is variable in length.


# Must save encrypted password file before resetting the password, confirm before proceeding.
if (Resolve-Path -Path $PasswordArchivePath)
{ $PasswordArchivePath = $(Resolve-Path -Path $PasswordArchivePath).Path }
else
{ write-statuslog -m "ERROR: Cannot resolve path to archive folder: $PasswordArchivePath" -exit }

if (-not $(test-path -pathtype container -path $PasswordArchivePath)) 
{ write-statuslog -m "ERROR: Archive path not accessible: $PasswordArchivePath" -exit } 

if ($PasswordArchivePath -notlike "*\") { $PasswordArchivePath = $PasswordArchivePath + "\" } 

$cipherbytes | set-content -encoding byte -path ($PasswordArchivePath + $filename) 
if (-not $?) { write-statuslog -m "ERROR: Failed to save archive file, password not reset." -exit } 

if (-not $(test-path -pathtype leaf -path $($PasswordArchivePath + $filename))){ write-statuslog -m "ERROR: Failed to find archive file, password not reset." -exit } 



# Attempt to reset the password.
if ( Reset-LocalUserPassword -UserName $LocalUserName -NewPassword $newpassword )
{
    remove-variable -name newpassword  #Just tidying up, not really necessary at this point...
    write-statuslog -m "SUCCESS: $LocalUserName password reset and archive file saved."  
}
else
{
    # Write the RESET-FAILURE file to the archive path; these failure files are used by the other scripts too.
    $filename = $env:computername + "+" + $LocalUserName + "+" + $(get-date).ticks + "+PASSWORD-RESET-FAILURE"
    "ERROR: Failed to reset password after creating a success file:`n`n" + $error[0] | set-content -path ($PasswordArchivePath + $filename) 
    write-statuslog -m "ERROR: Failed to reset password after creating a success file:`n`n $error[0]" -exit 
} 


# FIN
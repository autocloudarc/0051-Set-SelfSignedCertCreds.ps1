#Requires -PSEdition Desktop
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOP\SIS
Secure credentials in automated scripts.

.DESCRIPTION
This scripts will use a document encryption certificate to encrypt and decrypt service account passwords used to execute interactive or scheduled scripts or commands.

.PARAMETER netDirectory
Directory path where the encrypted password file pw.txt, clear-text username file upn.txt and the self-signed client authentication certificate PSScriptCipherCert.pfx will be stored.
You may find it convenient to specify a server file share path, i.e. \\<server>\<share>\<directory>\pw.txt as a central location to save these artifacts.
This way, you can log on with the same service account on another machine and import the same decryption certificate to decrypt the password during script execution when required.

.PARAMETER logDirectory
Log directory for transcript, i.e. "\\<server>\<share>\logs"

.PARAMETER svcAccountName
Service account name that will be used to execute commands and scripts in common name or sAMAccountName format, i.e. ServiceAccount, NOT ServiceAccount@domain.com 

.PARAMETER ExportCert
This is a switched parameter that when specified performs the following actions:
1. Creates a new self-signed SSL certificate.
2. Requests the username and password credential set for the service account that will be used to execute scripts.
3. Encrypts the password.
4. Exports the encrypted password to the pw.txt file stored at the $netDirectory path, i.e. \\<server>\<share>\<directory>\pw.txt
5. Exports the clear-text username in UPN format, i.e. svc.AccountName@domain.com to the path, i.e. \\<server>\<share>\<directory>\upn.txt
6. Exports the self-signed certificate PSScriptCipherCert.pfx with the password protected private key to the path \\<server>\<share>\<directory>\PSScriptCipherCert.pfx

.PARAMETER supressPrompts
This parameter will suppress prompting so that automated script that dot source this script will not be interrupted if executed interactively or scheduled.
For this to work the following conditions must first be satisfied:
1. The certificate must already be installed in the current user personal store of the logged on user that will be running the script which dot sources this one (Set-SelfSignedCertCreds.ps1)
2. The ExportCert switch must not be used since the intent is to use the existing certificate already instealled instead of creating a new one.

.EXAMPLE
[WITH the -ExportCert switch parameter]
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccountName> -ExportCert -Verbose
In this example, a new self-signed certificate will be created and installed. The service account password for the service account name specified will be encrypted and exported to a file share, along with the username.
The certificate will also be exported from the current machine. The verbose switch is added to show details of certain operations.
NOTE: If you are using VSCode to run this script, use this expression to dot source the script so that the variables will be available in your session after the script executes.
. .\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccountName> -Verbose

.EXAMPLE
[WITHOUT the -ExportCert switch parameter]
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccountName> -Verbose
This command will import the self-signed certificate associated with the service account name if required on a machine, retrieve the previously exported credentials, 
then use the certificate to decrypt the password component of the credential.
NOTE: If you are using VSCode to run this script, use this expression to dot source the script so that the variables will be available in your session after the script executes.
. .\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccountName> -Verbose

.EXAMPLE
[WITHOUT THE -ExportCert AND WITH the -SuppressPrompts switch parameter]
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccounName> -SuppressPrompts -Verbose
This command will import the self-signed certificate if required on a machine, retrieve the previously exported credentials associated with the service account name specified, 
then use the certificate to decrypt the password component of the credential. In this case, all interactive prompts will be suppressed, but transcript logging will continue.
This switch is intended for non-interactive scenarios such as dot sourcing this script from another in order to retrieve the service account credential set for use in the main script.
NOTE: If you are using VSCode to run this script, use this expression to dot source the script so that the variables will be available in your session after the script executes.
. .\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -svcAccountName <svcAccountName> -Verbose

Manual integration test suite:

# Test parameters
# TASK-ITEM: Update these parameters with your own custom values for your environment.
$remoteTestMachine = "<remoteTestMachine>"
$scriptPath = "<scriptPath>"
$scriptContent = "Get-ChildItem -Path 'c:\'"

# Test case 1.0: To test a command interactively, use the following expression:
# tc1.1 Interactive command test
Invoke-Command -Computername $remoteTestMachine -ScriptBlock { Get-Childitem -Path "c:\" } -Credential $svcAccountCred

# Test case 2.0: Register scheduled job using a script file, which contains the code: Get-ChildItem -Path "c:\" 
# tc2.1 Register the job using the script file
Register-ScheduledJob -Name psjob1 -FilePath $scriptPath -Credential $svcAccountCred
# tc2.2 Create a trigger for 10 seconds from now
$trigger1 = New-JobTrigger -At (Get-Date).AddSeconds(10) -Once -Verbose
# t2.3 Add the trigger to the job
Add-JobTrigger -Name psjob1 -Trigger $trigger1 -Verbose
# t2.4 After 20 seconds, get the job information.
Start-Sleep -seconds 20 -Verbose
Get-ScheduledJob -Name psjob1 -Verbose
# t2.5 Retieve the results
Receive-Job -Name psjob1 -Keep -Verbose
# t2.6 The scheduled jobs will appear at in the Task Scheduler at the path: Microsoft\Windows\PowerShell\ScheduledJobs
# t2.7 Remove the job 
Get-ScheduledJob -Name psjob1 | Unregister-ScheduledJob -Verbose

# Test case 3.0: Register scheduled job using a script block  
# t3.1 Register scheduled job
Register-ScheduledJob -Name psjob2 -ScriptBlock { Get-ChildItem -Path "\\azrads1003.dev.adatum.com\c$" } -Credential $svcAccountCred -Verbose
# t3.2 Create a trigger for 10 seconds from now
$trigger = New-JobTrigger -At (Get-Date).AddSeconds(10) -Once -Verbose
# t3.3 Add the trigger to the job
Add-JobTrigger -Name psjob2 -Trigger $trigger -Verbose
# t3.4 After 20 seconds, get the job information.
Start-Sleep -seconds 20 -Verbose
Get-ScheduledJob -Name psjob2 -Verbose
# t3.5 Retieve the results
Receive-Job -Name psjob2 -Keep -Verbose
# t3.6 The scheduled jobs will appear at in the Task Scheduler at the path: Microsoft\Windows\PowerShell\ScheduledJobs
# t3.6 Remove the job 
Get-ScheduledJob -Name psjob2 | Unregister-ScheduledJob -Verbose

# c1.0 Cleanup and reset test environment. Verify that all jobs have been removed to prepare for subsequent testing.
# c1.1 Show scheduled jobs if available 
Get-ScheduledJob -ErrorAction "SilentlyContinue" -Verbose

# c2.0 To remove the currently installed certificate for re-testing the -ExportCert scenario, run the following command:
# c2.1 Remove install self-signed certificates
Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object { $_.Subject -match "-PSScriptCipherCert" } | Remove-Item -Force

.INPUTS
None

.OUTPUTS
The outputs generated from this script includes:
1. A transcript log file to provide the full details of script execution. It will use the name format: Set-SecureCredentials-TRANSCRIPT-<Date-Time>.log

.NOTES
The MIT License (MIT)
Copyright (c) 2018 Preston K. Parsard

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

LEGAL DISCLAIMER:
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights.

.LINK
1: https://www.codeguru.com/columns/dotnet/using-self-signed-certificates-to-encrypt-text.html
2: https://www.cgoosen.com/2015/02/using-a-certificate-to-encrypt-credentials-in-automated-powershell-scripts/
3: https://www.cgoosen.com/2016/05/using-a-certificate-to-encrypt-credentials-in-automated-powershell-scripts-an-update/
4: https://www.iso.org/obp/ui/#iso:std:iso-iec:27005:ed-3:v1:en
5: https://www.iso.org/isoiec-27001-information-security.html
6: https://www.techrepublic.com/blog/data-center/powershell-code-to-store-user-credentials-encrypted-for-re-use/
7: https://sid-500.com/2018/02/24/powershell-encrypt-and-store-your-passwords-and-use-them-for-remote-authentication-protect-cmsmessage/
8: https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Security/ConvertFrom-SecureString?view=powershell-5.0
9: https://en.wikipedia.org/wiki/Data_Protection_API#frb-inline
10: http://www.powertheshell.com/searching-for-file-attributes/
11: https://blogs.technet.microsoft.com/ashleymcglone/2017/08/29/function-to-create-certificate-template-in-active-directory-certificate-services-for-powershell-dsc-and-cms-encryption/

.COMPONENT
Task Scheudler, Scripts, Authentication, Credentials, Certificates

.ROLE
Automation Engineer
DevOps Engineer

.FUNCTIONALITY
Encrypts and decrypts service account credentials during PowerShell script execution.
#>

<#
	TASK-ITEM: 00.00.0001 Notes
#>

[CmdletBinding(DefaultParameterSetName = "Allow Prompts")]
param
(
    # Target directory for exporting credentials and certificate.
    [parameter(Mandatory = $true,
        HelpMessage = "Enter a file server or local path \\<server>\share\directory where you want to host your *.pfx self-signed certificate, password file and username file")]
    [ValidateScript( {Test-Path -Path $_ })]
    [string]$netDirectory,

    # Log directory for transcript logs, i.e. "\\server\share\logs"
    [Parameter(Mandatory = $true,
        HelpMessage = "Enter the file server or local path for the transcript log files.")]
    [string]$logDirectory,

    # Include the service account name that will be used to execute commands or scripts
    [Parameter(Mandatory=$true,
        HelpMessage = "Enter the service account common or sAMAccountName, i.e. ServiceAccount WITHOUT the domain suffix.")]
        [ValidateScript({$_ -notmatch "[\@]+[\w+|\d+|\.]+"})]
        [string]$svcAccountName,

    # Specifies that a new certificate will be generated, installed and used to encrypt the service account credentials.
    # The certificate and credentials will then be exported to $netDirectory into desginated files, such as pw.txt, upn.txt and PSScriptCipherCert.pfx
    [parameter(ParameterSetName = "Allow Prompts")]
    [switch]$ExportCert,

    # Suppress prompts for dot sourced interactive or scheduled tasks script execution
    [parameter(ParameterSetName = "Suppress Prompts")]
    [switch]$SuppressPrompts
) # end param

#region INITIALIZE ENVIRONMENT
Set-StrictMode -Version Latest
#endregion INITIALIZE ENVIRONMENT

#region FUNCTIONS
function New-LogFiles
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPrefix
    ) # end param

    # Get curent date and time
    $TimeStamp = (get-date -format u).Substring(0, 16)
    $TimeStamp = $TimeStamp.Replace(" ", "-")
    $TimeStamp = $TimeStamp.Replace(":", "")

    # Construct transcript file full path
    $TranscriptFile = "$LogPrefix-TRANSCRIPT" + "-" + $TimeStamp + ".log"
    $script:Transcript = Join-Path -Path $LogDirectory -ChildPath $TranscriptFile

    # Create log and transcript files
    New-Item -Path $Transcript -ItemType File -ErrorAction SilentlyContinue
} # end function

function script:New-Header
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$label,
        [Parameter(Mandatory = $true)]
        [int]$charCount
    ) # end param

    $script:header = @{
        # Draw double line
        SeparatorDouble = ("=" * $charCount)
        Title           = ("$label :" + " $(Get-Date)")
        # Draw single line
        SeparatorSingle = ("-" * $charCount)
    } # end hashtable
} # end function
function New-PromptObjects
{
    # Create prompt and response objects
    [CmdletBinding()]
    param (
        [AllowNull()]
        [AllowEmptyCollection()]
        [PScustomObject]$PromptsObj,

        [AllowNull()]
        [AllowEmptyCollection()]
        [PScustomObject]$ResponsesObj
    ) # end param

    # Create and populate prompts object with property-value pairs
    # PROMPTS (PromptsObj)
    $script:PromptsObj = [PSCustomObject]@{
        pVerifySummary = "Is this information correct? [YES/NO]"
        pAskToOpenLogs = "Would you like to open the transcript log now ? [YES/NO]"
    } #end $PromptsObj

    # Create and populate responses object with property-value pairs
    # RESPONSES (ResponsesObj): Initialize all response variables with null value
    $script:ResponsesObj = [PSCustomObject]@{
        pProceed     = $null
        pOpenLogsNow = $null
    } #end $ResponsesObj
} # end function

function Install-AdModuleIfRequired
{
    [CmdletBinding()]
    param()
    # Install the ActiveDirectory module
    If (-not(Get-WindowsFeature -Name RSAT-AD-PowerShell).InstallState)
    {
        Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeManagementTools -Verbose -Confirm:$false
    } # end if
} # end function
function Get-SvcAccountCredential
{
    [OutputType([string])]
    [CmdletBinding()]
    # Retrieve the installed certificate
    $importedCert = Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object {$_.Subject -match "$($SelfSignedCertParams.Subject)"}
    $EncryptedPwd = Get-Content -Path $pwFilePath
    # Decrypt password
    $DecryptedPwd = $EncryptedPwd | Unprotect-CmsMessage -To $certCn
    return $DecryptedPwd
} # end function
function Get-PrivateKeyCredentials
{
    [OutputType([SecureString])]
    [CmdletBinding()]
    param
    (
    ) # end params
    $privateKeyCred = Get-Credential -Message "Enter encryption certificate private key password" -UserName $pfxUserName
    $privateKeySecurePw = $privateKeyCred.GetNetworkCredential().SecurePassword
    return $privateKeySecurePw
} # end function

function Get-InitialValues
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateScript({(Get-ADUser -Identity $_)})]
        [string]$svcAccountName
    ) # end param

    # Create parameters for document encryption certificate
    $SelfSignedCertParams = 
    @{
        KeyDescription    = "PowerShell Script Encryption-Decryption Key"
        Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        KeyFriendlyName   = "PSScriptEncryptDecryptKey"
        FriendlyName      = "$svcAccountName-PSScriptCipherCert"
        Subject           = "$svcAccountName-PSScriptCipherCert"
        KeyUsage          = "DataEncipherment"
        Type              = "DocumentEncryptionCert"
        HashAlgorithm     = "sha256"
        CertStoreLocation = "Cert:\CurrentUser\My"
    } # end params

    # Convert certificate subject to cn= format.
    $certCn =  "cn=$($SelfSignedCertParams.Subject)"

    $pwFile = "$svcAccountName-pw.txt"
    $upnFile = "$svcAccountName-upn.txt"
    $svcSubDir = Join-Path -Path $netDirectory -ChildPath $svcAccountName
    If (-not(Test-Path -path $svcSubDir))
    {
        New-Item -Path $svcSubDir -ItemType Directory
    } # end if
    $pwFilePath = Join-Path -Path $svcSubDir -ChildPath $pwFile
    $upnFilePath = Join-Path -Path $svcSubDir -ChildPath $upnFile
    $pfxUserName = "$svcAccountName-PrivateKeyPassword"
    $pfxCertFileName = $SelfSignedCertParams.Subject + ".pfx"
    $pfxFilePath = Join-path $svcSubDir -ChildPath $pfxCertFileName
} # end function
#endregion FUNCTIONs

#region INITIALIZE VALUES

# Create Log file
[string]$Transcript = $null

$scriptName = $MyInvocation.MyCommand.name
# Use script filename without exension as a log prefix
$LogPrefix = $scriptName.Split(".")[0]

# funciton: Create log files for transcript
New-LogFiles -LogDirectory $LogDirectory -LogPrefix $LogPrefix -Verbose

Start-Transcript -Path $Transcript -IncludeInvocationHeader -Verbose

# Create prompt and response objects for continuing script and opening logs.
$PromptsObj = $null
$ResponsesObj = $null

# function: Create prompt and response objects
New-PromptObjects -PromptsObj $PromptsObj -ResponsesObj $ResponsesObj -Verbose

$BeginTimer = Get-Date -Verbose

Install-AdModuleIfRequired -Verbose

# Request service account username
<#
Write-Output "Requesting the service account username. (This will not be encrypted)"
Do
{
    $svcAccount = Read-Host -Prompt "Enter service account username that will be used to run powershell scripts, i.e. svc.scripts. Do not include the UPN suffix: $($(Get-ADDomain).DnsRoot)"
    Write-Output ""
} until (Get-ADUser -Identity $svcAccount)
#>

$svcAccountUpn = $svcAccountName + "@" + $(($env:USERDNSDOMAIN).ToLower())

# Dot source the Get-InitialValues to bring the function scope values into the script scope.
. Get-InitialValues -SvcAccountName $svcAccountName

Write-Output "`$upnFile: $upnFile"

# Populate summary display object
# Add properties and values
$SummObj = [PSCustomObject]@{
    svcAccountUpn = $svcAccountUpn;
    netDirectory    = $netDirectory;
    transcript      = $Transcript;
    exportCert      = $ExportCert;
    suppressPrompts = $SuppressPrompts;
} #end $SummObj

# funciton: Create new header
$label = "SET SECURE CREDENTIALS WITH A SELF-SIGNED CERTIFICATE"
New-Header -label $label -charCount 200 -Verbose

# function: Create prompt and responses objects ($PromptsObj, ResponsesObj)
New-PromptObjects -Verbose

#endregion INITIALIZE VALUES

Write-Output $header.SeparatorDouble  -Verbose
Write-Output $Header.Title  -Verbose
Write-Output $header.SeparatorSingle  -Verbose

# Display Summary of initial parameters and constructed values
Write-Output $SummObj  -Verbose
Write-Output $header.SeparatorDouble  -Verbose

if (-not($SuppressPrompts))
{
    Do
    {
        $ResponsesObj.pProceed = read-host $PromptsObj.pVerifySummary
        $ResponsesObj.pProceed = $ResponsesObj.pProceed.ToUpper()
    } # end do
    Until ($ResponsesObj.pProceed -eq "Y" -OR $ResponsesObj.pProceed -eq "YES" -OR $ResponsesObj.pProceed -eq "N" -OR $ResponsesObj.pProceed -eq "NO")

    # Record prompt and response in log
    Write-Output $PromptsObj.pVerifySummary  -Verbose
    Write-Output $ResponsesObj.pProceed  -Verbose
}  # end if

#region MAIN
# Exit if user does not want to continue
if ($ResponsesObj.pProceed -eq "N" -OR $ResponsesObj.pProceed -eq "NO")
{
    Write-Output "Script terminated by user..."  -Verbose
    PAUSE
    EXIT
} #end if ne Y
else
{
    # If the -ExportCert switch paramter WAS included in the command, then create and import new self-signed certificate, get credentials and export both certificate and credentials.
    # NOTE: If you're setting this up for the first time, then the -ExportCert switch must be used initially since this option will create the certificate for subsequent decryption operations.
    If ($ExportCert)
    {
        $ExportCertMessage = @"
	The following actions will be performed:
	1. Create a new self-signed SSL certificate.
	2. Request password for the service account that will be used to execute scripts.
	3. Encrypt the service account password for $svcAccountUpn
	4. Export the encrypted password to the $pwFile file stored at the path: $pwFilePath
	5. Export the clear-text username that you provided as $svcAccountUpn to the path: $upnFilePath
	6. Export the self-signed certificate PSScriptCipherCert.pfx with the password protected private key to the path: $pfxFilePath

	PLEASE PRESS [ENTER] TO CONTINUE OR [CTRL-C] TO QUIT.
"@

        # List operations provided by the ExportCert switch
        Write-output $ExportCertMessage  -Verbose
        pause
        Write-output ""  -Verbose

        # Check for password file
        Write-output "Checking for $pwFilePath and creating it if required" 
        if (-not(Test-Path -Path $pwFilePath))
        {
            New-Item -Path $pwFilePath -ItemType File -Force -Verbose
        } # end if

        # Check for username file
        Write-output "Checking for $upnFilePath and creating it if required" 
        if (-not(Test-Path -Path $upnFilePath))
        {
            New-Item -Path $upnFilePath -ItemType File -Force -Verbose
        } # end if

        # Check if certificate is already installed
        Write-output "Checking for self-signed certificate $($SelfSignedCertParams.FriendlyName) at $($SelfSignedCertParams.CertStoreLocation) and creating it if required" 
        If (-not(Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object {$_.Subject -match "$($SelfSignedCertParams.Subject)"}))
        {
            # Create and install certificate
            Write-output "Creating the $($SelfSignedCertParams.FriendlyName) self-signed certificate and installing at $($SelfSignedCertParams.CertStoreLocation) ." 
            # Create new Self-Signed certificate with splatted parameters
            New-SelfSignedCertificate @SelfSignedCertParams -Verbose
        } # end if
        # Get certificate
        Write-output "Retrieving the installed certificate $($SelfSignedCertParams.FriendlyName) so it can be used for encrypting the service account password." 
        # Retrieve the installed certificate
        $exportedCert = Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object {$_.Subject -match "$($SelfSignedCertParams.Subject)"}

        # Request service account password
        Write-output "Requesting the service account password. (This will be encrypted)" 
        $cred = Get-Credential -Message "Enter the service account password that will be used to execute scripts." -UserName $svcAccountUpn

        # Encrypt service account password
        Write-output "Encrypting service account password." 
        $svcAccountName = $cred.GetNetworkCredential().UserName
        $svcAccountPassword = $cred.GetNetworkCredential().Password

        # Encrypt password
        $EncryptedPwd = $svcAccountPassword | Protect-CmsMessage -To $certCn

        # Write service account username to UPN file
        Write-output "Exporting service account username: $svcAccountName to $upnFilePath." 
        Set-Content -Path $upnFilePath -Value $svcAccountName -Force -Verbose

        # Write encrypted password to shared password file
        Write-output "Exporting service account password for $svcAccountName to $pwFilePath."  -Verbose
        Set-Content -Path $pwFilePath -Value $EncryptedPwd -Force -Verbose

        # Show username
        Write-output "Showing exported [username] $svcAccountName from $upnFilePath."  -Verbose
        Write-Output "Service account name"
        Get-Content -Path $upnFilePath -Verbose

        # Show encrypted password
        Write-output "Showing exported encrypted [password] for $svcAccountName from $pwFilePath."  -Verbose
        Get-Content -Path $pwFilePath -Verbose

        # Get-PrivateKeyCredentials
        # Export certificate
        Write-output "Requesting private key password for certificate $($SelfSignedCertParams.Subject) and exporting to $pfxFilePath."  -Verbose
        Export-PfxCertificate -FilePath $pfxFilePath -Cert $exportedCert -Password $(Get-PrivateKeyCredentials) -Force -Verbose
    } # end if
    # If the -ExportCert switch parameter was NOT included in the command, then import self-signed certificate if required, then retrieve and decrypt the service account credentials using the certificate.
    else
    {
        If (-not($SuppressPrompts))
        {
            $ImportCertMessage = @"
			The following actions will be performed:
			1. Import the certificate $($SelfSignedCertParams.Subject) if not already imported and installed to $($SelfSignedCertParams.CertStoreLocation) for the current user account."
			2. Retrieve the username and password credential set for the service account that will be used to execute scripts.
			3. Decrypt the password for the service account using the imported certificate.
			4. Construct a credential set based on the retrieved service account username and the decrypted service account password.

			PLEASE PRESS [ENTER] TO CONTINUE OR [CTRL-C] TO QUIT.
"@
            Write-output $ImportCertMessage  -Verbose
            pause
        } # end if

        # Import certificate
        Write-output "Importing certificate $($SelfSignedCertParams.Subject) into certificate store location $($SelfSignedCertparams.CertStoreLocation) if required."  -Verbose
        if (-not(Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object {$_.Subject -match "$($SelfSignedCertParams.Subject)"}))
        {
            Import-PfxCertificate -FilePath $pfxFilePath -CertStoreLocation $SelfSignedCertParams.CertStoreLocation -Exportable -Password $(Get-PrivateKeyCredentials) -Verbose
        } # end if

        # Get service account username
        Write-output "Retrieving clear-text service account username"  -Verbose
        $clearTextUpn = Get-Content -Path $upnFilePath

        # Get service account password and decrypt it
        Write-output "Retrieving encrypted service account password and decrypting it"  -Verbose
        $DecryptedPwd = Get-SvcAccountCredential

        # Create secure credential objects
        Write-output "Constructing credential set to use in PowerShell commands and scripts"  -Verbose
        $SecurePwd = $DecryptedPwd | ConvertTo-SecureString -AsPlainText -Force
        $svcAccountCred = [pscredential]::new($clearTextUpn, $SecurePwd)

        # Show credentials
        Write-output "Showing constructed credential set `$svcAccountCred"  -Verbose
        $svcAccountCred
    } # end else
} # end else
#endregion MAIN

#region SUMMARY

# Calculate elapsed time
Write-Output "Calculating script execution time..."  -Verbose
Write-Output "Getting current date/time..."  -Verbose
$StopTimer = Get-Date
$EndTime = (((Get-Date -format u).Substring(0, 16)).Replace(" ", "-")).Replace(":", "")
Write-Output "Calculating elapsed time..."  -Verbose
$ExecutionTime = New-TimeSpan -Start $BeginTimer -End $StopTimer -Verbose

$Footer = "SCRIPT COMPLETED AT: "
$EndOfScriptMessage = "End of script!"

Write-output $header.SeparatorDouble  -Verbose
Write-output "$Footer $EndTime"  -Verbose
Write-output "TOTAL SCRIPT EXECUTION TIME[hh:mm:ss]: $ExecutionTime"  -Verbose
Write-output $header.SeparatorDouble  -Verbose

# Review deployment logs
# Prompt to open logs
If (-not($SuppressPrompts))
{
    Do
    {
        $ResponsesObj.pOpenLogsNow = read-host $PromptsObj.pAskToOpenLogs
        $ResponsesObj.pOpenLogsNow = $ResponsesObj.pOpenLogsNow.ToUpper()
    } # end do
    Until ($ResponsesObj.pOpenLogsNow -eq "Y" -OR $ResponsesObj.pOpenLogsNow -eq "YES" -OR $ResponsesObj.pOpenLogsNow -eq "N" -OR $ResponsesObj.pOpenLogsNow -eq "NO")


    # Exit if user does not want to continue
    If ($ResponsesObj.pOpenLogsNow -in 'Y', 'YES')
    {
        Start-Process -FilePath notepad.exe $Transcript -Verbose
        # Invoke-Item -Path $resultsPathCsv -Verbose
        Write-Output $EndOfScriptMessage 
    } #end condition
    ElseIf ($ResponsesObj.pOpenLogsNow -in 'N', 'NO')
    {
        Write-Output $EndOfScriptMessage 
        Stop-Transcript -Verbose -ErrorAction SilentlyContinue
    } #end condition
} # end if
else
{
    Stop-Transcript -ErrorAction SilentlyContinue -Verbose
} # end else

#endregion SUMMARY
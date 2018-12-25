#Requires -PSEdition Desktop
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Secure credentials in automated scripts.

.DESCRIPTION
Scripts will use a client authentication certificate associated with a service account which has at least Builtin\Administrator privileges.
This certificate will be imported to the current user certificate store for the service account.
The certificate will be tied to the credential by using the thumbprint property.

.PARAMETER netDirectory
Directory path where the encrypted password file pw.txt, clear-text username file upn.txt and the self-signed client authentication certificate PSScriptCipherCert.pfx will be stored.
You may find it convenient to specify a server file share path, i.e. \\<server>\<share>\<directory>\pw.txt as a central location to save these artifacts.
This way, you can log on with the same service account on another machine and import the same decryption certificate to decrypt the password during script execution when required.

.PARAMETER logDirectory
Log directory for transcript, i.e. "\\<server>\<share>\logs"

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
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -ExportCert -Verbose
In this example, a new self-signed certificate will be created and installed. Service account credentials will be requested, and the password encrypted and exported to a file share, along with the username.
The certificate will also be exported, then removed from the current machine. The verbose switch is added to show details of certain operations.

.EXAMPLE
[WITHOUT the -ExportCert switch parameter]
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -Verbose
This command will import the self-signed certificate if required on a machine, retrieve the previously exported credentials, then use the certificate to decrypt the password component of the credential.

.EXAMPLE
[WITHOUT THE -ExportCert AND WITH the -SuppressPrompts switch parameter]
.\Set-SelfSignedCertCreds.ps1 -netDirectory "\\<server>\<share>\<directory>" -logDirectory "\\<server>\<share>\logs" -SuppressPrompts -Verbose
This command will import the self-signed certificate if required on a machine, retrieve the previously exported credentials, then use the certificate to decrypt the password component of the credential.
In this case, all interactive prompts will be suppressed, but transcript logging will continue.
This switch is intended for non-interactive scenarios such as dot sourcing this script from another in order to retrieve the service account credential set for use in the main script.

To test a command interactively use the following expression:
New-PSDrive -PSProvider FileSystem -Root \\<servername>\c$ -Name SetCredTest -Credential $svcAccountCred

A successfull result should look similar to the following output:

Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                           CurrentLocation
----           ---------     --------- --------      ----                                                                                                                                                                                           ---------------
SetCredTest                            FileSystem    \\<server>\c$

To test scheduling a scheduled job, us the following code snippet.

# 1.0: Register scheduled job using a script block
Register-ScheduledJob -Name psjob2 -ScriptBlock {dir c:\} -Credential $svcAccountCred
$trigger1 = New-JobTrigger -At (Get-Date).AddMinutes(2) -Once
Add-JobTrigger -Name psjob2 -Trigger $trigger1

OR

# 2.0: Register scheduled job using a script file, where c:\scripts\Set-CredTest.ps1 contains the code:
# dir c:\
Register-ScheduledJob -Name psjob3 -FilePath {c:\scripts\Set-CredTest.ps1} -Credential $svcAccountCred
$trigger1 = New-JobTrigger -At (Get-Date).AddMinutes(2) -Once
Add-JobTrigger -Name psjob2 -Trigger $trigger1

# 2.1: Register scheduled job using a script block.
	Register-ScheduledJob -Name PSJob -ScriptBlock { Get-ChildItem -Path \\$remotNodes\c$ -Recurse } -Credential $svcAccount -Verbose
	$trigger = New-JobTrigger -At (Get-Date).AddSeconds(10) -Once -Verbose
	Add-JobTrigger -Name PSJob -Trigger $trigger -Verbose

The scheduled jobs will appear at in the Task Scheduler at the path:
Microsoft\Windows\PowerShell\ScheduledJobs

.INPUTS
None

.OUTPUTS
The outputs generated from this script includes:
1. A transcript log file to provide the full details of script execution. It will use the name format: Set-SecureCredentials-TRANSCRIPT-<Date-Time>.log
2. A custom log file with the name format: Set-SecureCredentials-LOG-$env:COMPUTERNAME-<Date-Time>.log

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

    # Log directory for transcript and custom logs, i.e. "\\server\share\logs"
    [Parameter(Mandatory = $true,
        HelpMessage = "Enter the file server or local path for the transcript and custom log files.")]
    [string]$logDirectory,

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
        pAskToOpenLogs = "Would you like to open the custom and transcript logs now ? [YES/NO]"
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

    # Import the ActiveDirectory module so Get-ADUser can be used later
    Import-Module -Name ActiveDirectory
} # end function
function Get-SvcAccountCredential
{
    [OutputType([string])]
    [CmdletBinding()]
    # Retrieve the installed certificate
    $importedCert = Get-ChildItem -Path $SelfSignedCertParams.CertStoreLocation | Where-Object {$_.Subject -match "$($SelfSignedCertParams.Subject)"}
    $EncryptedPwd = Get-Content -Path $pwFilePath
    $EncryptedBytes = [System.Convert]::FromBase64String($EncryptedPwd)
    $DecryptedBytes = $importedCert.PrivateKey.Decrypt($EncryptedBytes, $true)
    $DecryptedPwd = [system.text.encoding]::UTF8.GetString($DecryptedBytes)
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
        [string]$svcAccountName
    ) # end param

    $SelfSignedCertParams =
    @{
        KeyDescription    = "PowerShell Script Encryption-Decryption Key"
        Provider          = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        KeyFriendlyName   = "PSScriptEncryptDecryptKey"
        FriendlyName      = "$svcAccountName-PSScriptCipherCert"
        Subject           = "$svcAccountName-PSScriptCipherCert"
        HashAlgorithm     = "sha256"
        CertStoreLocation = "Cert:\CurrentUser\My"
    } # end params

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

# funciton: Create log files for custom logging and transcript
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
Write-Output "Requesting the service account username. (This will not be encrypted)"
Do
{
    $svcAccount = Read-Host -Prompt "Enter service account username that will be used to run powershell scripts, i.e. svc.scripts. Do not include the UPN suffix: $($(Get-ADDomain).DnsRoot)"
    Write-Output ""
} until (Get-ADUser -Identity $svcAccount)

$svcAccountUpn = $svcAccount + "@" + $(($env:USERDNSDOMAIN).ToLower())

# Dot source the Get-InitialValues to bring the function scope values into the script scope.
. Get-InitialValues -SvcAccountName $svcAccount

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
        $EncodedPwd = [System.Text.Encoding]::UTF8.GetBytes($svcAccountPassword)
        $EncryptedBytes = $exportedCert.PublicKey.Key.Encrypt($EncodedPwd, $true)
        $EncryptedPwd = [System.Convert]::ToBase64String($EncryptedBytes)

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

#endregion SUMMARY

Stop-Transcript -ErrorAction SilentlyContinue -Verbose

#region INTEGRATION TESTING - MANUAL
<#
    Manual integration testing:
    
    To remove the currently installed certificate for re-testing the -ExportCert scenario, run the following command:
    Get-ChildItem -Path cert:\currentuser\my | Where-Object { $_.Subject -match "-PSScriptCipherCert" } | Remove-Item -Force

	To test a command interactively use the following expression:
	New-PSDrive -PSProvider FileSystem -Root \\<servername>\SetCredTest -Name SetCredTest -Credential $svcAccountCred

	A successfull result should look similar to the following output:

	Name           Used (GB)     Free (GB) Provider      Root                                                                                                                                                                                           CurrentLocation
	----           ---------     --------- --------      ----                                                                                                                                                                                           ---------------
	SetCredTest                            FileSystem    \\<server>\c$

	To test scheduling a scheduled job, us the following code snippets.

	# 2.0: Register scheduled job using a script file, where c:\scripts\Set-CredTest.ps1 contains the code:
    # Get-ChildItem -Path c:\ -Recurse

    # Register the job using the script file
    Register-ScheduledJob -Name psjob3 -FilePath {c:\scripts\Set-CredTest.ps1} -Credential $svcAccountCred

    # Create a trigger for two minutes from now
    $trigger1 = New-JobTrigger -At (Get-Date).AddMinutes(2) -Once

    # Add the trigger to the job
    Add-JobTrigger -Name psjob2 -Trigger $trigger1

    # 2.1: Register scheduled job using a script block.

    # Register a job using a script block
    Register-ScheduledJob -Name PSJob -ScriptBlock { Get-ChildItem -Path \\$remotNodes\c$ -Recurse } -Credential $svcAccount -Verbose

    # Create a trigger for 10 seconds from now
    $trigger = New-JobTrigger -At (Get-Date).AddSeconds(10) -Once -Verbose

    # Add the trigger to the job
    Add-JobTrigger -Name PSJob -Trigger $trigger -Verbose

    # The scheduled jobs will appear at in the Task Scheduler at the path:
	# Microsoft\Windows\PowerShell\ScheduledJobs
#>
#endregion INTEGRATION TESTING - MANUAL
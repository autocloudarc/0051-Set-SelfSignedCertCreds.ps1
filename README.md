# Introduction 
This project aims to secure PowerShell credentials used in scripts or interactively from the console, whether as an ad-hoc job or scheduled. 
The script in this project will use a document encryption certificate to encrypt and decrypt service account passwords used to execute interactive or scheduled scripts or commands.

# Getting Started
1.	Installation process

        To use this script, first extract the repository contents to a new directory. 
        You can use the directory named 0051 in your user profile $home folder. 
        You can use the powershell command to create the sub-directory:

        New-Path $home\0051 -ItemType Directory

        Next, from the repository page at: https://github.com/autocloudarc/0051-Set-SelfSignedCertCreds.ps1, Use the green <Clone or download> button on the right, then select <Download Zip>.

        The default user profile paths for Windows 10/8.1/7 client versions are: c:\users\<userid>, where "userid" represents the currently logged on username.
        The full path to the PowerShell script that is downloaded then will be c:\users\<userid>\0050\Set-SelfSignedCertCreds.ps1 

2.	Software dependencies
        This script may require the Windows PowerShell 5.1 version, which will allow automatic downloading and installation of any required modules from the www.powershellgallery.com repository if they are required from any future updates.

3.	Latest releases
        See commits

4.	References:
        [Project Link] (https://github.com/autocloudarc/0051-Set-SelfSignedCertCreds.ps1)

# Feedback
Please feel free to get involved by reporting problems, suggest ideas or improve this project by making the code better. 
To report problems and suggest ideas, please create an issue for this script, which will ensure that it is properly addressed.
For contributing to this project, please follow the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/) for coding/testing practices and pull request requirements.
This project is released under the [MIT license](https://mit-license.org/).
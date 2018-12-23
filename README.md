# Introduction 
This project will first check a provided list of servers to determine whether they are online and accessible for PowerShell remoting. 
Next, it will check the primary interface for a static IPv4 address. For each server that has a static IP address, 
the script will then change ONLY the preferred and alternate DNS entries in the DNS search order list to other specified new target values.
If a server has more than two entries in the search order list, they will NOT be modified.
This means if DNS1 = 10.10.10.10, then DNS1 = 10..10.10.100, and if DNS2 = 10.10.10.11, then DNS2 = 10.10.10.101 
A running report is also be generated to reflect the servers online availability and any changes that were made changes.

# Getting Started
1.	Installation process
        To use this script, first run the following commands that will download the script to a subfolder named UpdateDnsServerList in your user profile $home directory. 
        The default user profile paths for Windows 10/8.1/7 client versions are: c:\users\<userid>, where "userid" represents the currently logged on username.
        The full path to the PowerShell script that is downloaded then will be c:\users\<userid>\UpdateDnsServerList\UpdateDnsServerList.ps1 

2.	Software dependencies
        This script requires the Windows PowerShell 5.1 version, which will allow automatic downloading and installation of any required modules from the www.powershellgallery.com repository.

3.	Latest releases
        See commits

4.	References
    a. https://autocloudarc.visualstudio.com/0029-UpdateDnsServersList
    b. https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-windows 
    

# Test
You can test this script without making any changes by using the -WhatIf parameter. 
You can also revert to the original DNS settings by using the -Rollback parameter.
Examples:
.\UpdateDnsServerList -Path <PathToServerListFile> -WhatIf
.\UpdateDNsServerList -Path <PathToServerListFile> -

# Contribute
Please feel free to get involved by reporting problems, suggest ideas or improve this project by making the code better. 
To report problems and suggest ideas, please create an issue for this script, which will ensure that it is properly addressed.
For contributing to this project, please follow the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/) for coding/testing practices and pull request requirements.
This project is released under the [MIT license](https://mit-license.org/).
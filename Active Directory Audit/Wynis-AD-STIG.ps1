#Requires -RunAsAdministrator
#Requires -Version 4.0
#Author:Sneakysecdoggo
#Be awesome send me cookie
#This script must be run with admin rights 
#Check Windows Security Best Practice CIS 
#https://github.com/Sneakysecdoggo/
#https://twitter.com/SneakyWafWaf
#Script  Active Directory Version
#MIT License

#Copyright (c) [2020] [Sneakysecdoggo]

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE
#For running Prod , for debug comment the ligne below
$ErrorActionPreference= 'silentlycontinue'
##########


#ASCII ART BITCH
Write-Host " __          __          _      "  -ForegroundColor Cyan 
Write-Host " \ \        / /         (_)     "  -ForegroundColor Cyan 
Write-Host "  \ \  /\  / /   _ _ __  _ ___  "  -ForegroundColor Cyan 
Write-Host "   \ \/  \/ / | | | '_ \| / __| "  -ForegroundColor Cyan 
Write-Host "    \  /\  /| |_| | | | | \__ \ "  -ForegroundColor Cyan 
Write-Host "     \/  \/  \__, |_| |_|_|___/ "  -ForegroundColor Cyan 
Write-Host "              __/ |             "  -ForegroundColor Cyan 
Write-Host "             |___/              "  -ForegroundColor Cyan 
Write-Host" _______  ______  " -ForegroundColor Black 
Write-Host"(  ___  )(  __  \ " -ForegroundColor Black 
Write-Host"| (   ) || (  \  )" -ForegroundColor Black 
Write-Host"| (___) || |   ) |" -ForegroundColor Black 
Write-Host"|  ___  || |   | |" -ForegroundColor Black 
Write-Host"| (   ) || |   ) |" -ForegroundColor Black 
Write-Host"| )   ( || (__/  )" -ForegroundColor Black 
Write-Host"|/     \|(______/ " -ForegroundColor Black 
                  


#reference
Write-Host "This tools will use the compliance framework below :"
Write-Host "-https://stigviewer.com/stig/windows_server_20122012_r2_domain_controller/2019-01-16/"


# convert Stringarray to comma separated liste (String)
function StringArrayToList($StringArray) {
    if ($StringArray) {
        $Result = ""
        Foreach ($Value In $StringArray) {
            if ($Result -ne "") { $Result += "," }
            $Result += $Value
        }
        return $Result
    }
    else {
        return ""
    }
}


#get the date
$Date = Get-Date -U %d%m%Y


$nomfichier = "audit_AD" + $date + ".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$nomdossier = "Audit_CONF_AD" + $date


New-Item -ItemType Directory -Name $nomdossier

Set-Location $nomdossier

Write-Host "#########>Import Module Active Directory <#########" -ForegroundColor DarkGreen
Import-Module ActiveDirectory
#Get intel from the machine

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice


$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture

#Put it in a file
Write-Host "#########>Take Server Information<#########" -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $nomfichier
"Os version: $OSversion " >> $nomfichier
"Machine name : $OSName " >> $nomfichier
"Machine architecture : $OSArchi" >> $nomfichier
#Start testing
"#########AUDIT MACHINE#########" >> $nomfichier

$chaine = $null
$traitement = $null


#Take file important for analysis 
Write-Host "#########>Take File to analyse<#########" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile 
$gpofile = "./gpo" + "-" + "$OSName" + ".txt"
gpresult /r > $gpofile
$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null
#Second command in case of emergency


$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile






Write-Host "#########>Take  local Firewall Rules Information<#########" -ForegroundColor DarkGreen
$CSVFile = "./firewall-rules-" + "$OSName" + ".csv"
# read firewall rules
$FirewallRules = Get-NetFirewallRule -PolicyStore "ActiveStore"

# start array of rules
$FirewallRuleSet = @()
ForEach ($Rule In $FirewallRules) {
    # iterate throug rules
    # Retrieve addresses,
    $AdressFilter = $Rule | Get-NetFirewallAddressFilter
    # ports,
    $PortFilter = $Rule | Get-NetFirewallPortFilter
    # application,
    $ApplicationFilter = $Rule | Get-NetFirewallApplicationFilter
    # service,
    $ServiceFilter = $Rule | Get-NetFirewallServiceFilter
    # interface,
    $InterfaceFilter = $Rule | Get-NetFirewallInterfaceFilter
    # interfacetype
    $InterfaceTypeFilter = $Rule | Get-NetFirewallInterfaceTypeFilter
    # and security settings
    $SecurityFilter = $Rule | Get-NetFirewallSecurityFilter

    # generate sorted Hashtable
    $HashProps = [PSCustomObject]@{
        Name                = $Rule.Name
        DisplayName         = $Rule.DisplayName
        Description         = $Rule.Description
        Group               = $Rule.Group
        Enabled             = $Rule.Enabled
        Profile             = $Rule.Profile
        Platform            = StringArrayToList $Rule.Platform
        Direction           = $Rule.Direction
        Action              = $Rule.Action
        EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
        LooseSourceMapping  = $Rule.LooseSourceMapping
        LocalOnlyMapping    = $Rule.LocalOnlyMapping
        Owner               = $Rule.Owner
        LocalAddress        = StringArrayToList $AdressFilter.LocalAddress
        RemoteAddress       = StringArrayToList $AdressFilter.RemoteAddress
        Protocol            = $PortFilter.Protocol
        LocalPort           = StringArrayToList $PortFilter.LocalPort
        RemotePort          = StringArrayToList $PortFilter.RemotePort
        IcmpType            = StringArrayToList $PortFilter.IcmpType
        DynamicTarget       = $PortFilter.DynamicTarget
        Program             = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
        Package             = $ApplicationFilter.Package
        Service             = $ServiceFilter.Service
        InterfaceAlias      = StringArrayToList $InterfaceFilter.InterfaceAlias
        InterfaceType       = $InterfaceTypeFilter.InterfaceType
        LocalUser           = $SecurityFilter.LocalUser
        RemoteUser          = $SecurityFilter.RemoteUser
        RemoteMachine       = $SecurityFilter.RemoteMachine
        Authentication      = $SecurityFilter.Authentication
        Encryption          = $SecurityFilter.Encryption
        OverrideBlockRules  = $SecurityFilter.OverrideBlockRules
    }

    # add to array with rules
    $FirewallRuleSet += $HashProps
}

$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile



Write-Host "#########>Take  Antivirus  Information<#########" -ForegroundColor DarkGreen

$testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp


if ($null -eq $testAntivirus  ) {



    $testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp

    if ( $null -eq $testAntivirus) {
        Write-Host "Antivirus software not detected , please check manualy" -ForegroundColor Red
    }
}  

$CSVFileAntivirus = "./Antivirus-" + "$OSName" + ".csv"
$testAntivirus | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFileAntivirus





#Audit share present on the server 

Write-Host "#########>Take  Share  Information<#########" -ForegroundColor DarkGreen
$nomfichierShare = "./SHARE " + "$OSName" + ".csv"
    
function addShare {
    param([string]$NS, [string]$CS, [string]$US, [string]$TS, [string]$NDS)
    $d = New-Object PSObject
    $d | Add-Member -Name "Share Name"  -MemberType NoteProperty -Value $NS
    $d | Add-Member -Name "Share Path "-MemberType NoteProperty -Value $CS
    $d | Add-Member -Name "Account Name "-MemberType NoteProperty -Value $US
    $d | Add-Member -Name "AccessControlType"-MemberType NoteProperty -Value $TS
    $d | Add-Member -Name "AccessRight"-MemberType NoteProperty -Value $NDS
    return $d
}
$tableauShare = @()
       
$listShare = Get-SmbShare 
    
    
foreach ( $share in $listShare) {
    
    
    $droits = Get-SmbShareAccess $share.name
    
    
    foreach ( $droit in $droits) {
    
    
        $tableauShare += addShare -NS $share.name  -CS $share.path -US $droit.AccountName -TS $droit.AccessControlType -NDS $droit.AccessRight
    
    
    }
}

$tableauShare | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content  $nomfichierShare

#Audit Appdata 
Write-Host "#########>Take  Appdata  Information<#########" -ForegroundColor DarkGreen
$cheminProfils = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows' 'NT\CurrentVersion\ProfileList\).ProfilesDirectory
    
    
$profilpresent = Get-ChildItem $cheminProfils 
    
    
$nomfichierAPP = "./APPDATA" + "$OSName" + ".txt"
    
    
foreach ( $profil in $profilpresent) {
    
    $verifAppdata = Test-Path  $cheminProfils\$profil\Appdata
    
    if ($verifAppdata -eq $true) {
    
        $resultat = Get-ChildItem $cheminProfils\$profil\Appdata -Recurse -Include *.bat, *.exe, *.ps1, *.msi, *.py | Select-Object Name, Directory | Format-Table -AutoSize
    
    
        $resulatCount = $resultat |Measure-Object 
        $resulatCount = $resulatCount.Count
    
    
    
        if ( $resulatCount -gt 0) {
            " $profil  `r" >> ./$nomfichierAPP
    
            $resultat >> ./$nomfichierAPP
        }
    
    }
}
    
#Check feature and optionnal who are installed 
Write-Host "#########>Take  Feature and Optionnal Feature Information<#########" -ForegroundColor DarkGreen
$nomfichierFeature = "./Feature-" + "$OSName" + ".txt"
$nomfichierOptionnalFeature = "./OptionnalFeature-" + "$OSName" + ".txt"  
if ( $OSversion -match "Server") {
    #Import serverManger
    import-module servermanager
    
    Get-WindowsFeature | where-object {$_.Installed -eq $True} |Format-Table * -Autosize >> ./$nomfichierFeature  
    
}
Get-WindowsOptionalFeature -Online | where-object {$_.State -eq "Enabled"} |Format-Table * -Autosize >> $nomfichierOptionnalFeature
#Check installed software
Write-Host "#########>Take  Software Information<#########" -ForegroundColor DarkGreen
$nomfichierInstall = "./Installed-software- " + "$OSName" + ".csv"

$installedsoftware = Get-WmiObject win32_product | Select-Object Name, Caption, Description, InstallLocation, InstallSource, InstallDate, PackageName, Version

$installedsoftware | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content  $nomfichierInstall
#Get system Info 
Write-Host "#########>Take  System Information<#########" -ForegroundColor DarkGreen
$NomfichierSystem = "./systeminfo- " + "$OSName" + ".txt"
systeminfo > $NomfichierSystem 


#Microsoft Update Liste 
Write-Host "#########>Take  Update Information<#########" -ForegroundColor DarkGreen
$nomfichierUpdate = "./systemUpdate- " + "$OSName" + ".html"
wmic qfe list brief /format:htable > $nomfichierUpdate


#Check installed Service
Write-Host "#########>Take  Service Information<#########" -ForegroundColor DarkGreen
$nomfichierservice = "./Service- " + "$OSName" + ".csv"

Get-WmiObject win32_service | Select-Object Name, DisplayName, State, StartName, StartMode, PathName |Export-Csv -Delimiter ";" $nomfichierservice -NoTypeInformation

#Check Scheduled task
Write-Host "#########>Take  Scheduled task Information<#########" -ForegroundColor DarkGreen
$nomfichierttache = "./Scheduled-task- " + "$OSName" + ".txt"
$tabletache = Get-ScheduledTask |Select-Object -Property *
foreach ($tache in $tabletache) {

    "Task name : " + $tache.Taskname + "`r" >> $nomfichierttache 
    "Task state : " + $tache.State + "`r" >> $nomfichierttache 
    "Task Author : " + $tache.Author + "`r" >> $nomfichierttache 
    "Task Description : " + $tache.Description + "`r" >> $nomfichierttache 
    $taskactions = Get-ScheduledTask $tache.Taskname |Select-Object -ExpandProperty Actions
    "Task action : `r" >> $nomfichierttache
    foreach ( $taskaction in $taskactions ) {
        "Task action Argument :" + $taskaction.Arguments + "`r"  >> $nomfichierttache
        "Task action : " + $taskaction.Execute + "`r" >> $nomfichierttache 
        "Task Action WorkingDirectory : " + $taskaction.WorkingDirectory + "`r" >> $nomfichierttache 
        "---------------------------------------------------`r" >> $nomfichierttache 
    }
    "##############################################`r" >> $nomfichierttache 
}

#check net accounts intel
Write-Host "#########>Take  Service Information<#########" -ForegroundColor DarkGreen
$nomfichierNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $nomfichierNetAccount


#Check listen port 
Write-Host "#########>Take  Port listening  Information<#########" -ForegroundColor DarkGreen
$nomfichierPort = "./Listen-port- " + "$OSName" + ".csv"
$listport = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess
"LocalAddress;LocalPort;State;OwningProcess;Path" > $nomfichierPort

foreach ($port in $listport) {
    $exepath = Get-Process -PID $port.OwningProcess |Select-Object Path
    $port.LocalAddress + ";" + $port.LocalPort + ";" + $port.State + ";" + $exepath.path >> $nomfichierPort
}

#List all local user 

$listlocaluser = Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'"

foreach ( $user in $listlocaluser) {


    if ( $user.sid -like "*-500") {

        $nomcompteadmin = $user.Name

        $statutcompteadmin = $user.Disabled
        if ($statutcompteadmin -eq $true) {
            $adminstate = "disable"
        }
        else {
            $adminstate = "enable"
        }
    }
    elseif ( $user.sid -like "*-501") {
        $nomcompteguest = $user.Name
        $statutcompteguest = $user.Disabled
        if ($statutcompteguest -eq $true) {
            $gueststate = "disable"
        }
        else {
            $gueststate = "enable"
        }

    }

}

$listlocaluser > "localuser-$OSName.txt"

#Check Startup registry key
Write-Host "#########>Take  Startup Registry  Information<#########" -ForegroundColor DarkGreen
$nomfichierStartup = "./Startup- " + "$OSName" + ".txt"
"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" >> $nomfichierStartup
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $nomfichierStartup
"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> $nomfichierStartup
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $nomfichierStartup
"HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" >> $nomfichierStartup
Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $nomfichierStartup
"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" >> $nomfichierStartup
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $nomfichierStartup
"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> $nomfichierStartup
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive >> $nomfichierStartup

Write-Host "#########>Begin STIG audit<#########" -ForegroundColor Green
#Check Critical
Write-Host "#########>Begin Critical Criteria audit<#########" -ForegroundColor DarkGreen

#The Windows Remote Management (WinRM) service must not use Basic authentication

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-36718"
$chaine = "$id" + ";" + "The Windows Remote Management (WinRM) service must not use Basic authentication, Value must be 0 " + ";"
$exist = Test-Path HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\
if ( $exist -eq $true) {
    $traitement = Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service | Select-Object AllowBasic
    $traitement = $traitement.AllowBasic
}
else {
    $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

#The Windows Remote Management (WinRM) client must not use Basic authentication

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-36712"
$chaine = "$id" + ";" + "The Windows Remote Management (WinRM) client must not use Basic authentication, Value must be 0 " + ";"
$exist = Test-Path HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client
if ( $exist -eq $true) {
    $traitement = Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client | Select-Object AllowBasic
    $traitement = $traitement.AllowBasic
}
else {
    $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

#Anonymous access to Named Pipes and Shares must be restricted

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-6834"
$chaine = "$id" + ";" + "Anonymous access to Named Pipes and Shares must be restricted, Value must be 1 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
    $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters | Select-Object RestrictNullSessAccess
    $traitement = $traitement.RestrictNullSessAccess
}
else {
    $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

#The Debug programs user right must only be assigned to the Administrators group.


$chaine = $null
$traitement = $null
$id = "V-18010"
$chaine = "$id" + ";" + "The Debug programs user right must only be assigned to the Administrators group " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDebugPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeDebugPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


#Anonymous enumeration of shares must be restricted
$chaine = $null
$traitement = $null
$exist = $null
$id = "V-1093"
$chaine = "$id" + ";" + "Anonymous enumeration of shares must be restricted, Value must be 1 " + ";"
$exist = Test-Path HKLM:\CurrentControlSet\Control\Lsa\
if ( $exist -eq $true) {
    $traitement = Get-ItemProperty HKLM:\CurrentControlSet\Control\Lsa | Select-Object RestrictAnonymous
    $traitement = $traitement.RestrictAnonymous
}
else {
    $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

#Anonymous enumeration of SAM accounts must not be allowed
$chaine = $null
$traitement = $null
$exist = $null
$id = "V-26283"
$chaine = "$id" + ";" + "Anonymous enumeration of SAM accounts must not be allowed, Value must be 1 " + ";"
$exist = Test-Path HKLM:\CurrentControlSet\Control\Lsa\
if ( $exist -eq $true) {
    $traitement = Get-ItemProperty HKLM:\CurrentControlSet\Control\Lsa | Select-Object RestrictAnonymousSAM
    $traitement = $traitement.RestrictAnonymousSAM
}
else {
    $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

#File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive
$chaine = $null
$traitement = $null
$exist = $null
$id = "V-1121"
$chaine = "$id" + ";" + "File Transfer Protocol (FTP) servers must be configured to prevent access to the system drive, Dont put FTP on DC " + ";"
$traitement = "Check Feature,Optional feature, installed softwatre  netstat"
$chaine += $traitement
$chaine>> $nomfichier
Write-Host "Ask your client if they use FTP service on th" -ForegroundColor yellow

#Only administrators responsible for the domain controller must have Administrator rights on the system

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-1127"
$chaine = "$id" + ";" + "Only administrators responsible for the domain controller must have Administrator rights on the system, Value must be 0 " + ";"
Get-ADGroupMember S-1-5-32-544 | Select Name, objectClass, distinguishedName |Export-Csv localadmins.csv -NoTypeInformation -Delimiter ";"

$traitement = "Check localadmins.csv"


$chaine += $traitement
$chaine>> $nomfichier

#Only administrators responsible for the domain controller must have Administrator rights on the system

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-1127"
$chaine = "$id" + ";" + "Only administrators responsible for the domain controller must have Administrator rights on the system, Value must be 0 " + ";"
Get-ADGroupMember S-1-5-32-544 | Select Name, objectClass, distinguishedName |Export-Csv localadmins.csv -NoTypeInformation -Delimiter ";"

$traitement = "Check localadmins.csv"


$chaine += $traitement
$chaine>> $nomfichier

#The Active Directory SYSVOL directory must have the proper access control permissions.

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-39331"
$chaine = "$id" + ";" + "The Active Directory SYSVOL directory must have the proper access control permissions, Value must be NT AUTHORITY\Authenticated Users:(RX),BUILTIN\Server Operators:(RX),BUILTIN\Server Operators:(OI)(CI)(IO)(GR,GE),BUILTIN\Administrators:(M,WDAC,WO),BUILTIN\Administrators:(OI)(CI)(IO)(F),NT AUTHORITY\SYSTEM:(F) " + ";"

$traitement = "Check Sysvolright.csv"
$tableauSysvol = @()

$Sysvolshare = Get-SmbShare SYSVOL

$sysvoldroits = Get-SmbShareAccess $Sysvolshare.name
    
    
    foreach ( $sysvoldroit in $sysvoldroits) {
    
    
        $tableauShare += addShare -NS $Sysvolshare.name -CS $Sysvolshare.path -US $sysvoldroit.AccountName -TS $sysvoldroit.AccessControlType -NDS $sysvoldroit.AccessRight
    
    
    }
$tableauSysvol += addShare -NS $Sysvolshare.name  -CS $Sysvolshare.path -US $droit.AccountName -TS $droit.AccessControlType -NDS $droit.AccessRight

$tableauShare | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content  ./Sysvolright.csv

$chaine += $traitement
$chaine>> $nomfichier

#The Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions

$chaine = $null
$traitement = $null
$exist = $null
$id = "V-39332"
$chaine = "$id" + ";" + "The Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions, SELF - Special permissions,SYSTEM - Full Control,Enterprise Admins - Full Control,Administrators - Read, Write, Create all child objects, Generate resultant set of policy (logging), Generate resultant set of policy (planning), Special permissions , ENTERPRISE DOMAIN CONTROLLERS - Read, Special permissions " + ";"
$pathd= Get-ADOrganizationalUnit -Filter 'Name -like "Domain Controllers"' | Select DistinguishedName
dsacls $pathd.DistinguishedName > UOdomaincontrollerrights.txt

$traitement = "Check UOdomaincontrollerrights.txt"


$chaine += $traitement
$chaine>> $nomfichier


#The Active Directory Domain Controllers Organizational Unit (OU) object must have the proper access control permissions
$chaine = $null
$traitement = $null
$exist = $null
$id = "V-39333"
$chaine = "$id" + ";" + "Domain created Active Directory Organizational Unit (OU) objects must have proper access control permissions." + ";"
$pathd= Get-ADOrganizationalUnit -Filter 'Name -like "Domain Controllers"' | Select DistinguishedName
dsacls $pathd.DistinguishedName > UOdomaincontrollerrights.txt

$traitement = "Check UOdomaincontrollerrights.txt"


$chaine += $traitement
$chaine>> $nomfichier
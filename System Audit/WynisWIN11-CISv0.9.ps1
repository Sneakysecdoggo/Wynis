#Requires -RunAsAdministrator
#Requires -Version 4.0
#Author:Sneakysecdoggo
#Be awesome send me cookie
#This script must be run with admin rights 
#Check Windows Security Best Practice CIS 
#https://github.com/Sneakysecdoggo/
#Script WIN11 Version

#Copyright (c) [2019] [Sneakysecdoggo]

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

##########
#For running Prod , for debug comment the ligne below
$ErrorActionPreference= 'silentlycontinue'




#ASCII ART BITCH

Write-Host " __          __          _      "  -ForegroundColor Cyan 
Write-Host " \ \        / /         (_)     "  -ForegroundColor Cyan 
Write-Host "  \ \  /\  / /   _ _ __  _ ___  "  -ForegroundColor Cyan 
Write-Host "   \ \/  \/ / | | | '_ \| / __| "  -ForegroundColor Cyan 
Write-Host "    \  /\  /| |_| | | | | \__ \ "  -ForegroundColor Cyan 
Write-Host "     \/  \/  \__, |_| |_|_|___/ "  -ForegroundColor Cyan 
Write-Host "              __/ |             "  -ForegroundColor Cyan 
Write-Host "             |___/              "  -ForegroundColor Cyan 
Write-Host " __          ____   _ "  -ForegroundColor Black 
Write-Host " \ \        / /_ |/_ |"  -ForegroundColor Black 
Write-Host "  \ \  /\  / / | | | |"  -ForegroundColor Black  
Write-Host "   \ \/  \/ /  | | | |"  -ForegroundColor Black 
Write-Host "    \  /\  /   | | | | "  -ForegroundColor Black 
Write-Host "     \/  \/    |_| | |"  -ForegroundColor Black 

#FUNCTION 

$reverveCommand = Get-Command | where { $_.name -match "Get-WSManInstance"}
if($reverveCommand -ne $null){
 $reverseCommandExist= $true
}else{
 $reverseCommandExist= $false
}


Function Clean-Value($variable) {

$variable = $null 

return $variable

}


# Function to reverse SID from SecPol
Function Reverse-SID ($chaineSID) {


 $chaineSID = $chaineSID -creplace '^[^\\]*=', ''
 $chaineSID = $chaineSID.replace("*", "")
 $chaineSID = $chaineSID.replace(" ", "")
 if ( $chaineSID -ne $null){
 $tableau = @()
 $tableau = $chaineSID.Split(",") 


 ForEach ($ligne in $tableau) { 
  $sid = $null
  if ($ligne -like "S-*") {
   if($reverseCommandExist -eq $true){
   $sid = Get-WSManInstance -ResourceURI "wmicimv2/Win32_SID" -SelectorSet @{SID="$ligne"}|Select-Object AccountName
   $sid = $sid.AccountName
   }
if ( $sid -eq $null) {
    $objSID = New-Object System.Security.Principal.SecurityIdentifier ("$ligne")
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $sid=$objUser.Value
    if ( $sid -eq $null){
    $objUser = New-Object System.Security.Principal.NTAccount("$ligne") 
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $sid=$strSID.Value
}
   $outpuReverseSid += $sid + "|"

  }else{
   $outpuReverseSid += $ligne + "|"
  }
 }
 
 }
 return $outpuReverseSid
}else {
$outpuReverseSid += No One 
 return $outpuReverseSid

}
}



# convert Stringarray to comma separated list
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
#Get Intel On the machine

$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice


$OSversion = $OSInfo.Caption
$OSName = $OSInfo.CSName
$OSArchi = $OSInfo.OSArchitecture


#Get the date
$Date = Get-Date -U %d%m%Y

$nomfichier = "audit" + $date + "-" + $OSName +".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$nomdossier = "Audit_CONF_" + $OSName + "_" + $date


New-Item -ItemType Directory -Name $nomdossier

Set-Location $nomdossier


#Insert result in audit file
Write-Host "#########>Take Server Information<#########" -ForegroundColor DarkGreen
"#########INFO MACHINE#########" > $nomfichier
"Os version: $OSversion " >> $nomfichier
"Machine name : $OSName " >> $nomfichier
"Machine architecture : $OSArchi" >> $nomfichier
#Start Test 
"#########AUDIT MACHINE#########" >> $nomfichier
$indextest = 1
$chaine = $null
$traitement = $null


#Get usefull files
Write-Host "#########>Take File to analyse<#########" -ForegroundColor DarkGreen
$seceditfile = "./secpol" + "-" + "$OSName" + ".cfg"
secedit /export /cfg $seceditfile 
#Second command in case of emergency

gpresult /r /V > $gpofile

$PCUser = (Get-WMIObject -Classname Win32_ComputerSystem).Username 
$PSUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 

if ($PCUser -Like $PSUser) { 
  $gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".txt"
	gpresult /r /V > $gpofile
} else {
	$gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".txt"
	gpresult /r /V /user $PCUSER > $gpofile 
}

$gpofile = "./gpo" + "-" + "$OSName" + "-" + $PCUser + ".html"
if ($PCUser -Like $PSUser) { 
   
	gpresult /h $gpofile /f | out-null
} else {
	
	gpresult /h $gpofile /f /user $PCUSER | out-null 
}

$gpofile = "./gpo" + "-" + "$OSName" + ".html"
gpresult /h $gpofile /f | out-null

$auditconfigfile = "./auditpolicy" + "-" + "$OSName" + ".txt"

auditpol.exe /get /Category:* > $auditconfigfile


#Dump some Windows registry 
Write-Host "#########>Dump Windows Registry <#########" -ForegroundColor DarkGreen
$registrydumping = $(Write-Host "Woud you like to dump registry in order to deep dive some other value, this may cause EDR to kill Wynis (Y/N)?" -ForegroundColor Red ; Read-Host)

If( $registrydumping -like "Y"){

$auditregHKLM= "./auditregistry-HKLMicrosoft" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Microsoft\" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMCUrrentControlSet" + "-" + "$OSName" + ".txt"
reg export "HKLM\SYSTEM\CurrentControlSet" "$auditregHKLM"
$auditregHKLM= "./auditregistry-HKLMPolicies" + "-" + "$OSName" + ".txt"
reg export "HKLM\SOFTWARE\Policies" "$auditregHKLM"
}




Write-Host "#########>Take local Firewall Rules Information<#########" -ForegroundColor DarkGreen
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
  Name    = $Rule.Name
  DisplayName   = $Rule.DisplayName
  Description   = $Rule.Description
  Group    = $Rule.Group
  Enabled    = $Rule.Enabled
  Profile    = $Rule.Profile
  Platform   = StringArrayToList $Rule.Platform
  Direction   = $Rule.Direction
  Action    = $Rule.Action
  EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
  LooseSourceMapping = $Rule.LooseSourceMapping
  LocalOnlyMapping = $Rule.LocalOnlyMapping
  Owner    = $Rule.Owner
  LocalAddress  = StringArrayToList $AdressFilter.LocalAddress
  RemoteAddress  = StringArrayToList $AdressFilter.RemoteAddress
  Protocol   = $PortFilter.Protocol
  LocalPort   = StringArrayToList $PortFilter.LocalPort
  RemotePort   = StringArrayToList $PortFilter.RemotePort
  IcmpType   = StringArrayToList $PortFilter.IcmpType
  DynamicTarget  = $PortFilter.DynamicTarget
  Program    = $ApplicationFilter.Program -Replace "$($ENV:SystemRoot.Replace("\","\\"))\\", "%SystemRoot%\" -Replace "$(${ENV:ProgramFiles(x86)}.Replace("\","\\").Replace("(","\(").Replace(")","\)"))\\", "%ProgramFiles(x86)%\" -Replace "$($ENV:ProgramFiles.Replace("\","\\"))\\", "%ProgramFiles%\"
  Package    = $ApplicationFilter.Package
  Service    = $ServiceFilter.Service
  InterfaceAlias  = StringArrayToList $InterfaceFilter.InterfaceAlias
  InterfaceType  = $InterfaceTypeFilter.InterfaceType
  LocalUser   = $SecurityFilter.LocalUser
  RemoteUser   = $SecurityFilter.RemoteUser
  RemoteMachine  = $SecurityFilter.RemoteMachine
  Authentication  = $SecurityFilter.Authentication
  Encryption   = $SecurityFilter.Encryption
  OverrideBlockRules = $SecurityFilter.OverrideBlockRules
 }

 # add to array with rules
 $FirewallRuleSet += $HashProps
}

$FirewallRuleSet | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFile

#Take Protection software information 
Write-Host "#########>Take Antivirus Information<#########" -ForegroundColor DarkGreen

$testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp




if ($null -eq $testAntivirus ) {



 $testAntivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" |Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, timestamp

 if ( $null -eq $testAntivirus) {
  Write-Host "Antivirus software not detected , please check manualy" -ForegroundColor Red
 }
} 

$CSVFileAntivirus = "./Antivirus-" + "$OSName" + ".csv"
$testAntivirus | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $CSVFileAntivirus





#Audit share present on the server 

Write-Host "#########>Take Share Information<#########" -ForegroundColor DarkGreen
$nomfichierShare = "./SHARE " + "$OSName" + ".csv"
 
function addShare {
 param([string]$NS, [string]$CS, [string]$US, [string]$TS, [string]$NDS)
 $d = New-Object PSObject
 $d | Add-Member -Name "Share Name" -MemberType NoteProperty -Value $NS
 $d | Add-Member -Name "Share Path "-MemberType NoteProperty -Value $CS
 $d | Add-Member -Name "AccountName "-MemberType NoteProperty -Value $US
 $d | Add-Member -Name "AccessControlType"-MemberType NoteProperty -Value $TS
 $d | Add-Member -Name "AccessRight"-MemberType NoteProperty -Value $NDS
 return $d
}
$tableauShare = @()
  
$listShare = Get-SmbShare 
 
 
foreach ( $share in $listShare) {
 
 
 $droits = Get-SmbShareAccess $share.name
 
 
 foreach ( $droit in $droits) {
 
 
  $tableauShare += addShare -NS $share.name -CS $share.path -US $droit.AccountName -TS $droit.AccessControlType -NDS $droit.AccessRight
 
 
 }
}

$tableauShare | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $nomfichierShare

#Audit Appdata 
Write-Host "#########>Take Appdata Information<#########" -ForegroundColor DarkGreen
$cheminProfils = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows' 'NT\CurrentVersion\ProfileList\).ProfilesDirectory
  
  
$profilpresent = Get-ChildItem $cheminProfils 
  
$resultAPP = @()
$nomfichierAPP = "./APPDATA" + "$OSName" + ".csv"
  
  
foreach ( $profil in $profilpresent) {
  
  $verifAppdata = Test-Path $cheminProfils\$profil\Appdata
  
  if ($verifAppdata -eq $true) {
  
    $resultat = Get-ChildItem $cheminProfils\$profil\Appdata -Recurse -Include *.bat, *.exe, *.ps1, *.ps1xml, *.PS2, *.PS2XML, *.psc1, *.PSC2, *.msi, *.py, *.pif, *.MSP , *.COM, *.SCR, *.hta, *.CPL, *.MSC, *.JAR, *.VB, *.VBS, *.VBE, *.JS, *.JSE, *.WS, *.wsf, *.wsc, *.wsh, *.msh, *.MSH1, *.MSH2, *.MSHXML, *.MSH1XML, *.MSH2XML, *.scf, *.REG, *.INF   | Select-Object Name, Directory, Fullname 
  
  foreach ($riskyfile in $resultat) {

$signature = Get-FileHash -Algorithm SHA256 $riskyfile.Fullname -ErrorAction SilentlyContinue



  $resultApptemp = [PSCustomObject]@{
                            Name  = $riskyfile.Name
                            Directory = $riskyfile.Directory
                            Path = $riskyfile.Fullname
							              Signature = $signature.Hash
                            Profil= $profil.name
							
                        }

$resultAPP +=$resultApptemp


  }
  }
}
 
    $resulatCount = $resultAPP |Measure-Object 
    $resulatCount = $resulatCount.Count
  
  
  
    if ( $resulatCount -gt 0) {
      $resultAPP | Export-Csv -NoTypeInformation $nomfichierAPP
  
      
    }
  

 
#Check feature and optionnal who are installed 
Write-Host "#########>Take Feature and Optionnal Feature Information<#########" -ForegroundColor DarkGreen

$nomfichierOptionnalFeature = "./OptionnalFeature-" + "$OSName" + ".csv" 

Get-WindowsOptionalFeature -Online | where-object {$_.State -eq "Enabled"} | Export-Csv -NoTypeInformation $nomfichierOptionnalFeature
#Check installed software
Write-Host "#########>Take Software Information<#########" -ForegroundColor DarkGreen
$nomfichierInstall = "./Installed-software- " + "$OSName" + ".csv"

$installedsoftware = Get-WmiObject win32_product | Select-Object Name, Caption, Description, InstallLocation, InstallSource, InstallDate, PackageName, Version

$installedsoftware | ConvertTo-CSV -NoTypeInformation -Delimiter ";" | Set-Content $nomfichierInstall
#Get system Info 
Write-Host "#########>Take System Information<#########" -ForegroundColor DarkGreen
$NomfichierSystem = "./systeminfo- " + "$OSName" + ".txt"
systeminfo > $NomfichierSystem 


#Microsoft Update Liste 
Write-Host "#########>Take Update Information<#########" -ForegroundColor DarkGreen
$nomfichierUpdate = "./systemUpdate- " + "$OSName" + ".html"
wmic qfe list brief /format:htable > $nomfichierUpdate


#Check installed Service
Write-Host "#########>Take Service Information<#########" -ForegroundColor DarkGreen
$nomfichierservice = "./Service- " + "$OSName" + ".csv"

Get-WmiObject win32_service | Select-Object Name, DisplayName, State, StartName, StartMode, PathName |Export-Csv -Delimiter ";" $nomfichierservice -NoTypeInformation

#Check Scheduled task
Write-Host "#########>Take Scheduled task Information<#########" -ForegroundColor DarkGreen
$nomfichierttache = "./Scheduled-task- " + "$OSName" + ".csv"
$tabletache = Get-ScheduledTask |Select-Object -Property *
$resultTask= @()
foreach ($tache in $tabletache) {
$taskactions = Get-ScheduledTask $tache.Taskname |Select-Object -ExpandProperty Actions

 foreach ( $taskaction in $taskactions ) {


$resultTasktemp = [PSCustomObject]@{
                            Task_name = $tache.Taskname
                            Task_URI = $tache.URI
                            Task_state = $tache.State
                            Task_Author = $tache.Author
							Task_Description = $tache.Description
                            Task_action = $taskaction.Execute 
                            Task_action_Argument = $taskaction.Arguments
                            Task_Action_WorkingDirectory = $taskaction.WorkingDirectory
							
                        }

$resultTask += $resultTasktemp

 }
  }
  



$resultTask | Export-Csv -NoTypeInformation $nomfichierttache

#check net accounts intel
Write-Host "#########>Take Accounts Policy Information<#########" -ForegroundColor DarkGreen
$nomfichierNetAccount = "./AccountsPolicy- " + "$OSName" + ".txt"
net accounts > $nomfichierNetAccount

#Check listen port 
Write-Host "#########>Take Port listening Information<#########" -ForegroundColor DarkGreen
$nomfichierPort = "./Listen-port- " + "$OSName" + ".csv"
$listport = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, State, OwningProcess
Write-Host "LocalAddress;LocalPort;State;OwningProcess;Path" > $nomfichierPort

foreach ($port in $listport) {
 $exepath = Get-Process -PID $port.OwningProcess |Select-Object Path
 $port.LocalAddress + ";" + $port.LocalPort + ";" + $port.State + ";" + $exepath.path >> $nomfichierPort
}

#List all local user 

$listlocaluser = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"

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
Write-Host "#########>Take Startup Registry Information<#########" -ForegroundColor DarkGreen

"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" >> $nomfichierStartup

$nomfichierStartup = "./Startup- " + "$OSName" + "HKCU-RUN" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $nomfichierStartup
$nomfichierStartup = "./Startup- " + "$OSName" + "HKCU-RUNONCE" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $nomfichierStartup
$nomfichierStartup = "./Startup- " + "$OSName" + "HKCU-Windows" + ".csv"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $nomfichierStartup
$nomfichierStartup = "./Startup- " + "$OSName" + "HKLM-RUN" + ".csv"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $nomfichierStartup
$nomfichierStartup = "./Startup- " + "$OSName" + "HKLM-RUN" + ".csv"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" |Select-Object * -exclude PSPath,PSParentPath, PSChildName, PSProvider, PSDrive | Export-Csv -NoTypeInformation $nomfichierStartup




Write-Host "#########>Begin CIS audit<#########" -ForegroundColor Green
#Check password Policy
Write-Host "#########>Begin password policy audit<#########" -ForegroundColor DarkGreen


#Check Enforce password history
$id = "PP-" + "1.1.1"
$chaine = $id + ";" + "(L1)Ensure 'Enforce password history' is set to '24 or more password(s), value must be 24 or More" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordHistorySize"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Maximum password age 

$id = "PP-" + "1.1.2"
$chaine = "$id" + ";" + "(L1)Maximum password age is set to 365 or fewer days, value must be 365 or less but not 0" + ";"
$traitement = Get-Content $seceditfile |Select-String "MaximumPasswordAge" |select-object -First 1

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Minimum password age

$id = "PP-" + "1.1.3"
$chaine = "$id" + ";" + "(L1)Minimum password age is set to 1 or more day(s), value must be 1 or more but not 0" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordAge"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Check Minimum password length

$id = "PP-" + "1.1.4"

$chaine = "$id" + ";" + "(L1)Minimum password length is set to 14 or more character(s), value must be 14 or more" + ";"
$traitement = Get-Content $seceditfile |Select-String "MinimumPasswordLength"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Password must meet complexity requirements


$id = "PP-" + "1.1.5"
$chaine = "$id" + ";" + "(L1)Password must meet complexity requirements is set to Enabled, value must be 1" + ";"
$traitement = Get-Content $seceditfile |Select-String "PasswordComplexity"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Relax minimum password length limits'


$id = "PP-" + "1.1.6"
$chaine = "$id" + ";" + "(L1)Relax minimum password length limits' is set to Enabled, value must be 1 (Warning this may cause compatibility issues)" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SAM"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SAM" | Select-Object RelaxMinimumPasswordLengthLimits
 $traitement = $traitement.RelaxMinimumPasswordLengthLimits

if ( $traitement -eq $null) {
$traitement = "not configure"
}

}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Store passwords using reversible encryption
$indextest += 1

$id = "PP-" + "1.1.7"
$chaine = "$id" + ";" + "(L1)Store passwords using reversible encryption is set to Disabled, value must be 0" + ";"
$traitement = Get-Content $seceditfile |Select-String "ClearTextPassword"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check lock out policy
Write-Host "#########>Begin account lockout policy audit<#########" -ForegroundColor DarkGreen

#Check Account lockout duration

$id = "ALP-" + "1.2.1"

$chaine = "$id" + ";" + "(L1)Account lockout duration is set to 15 or more minute(s)" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern '(Durée du verrouillage)|(Lockout duration)'


$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Check Account lockout threshold

$id = "ALP-" + "1.2.2"

$chaine = "$id" + ";" + "(L1)Ensure Account lockout threshold is set to 5 or fewer invalid logon attempt(s), but not 0" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern '(Seuil de verrouillage)|(Lockout threshold)'

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Check Account lockout threshold

$id = "ALP-" + "1.2.3"

$chaine = "$id" + ";" + "(L1)Allow Administrator account lockout is set to Enabled, value must be 1" + ";"
$traitement = Get-Content $seceditfile |Select-String "AllowAdministratorLockout"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Reset account lockout 

$id = "ALP-" + "1.2.4"
$chaine = "$id" + ";" + "(L1)Reset account lockout counter after is set to 15 or more minute(s)" + ";"
$traitement = Get-Content $nomfichierNetAccount |Select-String -pattern "(Fenêtre d'observation du verrouillage)|(Lockout observation window)"


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check user rights assignment
Write-Host "#########>Begin user rights assignment audit<#########" -ForegroundColor DarkGreen

#Check Access Credential Manager 

$id = "URA-" + "2.2.1"
$chaine = "$id" + ";" + "(L1)Acess Credential Manager as a trusted caller is set to No One , value must be empty" + ";"
$traitement = Get-Content $seceditfile |Select-String "SeTrustedCredManAccessPrivilege"

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Access this computer from the network

$id = "URA-" + "2.2.2"
$chaine = "$id" + ";" + "(L1)Access this computer from the network, Only Administrators, Remote Desktop Users " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeNetworkLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Check Act as part of the operating system

$id = "URA-" + "2.2.3"
$chaine = "$id" + ";" + "(L1)Act as part of the operating system' , Must be empty " + ";"
$test = Get-Content $seceditfile |Select-String "SeTcbPrivilege"
$chaineSID = $chaineSID.line
$traitement = "SeTcbPrivilege" + ":"

$traitement += Reverse-SID $test

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Adjust memory quotas for a process

$id = "URA-" + "2.2.4"
$chaine = "$id" + ";" + "(L1)Adjust memory quotas for a process , Administrators, LOCAL SERVICE, NETWORK SERVICE " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeIncreaseQuotaPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeIncreaseQuotaPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Allow log on locally

$id = "URA-" + "2.2.5"

$chaine = "$id" + ";" + "(L1)Allow log on locally, Administrators, Users" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Allow log on through Remote Desktop Services

$id = "URA-" + "2.2.6"
$chaine = "$id" + ";" + "(L1)Allow log on through Remote Desktop Services, Only Administrators, Remote Desktop Users. If Remote Apps or CItrix authentificated users" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeRemoteInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Ensure Back up files and directories

$id = "URA-" + "2.2.7"
$chaine = "$id" + ";" + "(L1)Ensure Back up files and directories, Only Administrators," + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeBackupPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeBackupPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Change the system time'

$id = "URA-" + "2.2.8"
$chaine = "$id" + ";" + "(L1)Change the system time, Only Administrators and local service" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemtimePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeSystemtimePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Change the time zone

$id = "URA-" + "2.2.9"
$chaine = "$id" + ";" + "(L1)Change the time zone', Only Administrators ,local service and users" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeTimeZonePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeTimeZonePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Create a pagefile


$id = "URA-" + "2.2.10"
$chaine = "$id" + ";" + "(L1)Create a pagefile, Only Administrators " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreatePagefilePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeCreatePagefilePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Create a token object'

$id = "URA-" + "2.2.11"
$chaine = "$id" + ";" + "(L1)Create a token object, No one " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateTokenPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeCreateTokenPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Create global objects

$id = "URA-" + "2.2.12"
$chaine = "$id" + ";" + "(L1)Ensure Create global objects is set to Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateGlobalPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeCreateGlobalPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
#Create permanent shared objects'


$id = "URA" + "2.2.13"
$chaine = "$id" + ";" + "(L1)Ensure Create permanent shared objects, No one,value must empty" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreatePermanentPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeCreatePermanentPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Create symbolic links

$id = "URA" + "2.2.14"
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Create symbolic links, Administrator and for Hyper V NT VIRTUAL MACHINE\Virtual Machines. " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeCreateSymbolicLinkPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeCreateSymbolicLinkPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Debug programs

$id = "URA" + "2.2.15"
$id = "URA" + "$indextest"
$chaine = "$id" + ";" + "(L1)Ensure Debug programs is set to Administrators or no one" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDebugPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeDebugPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Deny access to this computer from the network

$id = "URA" + "2.2.16"
$chaine = "$id" + ";" + "(L1)Deny access to this computer from the network,Guest Local Account and member of Domain admin " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyNetworkLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyNetworkLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Deny log on as a batch job
$id = "URA" + "2.2.17"
$chaine = "$id" + ";" + "(L1)Deny log on as a batch job, Guest " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyBatchLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyBatchLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Deny log on as a service'
$id = "URA" + "2.2.18"
$chaine = "$id" + ";" + "(L1)Deny log on as a service, Guest " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyServiceLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyServiceLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Deny log on locally
$id = "URA" + "2.2.19"
$chaine = "$id" + ";" + "(L1)Deny log on locally, Guest and member of Domain admin " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Deny log on through Remote Desktop Services'
$id = "URA" + "2.2.20"
$chaine = "$id" + ";" + "(L1)Deny log on through Remote Desktop Services, Guest, Local account and member of Domain admin' " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeDenyRemoteInteractiveLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeDenyRemoteInteractiveLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Enable computer and user accounts to be trusted for delegation
$id = "URA" + "2.2.21"
$chaine = "$id" + ";" + "(L1)Enable computer and user accounts to be trusted for delegation,No one " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeEnableDelegationPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeEnableDelegationPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Force shutdown from a remote system
$id = "URA" + "2.2.22"
$chaine = "$id" + ";" + "(L1)Force shutdown from a remote system, Only administrators " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeRemoteShutdownPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeRemoteShutdownPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Generate security audits'
$id = "URA" + "2.2.23"
$chaine = "$id" + ";" + "(L1)Generate security audits is set to LOCAL SERVICE, NETWORK SERVICE " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeAuditPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeAuditPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Impersonate a client after authentication
$id = "URA" + "2.2.24"
$chaine = "$id" + ";" + "(L1)Impersonate a client after authentication , Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE " + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeImpersonatePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeImpersonatePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Increase scheduling priority
$id = "URA" + "2.2.25"
$chaine = "$id" + ";" + "(L1)Increase scheduling priority , only Administrator and Window Manager\Window Manager Group" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeIncreaseBasePriorityPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeIncreaseBasePriorityPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Load and unload device drivers'
$id = "URA" + "2.2.26"
$chaine = "$id" + ";" + "(L1)Load and unload device drivers' , only Administrator" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeLoadDriverPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeLoadDriverPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Lock pages in memory'
$id = "URA" + "2.2.27"
$chaine = "$id" + ";" + "(L1)Lock pages in memory, No one" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeLockMemoryPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeLockMemoryPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Log on as a batch job'
$id = "URA" + "2.2.28"
$chaine = "$id" + ";" + "(L2)Log on as a batch job',Administrators and very specific account" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeBatchLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeBatchLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Log on as a service
$id = "URA" + "2.2.29"
$chaine = "$id" + ";" + "(L2)Ensure Log on as a service is set to No One and NT VIRTUAL MACHINE\Virtual Machine( When HyperV is installed)" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeServiceLogonRight" 
$chaineSID = $chaineSID.line
$traitement = "SeServiceLogonRight" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Manage auditing and security log
$id = "URA" + "2.2.30"
$chaine = "$id" + ";" + "(L1)Manage auditing and security log,Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeSecurityPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeSecurityPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Modify an object label'
$id = "URA" + "2.2.31"
$chaine = "$id" + ";" + "(L1)Modify an object label, No one" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeRelabelPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeRelabelPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Modify firmware environment values'
$id = "URA" + "2.2.32"
$chaine = "$id" + ";" + "(L1)Modify firmware environment values is set to Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemEnvironmentPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeSystemEnvironmentPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Perform volume maintenance tasks
$id = "URA" + "2.2.33"
$chaine = "$id" + ";" + "(L1)Perform volume maintenance tasks is set to Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeManageVolumePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeManageVolumePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Profile single process'
$id = "URA" + "2.2.34"
$chaine = "$id" + ";" + "(L1)Profile single process is set to Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeProfileSingleProcessPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeProfileSingleProcessPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Profile system performance
$id = "URA" + "2.2.35"
$chaine = "$id" + ";" + "(L1)Profile system performance is set to Administrators, NT SERVICE\WdiServiceHost" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeSystemProfilePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeSystemProfilePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Replace a process level token
$id = "URA" + "2.2.36"
$chaine = "$id" + ";" + "(L1)Replace a process level token is set to LOCAL SERVICE, NETWORK SERVICE and for IIS server you may have IIS applications pools" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeAssignPrimaryTokenPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeAssignPrimaryTokenPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Restore files and directories'
$id = "URA" + "2.2.37"
$chaine = "$id" + ";" + "(L1)Restore files and directories is set to Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeRestorePrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeRestorePrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Shut down the system
$id = "URA" + "2.2.38"
$chaine = "$id" + ";" + "(L1)Shut down the system is set to Administrators, Users" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeShutdownPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeShutdownPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Take ownership of files or other objects
$id = "URA" + "2.2.39"
$chaine = "$id" + ";" + "(L1)Take ownership of files or other objects is set to Administrators" + ";"
$chaineSID = Get-Content $seceditfile |Select-String "SeTakeOwnershipPrivilege" 
$chaineSID = $chaineSID.line
$traitement = "SeTakeOwnershipPrivilege" + ":"
$traitement += Reverse-SID $chaineSID

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Checking Account
Write-Host "#########>Begin Accounts audit<#########" -ForegroundColor DarkGreen

#Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts
$id = "AA" + "2.3.1.1"
$chaine = "$id" + ";" + "(L1)Accounts: Block Microsoft accounts is set to Users cannot add or log on with Microsoft accounts Value must be 3 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object NoConnectedUser
 $traitement = $traitement.NoConnectedUser
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Ensure 'Accounts: Guest account status' is set to 'Disabled'
$id = "AA" + "2.3.1.2"
$chaine = "$id" + ";" + "(L1)Ensure Accounts: Guest account status is set to 'Disabled" + ";"
$traitement = "Default guest Account:" + $nomcompteguest + ",statut : $gueststate"



$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Accounts: Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled
$id = "AA" + "2.3.1.3"
$chaine = "$id" + ";" + "(L1)Accounts: Limit local account use of blank passwords to console logon only is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object LimitBlankPasswordUse
 $traitement = $traitement.LimitBlankPasswordUse
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Configure 'Accounts: Rename administrator account' (Scored)

$id = "AA" + "2.3.1.4"
$chaine = "$id" + ";" + "(L1)Accounts: Rename administrator account" + ";"
$traitement = "Default local admin Account:" + $nomcompteadmin 


$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Configure 'Accounts: Rename guest account'' (Scored)


$id = "AA" + "2.3.1.5"
$chaine = "$id" + ";" + "(L1)Accounts: Rename guest account" + ";"
$traitement = "Default guest Account:" + $nomcompteguest

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
#Checking Audit
Write-Host "#########>Begin audit policy audit<#########" -ForegroundColor DarkGreen


#Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings

$id = "APA" + "2.3.2.1"
$chaine = "$id" + ";" + "(L1)Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object SCENoApplyLegacyAuditPolicy
 $traitement = $traitement.SCENoApplyLegacyAuditPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled
$id = "APA" + "2.3.2.2"
$chaine = "$id" + ";" + "(L1)Audit: Shut down system immediately if unable to log security audits is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object CrashOnAuditFail
 $traitement = $traitement.CrashOnAuditFail
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking devices
Write-Host "#########>Begin devices policy audit<#########" -ForegroundColor DarkGreen

#Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators

$id = "DEVP" + "2.3.4.1"
$chaine = "$id" + ";" + "(L1)Ensure Devices: Allowed to format and eject removable media is set to Administrators and Interactive Users' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object AllocateDASD
 $traitement = $traitement.AllocateDASD
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Devices: Prevent users from installing printer drivers' is set to 'Enabled
$id = "DEVP" + "2.3.4.1"
$chaine = "$id" + ";" + "(L2)Devices: Prevent users from installing printer drivers is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" |Select-Object AddPrinterDrivers
 $traitement = $traitement.AddPrinterDrivers
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Checking Domain member Audit
Write-Host "#########>Begin Domain member policy audit<#########" -ForegroundColor DarkGreen

#Domain member: Digitally encrypt or sign secure channel data (always) is set to Enable

$id = "DMP" + "2.3.6.1"
$chaine = "$id" + ";" + "(L1)Domain member: Digitally encrypt or sign secure channel data (always) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireSignOrSeal
 $traitement = $traitement.RequireSignOrSeal
}
else {
 $traitement = "not configure"
}

Clean-Value($chaine)
Clean-Value($traitement)

#Domain member:  Digitally encrypt secure channel data (when possible) is set to Enabled,
$id = "DMP" + "2.3.6.2"
$chaine = "$id" + ";" + "(L1)Domain member: Digitally encrypt secure channel data (when possible) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object SealSecureChannel
 $traitement = $traitement.SealSecureChannel
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Domain member: Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
$id = "DMP" + "2.3.6.3"
$chaine = "$id" + ";" + "(L1)Domain member: Domain member: Digitally sign secure channel data (when possible) is set to Enabled, Value must be 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object SignSecureChannel
 $traitement = $traitement.SealSecureChannel
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Domain member: Disable machine account password changes
$id = "DMP" + "2.3.6.4"
$chaine = "$id" + ";" + "(L1)Domain member: Disable machine account password changes is set to Disabled, Value must be 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object DisablePasswordChange
 $traitement = $traitement.DisablePasswordChange
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0
$id = "DMP" + "2.3.6.5"
$chaine = "$id" + ";" + "(L1)Domain member: Maximum machine account password age is set to 30 or fewer days, but not 0 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
				$traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object MaximumPasswordAge
 $traitement = $traitement.MaximumPasswordAge
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled
$id = "DMP" + "2.3.6.6"
$chaine = "$id" + ";" + "(L1)Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters |Select-Object RequireStrongKey
 $traitement = $traitement.RequireStrongKey
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking Interactive logon
Write-Host "#########>Begin Interactive logon audit<#########" -ForegroundColor DarkGreen

#Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'

$id = "IL" + "2.3.7.1"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not require CTRL+ALT+DEL' is set to Disabled,value must 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DisableCAD
 $traitement = $traitement.DisableCAD
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Ensure Interactive logon: Do not display last user name is set to Enabled


$id = "IL" + "2.3.7.2"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Do not display last user name is set to Enabled,value must 1 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object DontDisplayLastUserName
 $traitement = $traitement.DontDisplayLastUserName
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#Ensure Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'


$id = "IL" + "2.3.7.3"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0',value must 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object MaxDevicePasswordFailedAttempts
 $traitement = $traitement.MaxDevicePasswordFailedAttempts
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Interactive logon: Machine inactivity limit'

$id = "IL" + "2.3.7.4"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Machine inactivity limit' is set to 900 or fewer second(s), but not 0 " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object InactivityTimeoutSecs
 $traitement = $traitement.InactivityTimeoutSecs
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Configure 'Interactive logon: Message text for users attempting to log on

$id = "IL" + "2.3.7.5"
$chaine = "$id" + ";" + "(L1)Configure 'Interactive logon: Message text for users attempting to log on, but not empty " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object LegalNoticeText
 $traitement = $traitement.LegalNoticeText
}
else {
 $traitement = "not configure"
}


Clean-Value($chaine)
Clean-Value($traitement)

#Configure 'Interactive logon: Message title for users attempting to log on

$id = "IL" + "2.3.7.6"
$chaine = "$id" + ";" + "(L1)Configure Interactive logon: Message title for users attempting to log on, but not empty " + ";"
$exist = Test-Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |Select-Object LegalNoticeCaption
 $traitement = $traitement.LegalNoticeCaption
}
else {
 $traitement = "not configure"
}

Clean-Value($chaine)
Clean-Value($traitement)


#Configure Interactive logon: Number of previous logons to cache

$id = "IL" + "2.3.7.7"
$chaine = "$id" + ";" + "(L2)Ensure interactive logon: Number of previous logons to cache (in case domain controller is not available) is set to 4 or fewer logon(s) " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object CachedLogonsCount
 $traitement = $traitement.CachedLogonsCount
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'Interactive logon: Prompt user to change password before expiration

$id = "IL" + "2.3.7.8"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Prompt user to change password before expiration is set to between 5 and 14 days " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object PasswordExpiryWarning
 $traitement = $traitement.PasswordExpiryWarning
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



# Ensure Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher

$id = "IL" + "2.3.7.9"
$chaine = "$id" + ";" + "(L1)Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher,value must be 1 (Lock Workstation) or 2 (Force Logoff) " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object ScRemoveOption
 $traitement = $traitement.ScRemoveOption
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Checking Interactive logon
Write-Host "#########>Begin Microsoft network client audit<#########" -ForegroundColor DarkGreen

#Microsoft network client: Digitally sign communications (always)


$id = "MNC" + "2.3.8.1"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (always) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object RequireSecuritySignature
 $traitement = $traitement.RequireSecuritySignature
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#'Microsoft network client: Digitally sign communications (if server agrees

$id = "MNC" + "2.3.8.2"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Digitally sign communications (if server agrees) is set to Enabled,value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnableSecuritySignature
 $traitement = $traitement.EnableSecuritySignature
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Microsoft network client: Send unencrypted password to third-party SMB servers

$id = "MNC" + "2.3.8.3"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network client: Send unencrypted password to third-party SMB servers is set to Disabled,value must be 0 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" |Select-Object EnablePlainTextPassword
 $traitement = $traitement.EnablePlainTextPassword
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking Microsoft network server 
Write-Host "#########>Begin Microsoft network server audit<#########" -ForegroundColor DarkGreen

#Microsoft network server: Amount of idle time required before suspending session
$id = "MNS" + "2.3.9.1"
$chaine = "$id" + ";" + "(L1)Microsoft network server: Amount of idle time required before suspending session is set to 15 or fewer minute(s) but not 0, " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object AutoDisconnect
 $traitement = $traitement.AutoDisconnect
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'Microsoft network server: Digitally sign communications (always

$id = "MNS" + "2.3.9.2"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network server: Digitally sign communications (always) is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object RequireSecuritySignature
 $traitement = $traitement.RequireSecuritySignature
}
else {
 $traitement = "not configure"
}

Clean-Value($chaine)
Clean-Value($traitement)


# Ensure 'Microsoft network server: Digitally sign communications (if client agrees)'

$id = "MNS" + "2.3.9.3"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network server: Digitally sign communications (if client agrees) is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object EnableSecuritySignature
 $traitement = $traitement.EnableSecuritySignature
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


# Microsoft network server: Disconnect clients when logon hours expire'

$id = "MNS" + "2.3.9.4"
$chaine = "$id" + ";" + "(L1)Ensure Microsoft network server: Disconnect clients when logon hours expire is set to Enabled,must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object EnableForcedLogoff
 $traitement = $traitement.EnableForcedLogoff
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


# Microsoft network server: Server SPN target name validation level'

$id = "MNS" + "2.3.9.5"
$chaine = "$id" + ";" + "(L1)Microsoft network server: Server SPN target name validation level is set to Accept if provided by client or higher,must be 1 or highter " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" |Select-Object SMBServerNameHardeningLevel
 $traitement = $traitement.SMBServerNameHardeningLevel
}
else {
 $traitement = "not configure"
}


Clean-Value($chaine)
Clean-Value($traitement)


#Checking Microsoft network server
Write-Host "#########>Begin Network access audit<#########" -ForegroundColor DarkGreen

# Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled

$id = "NA" + "2.3.10.1"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Allow anonymous SID/Name translation is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object AnonymousNameLookup
 $traitement = $traitement.AnonymousNameLookup
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Do not allow anonymous enumeration of SAM accounts'

$id = "NA" + "2.3.10.2"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts is set to Enabled,must be 1 " + ";"
$traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymousSAM
$traitement = $traitement.RestrictAnonymousSAM
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Do not allow anonymous enumeration of SAM accounts and shares'

$id = "NA" + "2.3.10.3"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled',must be 1 " + ";"
$traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object RestrictAnonymous
$traitement = $traitement.RestrictAnonymous
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Do not allow storage of passwords and credentials for network authentication

$id = "NA" + "2.3.10.4"
$chaine = "$id" + ";" + "(L1)Network access: Do not allow storage of passwords and credentials for network authentication is set to Enabled,must be 1 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object DisableDomainCreds
 $traitement = $traitement.DisableDomainCreds
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Let Everyone permissions apply to anonymous user

$id = "NA" + "2.3.10.5"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Let Everyone permissions apply to anonymous users is set to Disabled,must be 0 " + ";"
$exist = Test-Path HKLM:\System\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa |Select-Object EveryoneIncludesAnonymous
 $traitement = $traitement.EveryoneIncludesAnonymous
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
# Network access: Named Pipes that can be accessed anonymously

$id = "NA" + "2.3.10.6"
$chaine = "$id" + ";" + "(L1)Configure Network access: Named Pipes that can be accessed anonymously,must be empty " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object NullSessionPipes
 $traitement = $traitement.NullSessionPipes
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Remotely accessible registry paths

$id = "NA" + "2.3.10.7"
$chaine = "$id" + ";" + "(L1)Network access: Remotely accessible registry paths, musbe System\CurrentControlSet\Control\ProductOptions | System\CurrentControlSet\Control\Server Applications |Software\Microsoft\Windows NT\CurrentVersion " + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths |Select-Object Machine
 $traitement = $traitement.Machine
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Remotely accessible registry paths and sub-paths

$id = "NA" + "2.3.10.8"
$chaine = "$id" + ";" + "(L1)Network access: Remotely accessible registry paths and sub-paths:, check 2.3.10.8 part for the liste" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths |Select-Object Machine
 $traitement = $traitement.Machine
}
else {
 $traitement = "not configure"
}
$traitement > "NetworkAcces-Allowpath.txt"
$chaine += "Check NetworkAcces-Allowpath.txt"
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Restrict anonymous access to Named Pipes and Shares

$id = "NA" + "2.3.10.9"
$chaine = "$id" + ";" + "Ensure Network access: Restrict anonymous access to Named Pipes and Shares is set to Enabled,value must be 1" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object RestrictNullSessAccess
 $traitement = $traitement.RestrictNullSessAccess
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
# Network access: Restrict clients allowed to make remote calls to SAM

$id = "NA" + "2.3.10.10"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Restrict clients allowed to make remote calls to SAM is set to Administrators: Remote Access: Allow" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object restrictremotesam
 $traitement = $traitement.restrictremotesam
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Shares that can be accessed anonymously' is set to 'None'

$id = "NA" + "2.3.10.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None, value must be empty or {}" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters |Select-Object NullSessionShares
 $traitement = $traitement.NullSessionShares
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

# Network access: Sharing and security model for local accounts

$id = "NA" + "2.3.10.12"
$chaine = "$id" + ";" + "(L1)Ensure Network access: Sharing and security model for local accounts is set to Classic - local users authenticate as themselves,value must be 0" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object ForceGuest
 $traitement = $traitement.ForceGuest
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
#Checking Microsoft network server 
Write-Host "#########>Begin Network security audit<#########" -ForegroundColor DarkGreen

#Network security: Allow Local System to use computer identity for NTLM

$id = "NS" + "2.3.11.1"
$chaine = "$id" + ";" + "(L1)Network security: Allow Local System to use computer identity for NTLM is set to 'Enabled,value must be 1" + ";"
$exist = Test-Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa |Select-Object UseMachineId
 $traitement = $traitement.UseMachineId
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Network security: Allow LocalSystem NULL session fallback

$id = "NS" + "2.3.11.2"
$chaine = "$id" + ";" + "(L1)Ensure Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled,value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object AllowNullSessionFallback
 $traitement = $traitement.AllowNullSessionFallback
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Network Security: Allow PKU2U authentication requests to this computer to use online identities

$id = "NS" + "2.3.11.3"
$chaine = "$id" + ";" + "(L1)Network Security: Allow PKU2U authentication requests to this computer to use online identities is set to Disabled,value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"|Select-Object AllowOnlineID
 $traitement = $traitement.AllowOnlineID
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Network security: Configure encryption types allowed for Kerberos

$id = "NS" + "2.3.11.4"
$chaine = "$id" + ";" + "(L1)Ensure Network security: Configure encryption types allowed for Kerberos is set to AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"|Select-Object SupportedEncryptionTypes
 $traitement = $traitement.SupportedEncryptionTypes
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#'Network security: Do not store LAN Manager hash value on next password change

$id = "NS" + "2.3.11.5"
$chaine = "$id" + ";" + "(L1)Network security: Do not store LAN Manager hash value on next password change is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"|Select-Object NoLMHash
 $traitement = $traitement.NoLMHash
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Network security: Force logoff when logon hours expire' is set to 'Enabled'

$id = "NS" + "2.3.11.6"
$chaine = "$id" + ";" + "(L1)Network security: Force logoff when logon hours expire is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"|Select-Object EnableForcedLogOff
 $traitement = $traitement.EnableForcedLogOff
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Network security: LAN Manager authentication level

$id = "NS" + "2.3.11.7"
$chaine = "$id" + ";" + "(L1)Ensure Network security: LAN Manager authentication level is set to Send NTLMv2 response only. Refuse LM & NTLM,value must be 5" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"|Select-Object LmCompatibilityLevel
 $traitement = $traitement.LmCompatibilityLevel
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Network security: LDAP client signing requirements'

$id = "NS" + "2.3.11.8"
$chaine = "$id" + ";" + "(L1)Ensure Network security: LDAP client signing requirements is set to Negotiate signing or higher,value must be 1 or highter" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"|Select-Object LDAPClientIntegrity
 $traitement = $traitement.LDAPClientIntegrity
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Network security: Minimum session security for NTLM SSP based (including secure RPC) clients

$id = "NS" + "2.3.11.9"
$chaine = "$id" + ";" + "(L1)Ensure Network security: Minimum session security for NTLM SSP based (including secure RPC) clients is set to Require NTLMv2 session security, Require 128-bit encryption,value must be 537395200" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object NTLMMinClientSec
 $traitement = $traitement.NTLMMinClientSec
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#NNetwork security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'

$id = "NS" + "2.3.11.10"
$chaine = "$id" + ";" + "(L1)Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption', Require 128-bit encryption,value must be 537395200" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"|Select-Object NTLMMinServerSec
 $traitement = $traitement.NTLMMinServerSec
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#System cryptography
Write-Host "#########>Begin System cryptography<#########" -ForegroundColor DarkGreen



#System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher

$id = "SC" + "2.3.14.1"
$chaine = "$id" + ";" + "(L2)System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher,value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"|Select-Object ForceKeyProtection
 $traitement = $traitement.ForceKeyProtection
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#CheckingSystem objects
Write-Host "#########>Begin System objects audit<#########" -ForegroundColor DarkGreen


#System objects: Require case insensitivity for non-Windows subsystems


$id = "SO" + "2.3.15.1"
$chaine = "$id" + ";" + "(L1)Ensure System objects: Require case insensitivity for non-Windows subsystems is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"|Select-Object ObCaseInsensitive
 $traitement = $traitement.ObCaseInsensitive
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)


$id = "SO" + "2.3.15.2"
$chaine = "$id" + ";" + "(L1)Ensure System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links) is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"|Select-Object ProtectionMode
 $traitement = $traitement.ProtectionMode
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Checking User Account Control
Write-Host "#########>Begin User Account Control(UAC) audit<#########" -ForegroundColor DarkGreen

#User Account Control: Admin Approval Mode for the Built-in Administrator account

$id = "UAC" + "2.3.17.1"
$chaine = "$id" + ";" + "(L1)Ensure User Account Control: Admin Approval Mode for the Built-in Administrator account is set to Enabled,value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object FilterAdministratorToken
 $traitement = $traitement.FilterAdministratorToken
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode


$id = "UAC" + "2.3.17.2"
$chaine = "$id" + ";" + "(L1)Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode is set to Prompt for consent on the secure desktop,value must be 2(The value of 2 displays the UAC prompt that needs to be permitted or denied on a secure desktop. No authentication is required) or 1(A value of 1 requires the admin to enter username and password when operations require elevated privileges on a secure desktop)" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object ConsentPromptBehaviorAdmin
 $traitement = $traitement.ConsentPromptBehaviorAdmin
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#User Account Control: Behavior of the elevation prompt for standard users'


$id = "UAC" + "2.3.17.3"
$chaine = "$id" + ";" + "(L1)Ensure User Account Control: Behavior of the elevation prompt for standard users is set to Automatically deny elevation requests, value must be 0(A value of 0 will automatically deny any operation that requires elevated privileges if executed by standard users)." + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object ConsentPromptBehaviorUser
 $traitement = $traitement.ConsentPromptBehaviorUser
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#User Account Control: Detect application installations and prompt for elevation


$id = "UAC" + "2.3.17.4"
$chaine = "$id" + ";" + "(L1)Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableInstallerDetection
 $traitement = $traitement.EnableInstallerDetection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#User Account Control: Only elevate UIAccess applications that are installed in secure locations

$id = "UAC" + "2.3.17.5"
$chaine = "$id" + ";" + "(L1)Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableSecureUIAPaths
 $traitement = $traitement.EnableSecureUIAPaths
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#User Account Control: Run all administrators in Admin Approval Mode


$id = "UAC" + "2.3.17.6"
$chaine = "$indextest" + ";" + "(L1)Ensure 'User Account Control: Run all administrators in Admin Approval Mode is set to Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableLUA
 $traitement = $traitement.EnableLUA
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#User Account Control: Switch to the secure desktop when prompting for elevation


$id = "UAC" + "2.3.17.7"
$chaine = "$id" + ";" + "(L1)Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object PromptOnSecureDesktop
 $traitement = $traitement.PromptOnSecureDesktop
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#User Account Control: Virtualize file and registry write failures to per-user locations

$id = "UAC" + "2.3.17.8"
$chaine = "$id" + ";" + "(L1)Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object EnableVirtualization
 $traitement = $traitement.EnableVirtualization
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Checking System Services
Write-Host "#########>Begin System Services audit<#########" -ForegroundColor DarkGreen

#Bluetooth Audio Gateway Service (BTAGService)

$id = "SS" + "5.1"
$chaine = "$id" + ";" + "Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed "
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Bluetooth Support Service (bthserv)'

$id = "SS" + "5.2"
$chaine = "$id" + ";" + "(L2)Ensure Bluetooth Support Service (bthserv)' is set to 'Disabled', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Computer Browser (Browser)'

$id = "SS" + "5.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Computer Browser (Browser)' is set to 'Disabled' or 'Not Installed'', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Browser"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#CDownloaded Maps Manager (MapsBroker)'

$id = "SS" + "5.4"
$chaine = "$id" + ";" + "(L2)Ensure 'Downloaded Maps Manager (MapsBroker)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Geolocation Service (lfsvc)'

$id = "SS" + "5.5"
$chaine = "$id" + ";" + "(L2)Ensure 'Geolocation Service (lfsvc)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#IIS Admin Service (IISADMIN)'

$id = "SS" + "5.6"
$chaine = "$id" + ";" + "(L1)Ensure 'IIS Admin Service (IISADMIN)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Infrared monitor service (irmon)'

$id = "SS" + "5.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Infrared monitor service (irmon)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\irmon"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Internet Connection Sharing (ICS) (SharedAccess)

$id = "SS" + "5.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Internet Connection Sharing (ICS) (SharedAccess) ' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Link-Layer Topology Discovery Mapper (lltdsvc)'

$id = "SS" + "5.9"
$chaine = "$id" + ";" + "(L2)Ensure 'Link-Layer Topology Discovery Mapper (lltdsvc)' is set to 'Disabled', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#LxssManager (LxssManager)'

$id = "SS" + "5.10"
$chaine = "$id" + ";" + "(L1)Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Microsoft FTP Service (FTPSVC)'

$id = "SS" + "5.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Microsoft FTP Service (FTPSVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Microsoft iSCSI Initiator Service (MSiSCSI)'

$id = "SS" + "5.12"
$chaine = "$id" + ";" + "(L2)Ensure 'Microsoft iSCSI Initiator Service (MSiSCSI)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#OpenSSH SSH Server (sshd)'

$id = "SS" + "5.13"
$chaine = "$id" + ";" + "(L1)Ensure 'OpenSSH SSH Server (sshd)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\sshd"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

Clean-Value($chaine)
Clean-Value($traitement)

#MPeer Name Resolution Protocol (PNRPsvc)'

$id = "SS" + "5.14"
$chaine = "$id" + ";" + "(L2)Ensure 'Peer Name Resolution Protocol (PNRPsvc)' is set to 'Disabled'or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Peer Networking Grouping (p2psvc)'

$id = "SS" + "5.15"
$chaine = "$id" + ";" + "(L2)Ensure 'Peer Networking Grouping (p2psvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Peer Networking Identity Manager (p2pimsvc)'

$id = "SS" + "5.16"
$chaine = "$id" + ";" + "Ensure 'Peer Networking Identity Manager (p2pimsvc)' is set to 'Disabled or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#'PNRP Machine Name Publication Service (PNRPAutoReg)'

$id = "SS" + "5.17"
$chaine = "$id" + ";" + "(L2)Ensure 'PNRP Machine Name Publication Service (PNRPAutoReg)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Print Spooler (Spooler)

$id = "SS" + "5.18"
$chaine = "$id" + ";" + "(L2)Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (Automated), value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#Problem Reports and Solutions Control Panel Support (wercplsupport)'

$id = "SS" + "5.19"
$chaine = "$id" + ";" + "(L2)Ensure 'Problem Reports and Solutions Control Panel Support (wercplsupport)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Remote Access Auto Connection Manager (RasAuto)'

$id = "SS" + "5.20"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Access Auto Connection Manager (RasAuto)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Remote Desktop Configuration (SessionEnv)'

$id = "SS" + "5.21"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Configuration (SessionEnv)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Remote Desktop Services (TermService)'

$id = "SS" + "5.22"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Services (TermService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Remote Desktop Services UserMode Port Redirector (UmRdpService)'
$id = "SS" + "5.23"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Desktop Services UserMode Port Redirector (UmRdpService) is set to Disabled or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Remote Procedure Call (RPC) Locator (RpcLocator)'

$id = "SS" + "5.24"
$chaine = "$id" + ";" + "sshdEnsure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Remote Registry (RemoteRegistry)'

$id = "SS" + "5.25"
$chaine = "$id" + ";" + "(L2)Ensure 'Remote Registry (RemoteRegistry)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Routing and Remote Access (RemoteAccess)'
$id = "SS" + "5.26"
$chaine = "$id" + ";" + "(L1)Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Server (LanmanServer)'

$id = "SS" + "5.27"
$chaine = "$id" + ";" + "(L2)Ensure 'Server (LanmanServer)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Simple TCP/IP Services (simptcp)'

$id = "SS" + "5.28"
$chaine = "$id" + ";" + "(L1)Ensure 'Simple TCP/IP Services (simptcp)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#SNMP Service (SNMP)'

$id = "SS" + "5.29"
$chaine = "$id" + ";" + "(L2)Ensure 'SNMP Service (SNMP)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Special Administration Console Helper (sacsvr)

$id = "SS" + "5.30"
$chaine = "$id" + ";" + "(L1)Ensure 'Special Administration Console Helper (sacsvr)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#SSDP Discovery (SSDPSRV)' is

$id = "SS" + "5.31"
$chaine = "$id" + ";" + "(L1)Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#UPnP Device Host (upnphost)'

$id = "SS" + "5.32"
$chaine = "$id" + ";" + "(L1)Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Web Management Service (WMSvc)'

$id = "SS" + "5.33"
$chaine = "$id" + ";" + "(L1)Ensure 'Web Management Service (WMSvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Error Reporting Service (WerSvc)'

$id = "SS" + "5.34"
$chaine = "$id" + ";" + "(L2)Ensure 'Windows Error Reporting Service (WerSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Event Collector (Wecsvc)'

$id = "SS" + "5.35"
$chaine = "$id" + ";" + "(L2)Ensure 'Windows Event Collector (Wecsvc)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Media Player Network Sharing Service (WMPNetworkSvc)'

$id = "SS" + "5.36"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)'' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Mobile Hotspot Service (icssvc)'

$id = "SS" + "5.37"
$chaine = "$id" + ";" + "(L1)Ensure Windows Mobile Hotspot Service (icssvc)'' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Push Notifications System Service (WpnService)'

$id = "SS" + "5.38"
$chaine = "$id" + ";" + "(L2)Ensure Windows Push Notifications System Service (WpnService)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows PushToInstall Service (PushToInstall)'

$id = "SS" + "5.39"
$chaine = "$id" + ";" + "(L2)Ensure 'Windows PushToInstall Service (PushToInstall)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Remote Management (WS-Management) (WinRM)'

$id = "SS" + "5.40"
$chaine = "$id" + ";" + "(L2)Ensure Windows Remote Management (WS-Management) (WinRM) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)



#World Wide Web Publishing Service (W3SVC)'

$id = "SS" + "5.41"
$chaine = "$id" + ";" + "(L1)Ensure World Wide Web Publishing Service (W3SVC)' is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Xbox Accessory Management Service (XboxGipSvc)'
$id = "SS" + "5.42"
$chaine = "$id" + ";" + "(L1)Ensure Xbox Accessory Management Service (XboxGipSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Xbox Live Auth Manager (XblAuthManager)'

$id = "SS" + "5.43"
$chaine = "$id" + ";" + "(L1)Ensure Xbox Live Auth Manager (XblAuthManager) s set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Xbox Live Game Save (XblGameSave)'

$id = "SS" + "5.44"
$chaine = "$id" + ";" + "(L1)Ensure Xbox Live Game Save (XblGameSave) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Xbox Live Networking Service (XboxNetApiSvc)'

$id = "SS" + "5.45"
$chaine = "$id" + ";" + "(L1)Ensure Xbox Live Networking Service (XboxNetApiSvc) is set to 'Disabled' or 'Not Installed', value must be 4 or not installed" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "It s not installed"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking Firewall Domain Profile
Write-Host "#########>Begin Firewall Domain Profile audit<#########" -ForegroundColor DarkGreen



#Windows Firewall: Domain: Firewall state


$id = "WFDP" + "9.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On, value must be True" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object Enabled
$traitement = $traitement.Enabled

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Domain: Inbound connections

$id = "WFDP" + "9.1.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default), value must be Block" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object DefaultInboundAction
$traitement = $traitement.DefaultInboundAction

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Domain: Outbound connections'

$id = "WFDP" + "9.1.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass" + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object DefaultOutboundAction
$traitement = $traitement.DefaultOutboundAction

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Domain: Settings: Display a notification'

$id = "WFDP" + "9.1.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No', value must false " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object NotifyOnListen
$traitement = $traitement.NotifyOnListen

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Windows Firewall: Domain: Logging: Name''

$id = "WFDP" + "9.1.5"

$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object LogFileName
$traitement = $traitement.LogFileName

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Domain: Logging: Size limit (KB)'''

$id = "WFDP" + "9.1.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object LogMaxSizeKilobytes
$traitement = $traitement.LogMaxSizeKilobytes

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Domain: Logging: Log dropped packets'

$id = "WFDP" + "9.1.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object LogBlocked
$traitement = $traitement.LogBlocked

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Log successful connections'

$id = "WFDP" + "9.1.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes,value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object LogAllowed
$traitement = $traitement.LogAllowed
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking Firewall Private Profile
Write-Host "#########>Begin Firewall Private Profile audit<#########" -ForegroundColor DarkGreen



#Windows Firewall: Private: Firewall state

$id = "WFPPRIP" + "9.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Firewall state' is set to 'On, value must be True" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object Enabled
$traitement = $traitement.Enabled
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Private: Inbound connections

$id = "WFPPRIP" + "9.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default, value must be Block" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultInboundAction
$traitement = $traitement.DefaultInboundAction
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Private: Outbound connections'

$id = "WFPPRIP" + "9.2.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)', value must be Allow but if it's block it s fucking badass" + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object DefaultOutboundAction
$traitement = $traitement.DefaultOutboundAction

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Private: Settings: Display a notification'

$id = "WFPPRIP" + "9.2.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No, value must false " + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object NotifyOnListen
$traitement = $traitement.NotifyOnListen

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Private: Logging: Name

$id = "WFPPRIP" + "9.2.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log " + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object LogFileName
$traitement = $traitement.LogFileName

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Windows Firewall: Private: Logging: Size limit (KB)'

$id = "WFPPRIP" + "9.2.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater, value must 16384 or higthter " + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object LogMaxSizeKilobytes
$traitement = $traitement.LogMaxSizeKilobytes

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Private: Logging: Log dropped packets

$id = "WFPPRIP" + "9.2.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Private" |Select-Object LogBlocked
$traitement = $traitement.LogBlocked

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Private: Logging: Log successful connections'

$id = "WFPPRIP" + "9.2.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes',value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Domain" |Select-Object LogAllowed
$traitement = $traitement.LogAllowed
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Checking Firewall Public Profile
Write-Host "#########>Begin Firewall Public Profile audit<#########" -ForegroundColor DarkGreen



#Windows Firewall: Public: Firewall state

$id = "WFPPUBP" + "9.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Firewall state' is set to 'On, value must be True" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object Enabled
$traitement = $traitement.Enabled

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Public: Inbound connections

$id = "WFPPUBP" + "9.3.2"
$chaine = "$id" + ";" + "(L1)Windows Firewall: Public: Inbound connections' is set to 'Block , value must be Block" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object DefaultInboundAction
$traitement = $traitement.DefaultInboundAction

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Public: Outbound connections

$id = "WFPPUBP" + "9.3.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default), value must be Allow but if it's block it s fucking badass" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object DefaultOutboundAction
$traitement = $traitement.DefaultOutboundAction

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Windows Firewall: Public: Settings: Display a notification

$id = "WFPPUBP" + "9.3.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'Yes, value must false " + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object NotifyOnListen
$traitement = $traitement.NotifyOnListen

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Public: Settings: Apply local firewall rules

$id = "WFPPUBP" + "9.3.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No, value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"|Select-Object AllowLocalPolicyMerge
 $traitement = $traitement.AllowLocalPolicyMerge
}
else {
 $traitement = "not configure"
}


$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Public: Settings: Apply local connection security rules

$id = "WFPPUBP" + "9.3.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"|Select-Object AllowLocalIPsecPolicyMerge
 $traitement = $traitement.AllowLocalIPsecPolicyMerge
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Windows Firewall: Public: Logging: Name'

$id = "WFPPUBP" + "9.3.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object LogFileName
$traitement = $traitement.LogFileName

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Public: Logging: Size limit (KB)'

$id = "WFPPUBP" + "9.3.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater" + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object LogMaxSizeKilobytes
$traitement = $traitement.LogMaxSizeKilobytes

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Public: Logging: Log dropped packets

$id = "WFPPUBP" + "9.3.9"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes',value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object LogBlocked
$traitement = $traitement.LogBlocked

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Windows Firewall: Public: Logging: Log successful connections

$id = "WFPPUBP" + "9.3.10"
$chaine = "$id" + ";" + "(L1)Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes',value must be true " + ";"
$traitement = Get-NetFirewallProfile -Name "Public" |Select-Object LogAllowed
$traitement = $traitement.LogAllowed

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Checking Advanced Audit Policy Account Logon
Write-Host "#########>Begin Advanced Audit Policy audit<#########" -ForegroundColor DarkGreen

#Audit Credential Validation

$id = "AAAL" + "17.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Credential Validation' is set to 'Success and Failure" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Validation des informations d'identification)|(Credential Validation)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Security Group Management

$id = "AAGM" + "17.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Security Group Management' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Gestion des groupes de sécurité)|(Security Group Management)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit User Account Management

$id = "AAGM" + "17.2.3"
$chaine = "$indextest" + ";" + "(L1)Ensure 'Audit User Account Management' is set to 'Success and Failure" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Gestion des comptes d'utilisateur)|(User Account Management)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit PNP Activity

$id = "AADT" + "17.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit PNP Activity' is set to 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(événements Plug-and-Play)|(PNP Activity)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Process Creation'

$id = "AADT" + "17.3.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Process Creation' is set to 'Success" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Création du processus)|(Process Creation)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'Audit Account Lockout

$id = "AALL" + "17.5.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Account Lockout' is set to Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Verrouillage du compte)|(Account Lockout)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Group Membership'

$id = "AALL" + "17.5.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Group Membership' is set to 'Success" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Appartenance é un groupe)|(Group Membership)"
$traitement = $traitement.line
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Ensure 'Audit Logoff'

$id = "AALL" + "17.5.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Logoff' is set to 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Fermer la session)|(Logoff)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Ensure Audit Logon

$id = "AALL" + "17.5.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Logon' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Ouvrir la session)|(Logon)"
$traitement = $traitement.line

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Other Logon/Logoff Events

$id = "AALL" + "17.5.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Autres événements d'ouverture/fermeture de session)|(Other Logon/Logoff Events)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Special Logon

$id = "AALL" + "17.5.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Special Logon' is set to 'Success'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Ouverture de session spéciale)|(Special Logon)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Detailed File Share

$id = "AAOA" + "17.6.1"
$chaine = "$id" + ";" + "(L1)Encdsure Audit Detailed File Share is set to Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Partage de fichiers détaillé )|(Detailed File Share)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)



#Audit File Share'

$id = "AAOA" + "17.6.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit File Share'' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Partage de fichiers)|(File share)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Other Object Access Events'

$id = "AAOA" + "17.6.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Other Object Access Events''' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Autres événements d'accès à l'objet)|(Other Object Access Event)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Removable Storage

$id = "AAOA" + "17.6.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Removable Storage' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Stockage amovible)|(Removable Storage)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Audit Policy Change'

$id = "AAPC" + "17.7.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Modification de la stratégie d'audit)|(Audit Policy Change)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Authentication Policy Change

$id = "AAPC" + "17.7.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Authentication Policy Change' is set to 'Success''" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Modification de la stratégie d'authentification)|(Authentication Policy Change)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Audit Authorization Policy Change

$id = "AAPC" + "17.7.3"
$chaine = "$id" + ";" + "Ensure 'Audit Authorization Policy Change' is set to 'Success''" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Modification de la stratégie d'autorisation)|(Authorization Policy Change)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit SMPSSVC Rule-Level Policy Change'

$id = "AAPU" + "17.7.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit MPSSVC Rule-Level Policy Change is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Modification de la stratégie de niveau règle MPSSVC)|(MPSSVC Rule-Level Policy Change)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Other Policy Change Events'

$id = "AAPU" + "17.7.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Other Policy Change Events' is set to include 'Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Autres événements de modification de stratégie)|(Other Policy Change Events)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Sensitive Privilege Use'

$id = "AAPU" + "17.8.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Utilisation de priviléges sensibles)|(Sensitive Privilege Use)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'Audit IPsec Driver' is set to 'Success and Failure'

$id = "AAS" + "17.9.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit IPsec Driver' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Pilote IPSEC)|(IPsec Driver)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Audit Other System Events

$id = "AAS" + "17.9.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Other System Events' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Autres événements systéme)|(Other System Events)"
$traitement = $traitement.line
  
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Security State Change'

$id = "AAS" + "17.9.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Security State Change' is set to 'Success" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Modification de l'état de la sécurité)|(Security State Change)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Audit Security System Extension

$id = "AAS" + "17.9.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit Security System Extension' is set to 'Success and Failure" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Extension systéme de sécurité)|(Security System Extension)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Audit System Integrity

$id = "AAS" + "17.9.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Audit System Integrity' is set to 'Success and Failure'" + ";"
$traitement = Get-Content $auditconfigfile |Select-String -pattern "(Intégrité du systéme)|(System Integrity)"
$traitement = $traitement.line 

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Checking Personalization audit
Write-Host "#########>Begin Personalization audit<#########" -ForegroundColor DarkGreen


#Prevent enabling lock screen camera

$id = "PA" + "18.1.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent enabling lock screen camera' is set to 'Enabled, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"|Select-Object NoLockScreenCamera
 $traitement = $traitement.NoLockScreenCamera
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Prevent enabling lock screen slide show'

$id = "PA" + "18.1.1.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"|Select-Object NoLockScreenSlideshow
 $traitement = $traitement.NoLockScreenSlideshow
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Allow users to enable online speech recognition services

$id = "PA" + "18.1.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"|Select-Object AllowInputPersonalization
 $traitement = $traitement.AllowInputPersonalization
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Allow Online Tips'

$id = "PA" + "18.1.3"
$chaine = "$id" + ";" + "(L2)Ensure Allow Online Tips'' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"|Select-Object AllowOnlineTips
 $traitement = $traitement.AllowOnlineTips
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)





#Checking LAPS audit
Write-Host "#########>Begin LAPS audit<#########" -ForegroundColor DarkGreen

#LAPS AdmPwd GPO Extension / CSE is installed

$id = "LAPS" + "18.3.1"
$chaine = "$id" + ";" + "(L1)Ensure LAPS AdmPwd GPO Extension / CSE is installed, value must true " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"
if ( $exist -eq $true) {
 $traitement = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}"|Select-Object DllName
 $traitement = $traitement.DllName
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#Do not allow password expiration time longer than required by policy'

$id = "LAPS" + "18.3.2"

$chaine = "$id" + ";" + "(L1)Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PwdExpirationProtectionEnabled
 $traitement = $traitement.PwdExpirationProtectionEnabled
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)



#Enable Local Admin Password Management

$id = "LAPS" + "18.3.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable Local Admin Password Management' is set to 'Enabled', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object AdmPwdEnabled
 $traitement = $traitement.AdmPwdEnabled
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters'

$id = "LAPS" + "18.3.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters, value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordComplexity
 $traitement = $traitement.PasswordComplexity
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Password Settings: Password Length

$id = "LAPS" + "18.3.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more, value must greater than 15 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordLength
 $traitement = $traitement.PasswordLength
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Password Settings: Password Age (Days)'

$id = "LAPS" + "18.3.6"

$chaine = "$id" + ";" + "(L1)Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer', value must less than 30 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"|Select-Object PasswordAgeDays
 $traitement = $traitement.PasswordAgeDays
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Checking MSS (Legacy)
Write-Host "#########>Begin MS Security Guide audit<#########" -ForegroundColor DarkGreen


#Apply UAC restrictions to local accounts on network logons

$id = "MSSG" + "18.4.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"|Select-Object LocalAccountTokenFilterPolicy
 $traitement = $traitement.LocalAccountTokenFilterPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled

$id = "MSSG" + "18.4.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print"|Select-Object RpcAuthnLevelPrivacyEnabled
 $traitement = $traitement.RpcAuthnLevelPrivacyEnabled
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Configure SMB v1 client driver'


$id = "MSSG" + "18.4.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver', value must be 4" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"|Select-Object Start
 $traitement = $traitement.Start
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)



#Configure SMB v1 server' is set to 'Disabled'


$id = "MSSG" + "18.4.4"
$chaine = "$id" + ";" + "(L1)Ensure Configure SMB v1 server' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"|Select-Object SMB1
 $traitement = $traitement.SMB1
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'Enable Structured Exception Handling Overwrite Protection (SEHOP)'

$id = "MSSG" + "18.4.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"|Select-Object DisableExceptionChainValidation
 $traitement = $traitement.DisableExceptionChainValidation
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)

$id = "MSSG" + "18.4.6"
$chaine = "$id" + ";" + "(L1)Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended), value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"|Select-Object NodeType
 $traitement = $traitement.NodeType
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#WDigest Authentication'


$id = "MSSG" + "18.4.7"
$chaine = "$id" + ";" + "(L1)Ensure 'WDigest Authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"|Select-Object UseLogonCredential
 $traitement = $traitement.UseLogonCredential
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Checking MSS (Legacy)
Write-Host "#########>Begin MSS (Legacy) audit<#########" -ForegroundColor DarkGreen


#MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)'

$id = "MSSL" + "18.5.1"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled, value must be 0 or empty" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"|Select-Object AutoAdminLogon
 $traitement = $traitement.AutoAdminLogon
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)'

$id = "MSSL" + "18.5.2"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"|Select-Object disableIPSourceRouting
 $traitement = $traitement.disableIPSourceRouting
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)'

$id = "MSSL" + "18.5.3"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled, value must be 2" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object disableIPSourceRouting
 $traitement = $traitement.disableIPSourceRouting
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'MSS: (DisableSavePassword) Prevent the dial-up password from being saved''

$id = "MSSL" + "18.5.4"
$chaine = "$id" + ";" + "(L2)Ensure 'MSS: (DisableSavePassword) Prevent the dial-up password from being saved' is set to 'Enabled', source routing is completely disabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"|Select-Object DisableSavePassword
 $traitement = $traitement.DisableSavePassword
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes''

$id = "MSSL" + "18.5.5"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled, value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object EnableICMPRedirect
 $traitement = $traitement.EnableICMPRedirect
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds''

$id = "MSSL" + "18.5.6"
$chaine = "$id" + ";" + "(L2)Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes, value must be 300000" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"|Select-Object KeepAliveTime
 $traitement = $traitement.KeepAliveTime
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers

$id = "MSSL" + "18.5.7"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" |Select-Object NoNameReleaseOnDemand
 $traitement = $traitement.NoNameReleaseOnDemand
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)'

$id = "MSSL" + "18.5.8"
$chaine = "$id" + ";" + "(L2)Ensure MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)', value must be 0" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" |Select-Object PerformRouterDiscovery
 $traitement = $traitement.PerformRouterDiscovery
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)'

$id = "MSSL" + "18.5.9"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
if ( $exist -eq $true) {
				$traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" |Select-Object SafeDllSearchMode
 $traitement = $traitement.SafeDllSearchMode
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)'

$id = "MSSL" + "18.5.10"
$chaine = "$id" + ";" + "(L1)Ensure MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires 'is set to 'Enabled: 5 or fewer seconds (0 recommended)', value must be 5 or less " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |Select-Object ScreenSaverGracePeriod
 $traitement = $traitement.ScreenSaverGracePeriod
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted

$id = "MSSL" + "18.5.11"
$chaine = "$id" + ";" + "(L2)Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" |Select-Object tcpMaxDataRetransmissions
 $traitement = $traitement.tcpMaxDataRetransmissions
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted

$id = "MSSL" + "18.5.12"
$chaine = "$id" + ";" + "(L2)Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3: value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters" |Select-Object tcpMaxDataRetransmissions
 $traitement = $traitement.tcpMaxDataRetransmissions
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning

$id = "MSSL" + "18.5.13"
$chaine = "$id" + ";" + "(L1)Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" |Select-Object WarningLevel
 $traitement = $traitement.WarningLevel
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#DNS Client
Write-Host "#########>Begin DNS Client audit<#########" -ForegroundColor DarkGreen



#DNS Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher

$id = "DNSCA" + "18.6.4.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher, value must be 2 OR 3 could cause issue in domain joined environment " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object DoHPolicy
 $traitement = $traitement.DoHPolicy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#DNS Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher

$id = "DNSCA" + "18.6.4.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks, value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object EnableNetbios
 $traitement = $traitement.EnableNetbios
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)





#Turn off multicast name resolution'
$id = "DNSCA" + "18.6.4.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only), value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" |Select-Object EnableMulticast
 $traitement = $traitement.EnableMulticast
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Check Fonts
Write-Host "#########>Begin Fonts audit<#########" -ForegroundColor DarkGreen


#Enable Font Providers'

$id = "FONT" + "18.6.5.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Enable Font Providers' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableFontProviders
 $traitement = $traitement.EnableFontProviders
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Check Lanman Workstation
Write-Host "#########>Begin Lanman Workstation audit<#########" -ForegroundColor DarkGreen


#Enable insecure guest logons'

$id = "LW" + "18.6.8.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable insecure guest logons' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" |Select-Object AllowInsecureGuestAuth
 $traitement = $traitement.AllowInsecureGuestAuth
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Check Link-Layer Topology Discovery
Write-Host "#########>Begin Link-Layer Topology Discovery audit<#########" -ForegroundColor DarkGreen

#Turn on Mapper I/O (LLTDIO) driver'

$id = "LLTDIO" + "18.6.9.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowLLTDIOOnDomain
 $traitement = $traitement.AllowLLTDIOOnDomain
 $traitementtemp = "AllowLLTDIOOnDomain" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowLLTDIOOnPublicNet
 $traitement = $traitement.AllowLLTDIOOnPublicNet
 $traitementtemp += "AllowLLTDIOOnPublicNet" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object EnableLLTDIO
 $traitement = $traitement.EnableLLTDIO
 $traitementtemp += "EnableLLTDIO" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object ProhibitLLTDIOOnPrivateNet
 $traitement = $traitement.ProhibitLLTDIOOnPrivateNet
 $traitementtemp += "ProhibitLLTDIOOnPrivateNet" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}

$chaine += $traitementtemp
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Turn on Responder (RSPNDR) driver

$id = "LLTDIO" + "18.6.9.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowRspndrOnDomain
 $traitement = $traitement.AllowRspndrOnDomain
 $traitementtemp = "AllowRspndrOnDomain" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object AllowRspndrOnPublicNet
 $traitement = $traitement.AllowRspndrOnPublicNet
 $traitementtemp += "AllowRspndrOnPublicNet" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object EnableRspndr
 $traitement = $traitement.EnableRspndr
 $traitementtemp += "EnableRspndr" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD" |Select-Object ProhibitRspndrOnPrivateNet
 $traitement = $traitement.ProhibitRspndrOnPrivateNet
 $traitementtemp += "ProhibitRspndrOnPrivateNet" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}

$chaine += $traitementtemp
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Check Microsoft Peer-to-Peer Networking Services
Write-Host "#########>Begin Microsoft Peer-to-Peer Networking Service saudit<#########" -ForegroundColor DarkGreen


#Turn off Microsoft Peer-to-Peer Networking Services

$id = "PPNS" + "18.6.10.2"

$chaine = "$id" + ";" + "(L2)Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" |Select-Object Disabled
 $traitement = $traitement.Disabled
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
#Check Network Connections
Write-Host "#########>Begin Network Connections audit<#########" -ForegroundColor DarkGreen

#Prohibit installation and configuration of Network Bridge on your DNS domain network

$id = "NC" + "18.6.11.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_AllowNetBridge_NLA
 $traitement = $traitement.NC_AllowNetBridge_NLA
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Prohibit use of Internet Connection Sharing on your DNS domain network

$id = "NC" + "18.6.11.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_ShowSharedAccessUI
 $traitement = $traitement.NC_ShowSharedAccessUI
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Require domain users to elevate when setting a network's location'

$id = "NC" + "18.6.11.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" |Select-Object NC_StdDomainUserSetLocation
 $traitement = $traitement.NC_StdDomainUserSetLocation
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Hardened UNC Paths

$id = "NP" + "18.6.14.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Hardened UNC Paths' is set to 'Enabled, with Require Mutual Authentication and Require Integrity set for all NETLOGON and SYSVOL shares', RequireMutualAuthentication=1, RequireIntegrity=1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" |Select-Object "\\*\NETLOGON"
 $traitement = $traitement."\\*\NETLOGON"
 $traitementtemp = "\\*\NETLOGON" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider" |Select-Object "\\*\SYSVOL"
 $traitement = $traitement."\\*\SYSVOL"
 $traitementtemp = "\\*\SYSVOL" + ":" + "$traitement" + "|"
}
else {
 $traitement = "not configure"
}

$chaine += $traitementtemp
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)



#Disable IPv6

$id = "IPV6" + "18.6.19.2.1"

$chaine = "$id" + ";" + "(L2)Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)'), value must be 255 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" |Select-Object disabledComponents
 $traitement = $traitement.disabledComponents
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Configuration of wireless settings using Windows Connect Now

$id = "WCN" + "18.6.20.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object EnableRegistrars
 $traitement = $traitement.EnableRegistrars
 $traitementtemp = "EnableRegistrars" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableUPnPRegistrar
 $traitement = $traitement.DisableUPnPRegistrar
 $traitementtemp += "DisableUPnPRegistrar" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object disableInBand802DOT11Registrar
 $traitement = $traitement.disableInBand802DOT11Registrar
 $traitementtemp += "disableInBand802DOT11Registrar" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableFlashConfigRegistrar
 $traitement = $traitement.DisableFlashConfigRegistrar
 $traitementtemp += "DisableFlashConfigRegistrar" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" |Select-Object DisableWPDRegistrar
 $traitement = $traitement.DisableWPDRegistrar
 $traitementtemp += "DisableWPDRegistrar" + ":" + "$traitement" + "|"
}
else {
 $traitement = "not configure"
}

$chaine += $traitementtemp
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)
#Prohibit access of the Windows Connect Now wizards'

$id = "WCN" + "18.6.20.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" |Select-Object DisableWcnUi
 $traitement = $traitement.DisableWcnUi
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Minimize the number of simultaneous connections to the Internet or a Windows Domain'

$id = "WCM" + "18.6.21.1"
$chaine = "$id" + ";" + "(L1)Ensure Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" |Select-Object fMinimizeConnections
 $traitement = $traitement.fMinimizeConnections
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Prohibit connection to non-domain networks when connected to domain authenticated network'

$id = "WCM" + "18.6.21.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" |Select-Object fBlockNonDomain
 $traitement = $traitement.fBlockNonDomain
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)




#Check WLAN Settings
Write-Host "#########>Begin WLAN Settings audit<#########" -ForegroundColor DarkGreen
#Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services

$id = "WLAN" + "18.6.23.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" |Select-Object AutoConnectAllowedOEM
 $traitement = $traitement.AutoConnectAllowedOEM
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Check WLAN Settings
Write-Host "#########>Begin Printer Settings audit<#########" -ForegroundColor DarkGreen
#Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled

$id = "PRINT" + "18.7.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'', value must be 2 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object RegisterSpoolerRemoteRpcEndPoint
 $traitement = $traitement.RegisterSpoolerRemoteRpcEndPoint
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'

$id = "PRINT" + "18.7.2"
$chaine = "$id" + ";" + "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled', value must be 1 , 2 mean audit mode " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object RedirectionguardPolicy
 $traitement = $traitement.RedirectionguardPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'

$id = "PRINT" + "18.7.3"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP', value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcUseNamedPipeProtocol
 $traitement = $traitement.RpcUseNamedPipeProtocol
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# Ensure '(L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default''

$id = "PRINT" + "18.7.4"
$chaine = "$id" + ";" + "(L1) (L1) Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default', value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcAuthentication
 $traitement = $traitement.RpcAuthentication
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# Ensure '(L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'

$id = "PRINT" + "18.7.5"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP', value must be 0x7 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcProtocols
 $traitement = $traitement.RpcProtocols
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# (L1) Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher

$id = "PRINT" + "18.7.7"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 0 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\RPC" |Select-Object RpcTcpPort
 $traitement = $traitement.RpcTcpPort
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# (L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'

$id = "PRINT" + "18.7.8"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0' (Automated) value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object RestrictDriverInstallationToAdministrators
 $traitement = $traitement.RestrictDriverInstallationToAdministrators
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

# (L1) Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles'

$id = "PRINT" + "18.7.9"
$chaine = "$id" + ";" + "(L1)Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue-specific files to Color profiles' value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" |Select-Object CopyFilesPolicy
 $traitement = $traitement.CopyFilesPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# (L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt''

$id = "PRINT" + "18.7.10"
$chaine = "$id" + ";" + "(L1)Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt',value must be 1 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object NoWarningNoElevationOnInstall
 $traitement = $traitement.NoWarningNoElevationOnInstall
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


# (L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'

$id = "PRINT" + "18.7.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt',value must be 0 " + ";"
$exist = Test-Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" |Select-Object UpdatePromptSettings
 $traitement = $traitement.UpdatePromptSettings
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Check Notifications Seting
Write-Host "#########>Begin Notification Settings audit<#########" -ForegroundColor DarkGreen
# (L2) Ensure 'Turn off notifications network usage' is set to 'Enabled'

$id = "NOTI" + "18.8.1.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Turn off notifications network usage' is set to 'Enabled',value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" |Select-Object NoCloudApplicationNotification
 $traitement = $traitement.NoCloudApplicationNotification
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Check Network Connections
Write-Host "#########>Begin Audit Process Creation audit<#########" -ForegroundColor DarkGreen
#(L1) Ensure 'Include command line in process creation events' is set to 'Enabled'
$id = "APC" + "18.9.3.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Include command line in process creation events' is set to 'Enabled',value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" |Select-Object ProcessCreationIncludeCmdLine_Enabled
 $traitement = $traitement.ProcessCreationIncludeCmdLine_Enabled
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)






#Check Network Connections
Write-Host "#########>Begin Credential Delegation audit<#########" -ForegroundColor DarkGreen



#Encryption Oracle Remediation''

$id = "CD" + "18.9.4.1"
$chaine = "$indextest" + ";" + "(L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" |Select-Object AllowEncryptionOracle
 $traitement = $traitement.AllowEncryptionOracle
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Remote host allows delegation of non-exportable credentials

$id = "CD" + "$indextest"
$chaine = "$indextest" + ";" + "(L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" |Select-Object AllowProtectedCreds
 $traitement = $traitement.AllowProtectedCreds
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Check Device Guard
Write-Host "#########>Begin Device Guard audit<#########" -ForegroundColor DarkGreen

#Turn On Virtualization Based Security

$id = "DG" + "18.9.5.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security' is set to 'Enabled' (Scored), value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object EnableVirtualizationBasedSecurity
 $traitement = $traitement.EnableVirtualizationBasedSecurity
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection

$id = "DG" + "18.9.5.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot and DMA Protection', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object RequirePlatformSecurityFeatures
 $traitement = $traitement.RequirePlatformSecurityFeatures
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'

$id = "DG" + "18.9.5.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock' (Scored), value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object HypervisorEnforcedCodeIntegrity
 $traitement = $traitement.HypervisorEnforcedCodeIntegrity
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'

$id = "DG" + "18.9.5.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object HVCIMATRequired
 $traitement = $traitement.HVCIMATRequired
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock'

$id = "DG" + "18.9.5.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object LsaCfgFlags
 $traitement = $traitement.LsaCfgFlags
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'
$id = "DG" + "18.9.5.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object ConfigureSystemGuardLaunch
 $traitement = $traitement.ConfigureSystemGuardLaunch
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection'
$id = "DG" + "18.9.5.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection' is set to 'Enabled: Enabled in enforcement mode', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" |Select-Object ConfigureKernelShadowStacksLaunch
 $traitement = $traitement.ConfigureKernelShadowStacksLaunch
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Check Device Installation Restrictions
Write-Host "#########>Begin Device Installation Restrictions audit<#########" -ForegroundColor DarkGreen

#Prevent installation of devices that match any of these device IDs'

$id = "DIR" + "18.9.7.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceIDs
 $traitement = $traitement.DenyDeviceIDs
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device

$id = "DIR" + "18.9.7.1.2"
$chaine = "$id" + ";" + "Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" |Select-Object 1
 $traitement = $traitement.1
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed

$id = "DIR" + "18.9.7.1.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices that match any of these device IDs' is set to 'Enabled', value must be PCI\CC_0C0A " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceIDsRetroactive
 $traitement = $traitement.DenyDeviceIDsRetroactive
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)

#Prevent installation of devices using drivers that match these device setup classes'

$id = "DIR" + "18.9.7.1.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceClasses
 $traitement = $traitement.DenyDeviceClasses
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes

$id = "DIR" + "18.9.7.1.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup' is set to 'IEEE 1394 device setup classes, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
 $traitement = $traitement."{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
 $traitementtemp = "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
 $traitement = $traitement."{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}"
 $traitementtemp += "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{c06ff265-ae09-48f0-812c-16753d7cba83}"
 $traitement = $traitement."{c06ff265-ae09-48f0-812c-16753d7cba83}"
 $traitementtemp += "{c06ff265-ae09-48f0-812c-16753d7cba83}" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" |Select-Object "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
 $traitement = $traitement."{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
 $traitementtemp += "{6bdd1fc1-810f-11d0-bec7-08002be2092f}" + ":" + "$traitement" + "|"
 $traitement = $traitementtemp 
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.'

$id = "DIR" + "18.9.7.1.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed.' is set to 'True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" |Select-Object DenyDeviceClassesRetroactive
 $traitement = $traitement.DenyDeviceClassesRetroactive
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#(L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'

$id = "DIR" + "18.9.7.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled'' is set to 'True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" |Select-Object PreventDeviceMetadataFromNetwork
 $traitement = $traitement.PreventDeviceMetadataFromNetwork
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Check Early Launch Antimalware
Write-Host "#########>Begin Early Launch Antimalware audit<#########" -ForegroundColor DarkGreen

#Boot-Start Driver Initialization Policy

$id = "ELA" + "18.9.13.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical, value must be 3 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" |Select-Object driverLoadPolicy
 $traitement = $traitement.driverLoadPolicy
}
else {
 $traitement = "not configure"
}

$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Check Logging and tracing
Write-Host "#########>Begin Logging and tracing audit<#########" -ForegroundColor DarkGreen


#Configure registry policy processing: Do not apply during periodic background processing

$id = "LT" + "18.9.19.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" |Select-Object NoBackgroundPolicy
 $traitement = $traitement.NoBackgroundPolicy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure registry policy processing: Process even if the Group Policy objects have not changed

$id = "LT" + "18.9.19.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" |Select-Object NoGPOListChanges
 $traitement = $traitement.NoGPOListChanges
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)
#Continue experiences on this device

$id = "LT" + "18.9.19.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Continue experiences on this device' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableCdp
 $traitement = $traitement.EnableCdp
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier


Clean-Value($chaine)
Clean-Value($traitement)


#Turn off background refresh of Group Policy'

$id = "LT" + "18.9.19.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object DisableBkGndGroupPolicy
 $traitement = $traitement.DisableBkGndGroupPolicy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Internet Communication Management 
Write-Host "#########>Begin Internet Communication Management audit<#########" -ForegroundColor DarkGreen

#Turn off access to the Store 

$id = "ICS" + "18.9.20.1.1"
$chaine = "$id" + ";" + "(L1)Ensure Turn off access to the Store is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoUseStoreOpenWith
 $traitement = $traitement.NoUseStoreOpenWith
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Turn off downloading of print drivers over HTTP 

$id = "ICS" + "18.9.20.1.2"
$chaine = "$id" + ";" + "(L1)Ensure Turn off downloading of print drivers over HTTP, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" |Select-Object DisableWebPnPDownload
 $traitement = $traitement.DisableWebPnPDownload
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Turn off handwriting personalization data sharing

$id = "ICS" + "18.9.20.1.3"
$chaine = "$id" + ";" + "(L2)Ensure Turn off handwriting personalization data sharing is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" |Select-Object PreventHandwritingDataSharing
 $traitement = $traitement.PreventHandwritingDataSharing
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Turn off handwriting recognition error reporting

$id = "ICS" + "18.9.20.1.4"
$chaine = "$id" + ";" + "(L2)Ensure Turn off handwriting recognition error reporting is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" |Select-Object PreventHandwritingErrorReports
 $traitement = $traitement.PreventHandwritingErrorReports
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com
$id = "ICS" + "18.9.20.1.5"

$chaine = "$id" + ";" + "(L2)Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" |Select-Object ExitOnMSICW
 $traitement = $traitement.ExitOnMSICW
}
else {
 $traitement = "not configure"
}

Clean-Value($chaine)
Clean-Value($traitement)



#Turn off Internet download for Web publishing and online ordering wizards'
$id = "ICS" + "18.9.20.1.6"


$chaine = "$id" + ";" + "(L1)Ensure Turn off Internet download for Web publishing and online ordering wizards is set to 'Enabled' , value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoWebServices
 $traitement = $traitement.NoWebServices
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off printing over HTTP
$id = "ICS" + "18.9.20.1.7"

$chaine = "$id" + ";" + "(L2)Ensure Turn off printing over HTTP is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" |Select-Object DisableHTTPPrinting
 $traitement = $traitement.DisableHTTPPrinting
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off Registration if URL connection is referring to Microsoft.com
$id = "ICS" + "18.9.20.1.8"

$chaine = "$id" + ";" + "(L2)Ensure Turn off Registration if URL connection is referring to Microsoft.com is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control" |Select-Object NoRegistration
 $traitement = $traitement.NoRegistration
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)



#Turn off Search Companion content file updates
$id = "ICS" + "18.9.20.1.9"

$chaine = "$id" + ";" + "(L2)Ensure Turn off Search Companion content file updates is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" |Select-Object DisableContentFileUpdates
 $traitement = $traitement.DisableContentFileUpdates
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off the "Order Prints" picture task
$id = "ICS" + "18.9.20.1.10"

$chaine = "$id" + ";" + "(L2)Ensure Turn off the Order Prints picture task is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoOnlinePrintsWizard
 $traitement = $traitement.NoOnlinePrintsWizard
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off the "Publish to Web" task for files and folders'
$id = "ICS" + "18.9.20.1.11"

$chaine = "$id" + ";" + "(L2)Ensure 'Turn off the Publish to Web task for files and folders is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoPublishingWizard
 $traitement = $traitement.NoPublishingWizard
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off the Windows Messenger Customer Experience Improvement Program
$id = "ICS" + "18.9.20.1.12"

$chaine = "$id" + ";" + "(L2)Ensure Turn off the Windows Messenger Customer Experience Improvement Program is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" |Select-Object CEIP
 $traitement = $traitement.CEIP
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off Windows Customer Experience Improvement Program
$id = "ICS" + "18.9.20.1.13"

$chaine = "$id" + ";" + "(L2)Ensure Turn off Windows Customer Experience Improvement Program is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" |Select-Object CEIPEnable
 $traitement = $traitement.CEIPEnable
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#'Turn off Windows Error Reporting
$id = "ICS" + "18.9.20.1.14"

$chaine = "$id" + ";" + "(L2)Ensure Turn off Windows Error Reporting is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" |Select-Object Disabled
 $traitement = $traitement.Disabled
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Check Kerberos
Write-Host "#########>Begin Kerberos audit<#########" -ForegroundColor DarkGreen

#Support device authentication using certificate'
$id = "KER" + "18.9.23.1"

$chaine = "$id" + ";" + "(L2)Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" |Select-Object DevicePKInitBehavior
 $traitement = $traitement.DevicePKInitBehavior
 $traitementtemp = "DevicePKInitBehavior" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" |Select-Object DevicePKInitEnabled
 $traitement = $traitement.DevicePKInitEnabled
 $traitementtemp = "DevicePKInitEnabled" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)

#Kernel DMA Protection
Write-Host "#########>Begin Kernel DMA Protection audit<#########" -ForegroundColor DarkGreen


#Disallow copying of user input methods to the system account for sign-in'
$id = "KDP" + "18.9.24.1"

$chaine = "$id" + ";" + "(L1)Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" |Select-Object DeviceEnumerationPolicy
 $traitement = $traitement.DeviceEnumerationPolicy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Locale Services
Write-Host "#########>Begin Local Security Authority audit<#########" -ForegroundColor DarkGreen

#Allow Custom SSPs and APs to be loaded into LSASS
$id = "LSA" + "18.9.25.1"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowCustomSSPsAPs
 $traitement = $traitement.AllowCustomSSPsAPs
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configures LSASS to run as a protected process

$id = "LSA" + "18.9.25.2"

$chaine = "$id" + ";" + "(L1) Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |Select-Object RunAsPPL
 $traitement = $traitement.RunAsPPL
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Locale Services
Write-Host "#########>Begin Locale Services audit<#########" -ForegroundColor DarkGreen


#Disallow copying of user input methods to the system account for sign-in'
$id = "LS" + "18.9.26.1"

$chaine = "$id" + ";" + "(L2)Ensure Disallow copying of user input methods to the system account for sign-in is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International" |Select-Object BlockUserInputMethodsForSignIn
 $traitement = $traitement.BlockUserInputMethodsForSignIn
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)


#Logon
Write-Host "#########>Begin Logon audit<#########" -ForegroundColor DarkGreen


#Disallow copying of user input methods to the system account for sign-in'
$id = "LOGON" + "18.9.27.1"

$chaine = "$id" + ";" + "(L1)Ensure Block user from showing account details on sign-in is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object BlockUserFromShowingAccountDetailsOnSignin
 $traitement = $traitement.BlockUserFromShowingAccountDetailsOnSignin
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Do not display network selection UI
$id = "LOGON" + "18.9.27.2"

$chaine = "$id" + ";" + "(L1)Ensure Do not display network selection UI is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DontDisplayNetworkSelectionUI
 $traitement = $traitement.DontDisplayNetworkSelectionUI
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not enumerate connected users on domain-joined computers'
$id = "LOGON" + "18.9.27.3"

$chaine = "$id" + ";" + "Ensure Do not enumerate connected users on domain-joined computers is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DontEnumerateConnectedUsers
 $traitement = $traitement.DontEnumerateConnectedUsers
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Enumerate local users on domain-joined computers'
$id = "LOGON" + "18.9.27.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnumerateLocalUsers
 $traitement = $traitement.EnumerateLocalUsers
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Turn off app notifications on the lock screen'
$id = "LOGON" + "18.9.27.5"
$chaine = "$id" + ";" + "(L1)Ensure Turn off app notifications on the lock screen is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object DisableLockScreenAppNotifications
 $traitement = $traitement.DisableLockScreenAppNotifications
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off picture password sign-in'
$id = "LOGON" + "18.9.27.6"

$chaine = "$id" + ";" + "(L1)Ensure 'Turn off picture password sign-in' is set to 'Enabled', value must be1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object BlockDomainPicturePassword
 $traitement = $traitement.BlockDomainPicturePassword
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn on convenience PIN sign-in'
$id = "LOGON" + "18.9.27.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowDomainPINLogon
 $traitement = $traitement.AllowDomainPINLogon
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#OS Policies
Write-Host "#########>Begin OS Policies audit<#########" -ForegroundColor DarkGreen

#Allow Clipboard synchronization across devices
$id = "OP" + "18.9.30.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object AllowCrossDeviceClipboard
 $traitement = $traitement.AllowCrossDeviceClipboard
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow Clipboard synchronization across devices
$id = "OP" + "18.9.30.2"
$chaine = "$id" + ";" + "(L2) Ensure 'Allow upload of User Activities' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object UploadUserActivities
 $traitement = $traitement.UploadUserActivities
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Sleep Settings
Write-Host "#########>Begin Sleep Settings audit<#########" -ForegroundColor DarkGreen

#Allow network connectivity during connected-standby (on battery)'
$id = "SLEEP" + "18.9.32.6.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" |Select-Object DCSettingIndex
 $traitement = $traitement.DCSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Allow network connectivity during connected-standby (plugged in)'
$id = "SLEEP" + "18.9.32.6.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" |Select-Object ACSettingIndex
 $traitement = $traitement.ACSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Allow standby states (S1-S3) when sleeping (on battery)'
$id = "SLEEP" + "18.9.32.6.3"
$chaine = "$id" + ";" + "(L1) Ensure 'Allow standby states (S1-S3) when sleeping (on battery)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" |Select-Object DCSettingIndex
 $traitement = $traitement.DCSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow standby states (S1-S3) when sleeping (plugged in)'
$id = "SLEEP" + "18.9.32.6.4"
$chaine = "$id" + ";" + "(L1) Ensure 'Allow standby states (S1-S3) when sleeping (plugged in)' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" |Select-Object ACSettingIndex
 $traitement = $traitement.ACSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Require a password when a computer wakes (on battery)'
$id = "SLEEP" + "18.9.32.6.5"
$chaine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" |Select-Object DCSettingIndex
 $traitement = $traitement.DCSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Require a password when a computer wakes (plugged in)'
$id = "SLEEP" + "18.9.32.6.6"
$chaine = "$id" + ";" + "(L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" |Select-Object ACSettingIndex
 $traitement = $traitement.ACSettingIndex
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Remote Assistance
Write-Host "#########>Begin Remote Assistance audit<#########" -ForegroundColor DarkGreen

#Configure Offer Remote Assistance'
$id = "RA" + "18.9.34.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fAllowUnsolicited
 $traitement = $traitement.fAllowUnsolicited
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure Solicited Remote Assistance'
$id = "RA" + "18.9.34.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fAllowToGetHelp
 $traitement = $traitement.fAllowToGetHelp
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Remote Procedure Call
Write-Host "#########>Begin Remote Procedure Call audit<#########" -ForegroundColor DarkGreen

#Enable RPC Endpoint Mapper Client Authentication'
$id = "RPC" + "18.9.35.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" |Select-Object EnableAuthEpResolution
 $traitement = $traitement.EnableAuthEpResolution
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Restrict Unauthenticated RPC clients
$id = "RPC" + "18.9.35.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" |Select-Object RestrictRemoteClients
 $traitement = $traitement.RestrictRemoteClients
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Microsoft Support Diagnostic Tool
Write-Host "#########>Begin Microsoft Support Diagnostic Tool audit<#########" -ForegroundColor DarkGreen


#Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider
$id = "MSDT" + "18.9.46.5.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" |Select-Object DisableQueryRemoteServer
 $traitement = $traitement.DisableQueryRemoteServer
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Performance PerfTrack
Write-Host "#########>Begin Windows Performance PerfTrack audit<#########" -ForegroundColor DarkGreen


#Enable/Disable PerfTrack
$id = "WPP" + "18.9.46.11.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Enable/Disable PerfTrack' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" |Select-Object ScenarioExecutionEnabled
 $traitement = $traitement.ScenarioExecutionEnabled
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#User Profiles
Write-Host "#########>Begin User Profiles audit<#########" -ForegroundColor DarkGreen


#Turn off the advertising ID'
$id = "UP" + "18.9.48.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Turn off the advertising ID' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\policies\Microsoft\Windows\AdvertisingInfo" |Select-Object DisabledByGroupPolicy
 $traitement = $traitement.DisabledByGroupPolicy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Time Providers
Write-Host "#########>Begin Time Providers audit<#########" -ForegroundColor DarkGreen


#Enable Windows NTP Client
$id = "TP" + "18.9.50.1.1"
$chaine = "$id" + ";" + "(L2) Ensure 'Enable Windows NTP Client' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" |Select-Object Enabled
 $traitement = $traitement.Enabled
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Enable Windows NTP Server'
$id = "TP" + "18.9.50.1.2"
$chaine = "$id" + ";" + "(L2) Ensure 'Enable Windows NTP Server' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" |Select-Object Enabled
 $traitement = $traitement.Enabled
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#App Package Deployment
Write-Host "#########>Begin App Package Deployment audit<#########" -ForegroundColor DarkGreen


#Allow a Windows app to share application data between user
$id = "APD" + "18.10.3.1"
$chaine = "$id" + ";" + "(L2) Ensure Allow a Windows app to share application data between users, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" |Select-Object AllowSharedLocalAppData
 $traitement = $traitement.AllowSharedLocalAppData
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Prevent non-admin users from installing packaged Windows apps
$id = "APD" + "18.10.3.2"
$chaine = "$id" + ";" + "Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" |Select-Object BlockNonAdminUserInstall
 $traitement = $traitement.BlockNonAdminUserInstall
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#App Package Deployment
Write-Host "#########>Begin App Privacy audit<#########" -ForegroundColor DarkGreen

#Let Windows apps activate with voice while the system is locked'
$id = "APP" + "18.10.4.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" |Select-Object LetAppsActivateWithVoiceAboveLock
 $traitement = $traitement.LetAppsActivateWithVoiceAboveLock
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#App runtime
Write-Host "#########>Begin App runtime audit<#########" -ForegroundColor DarkGreen


#Allow Microsoft accounts to be optional'
$id = "AR" + "18.10.5.1"

$chaine = "$id" + ";" + "(L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object MSAOptional
 $traitement = $traitement.MSAOptional
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Block launching Windows Store apps with Windows Runtime API access from hosted content.'
$id = "AR" + "18.10.5.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Block launching Windows Store apps with Windows Runtime API access from hosted content.' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object BlockHostedAppAccessWinRT
 $traitement = $traitement.BlockHostedAppAccessWinRT
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#AutoPlay Policies
Write-Host "#########>Begin AutoPlay Policies audit<#########" -ForegroundColor DarkGreen


#Allow Microsoft accounts to be optional'
$id = "AP" + "18.10.7.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoAutoplayfornonVolume
 $traitement = $traitement.NoAutoplayfornonVolume
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Set the default behavior for AutoRun'
$id = "AP" + "18.10.7.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoAutorun
 $traitement = $traitement.NoAutorun
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off Autoplay'
$id = "AP" + "18.10.7.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'', value must be B5 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoDriveTypeAutoRun
 $traitement = $traitement.NoDriveTypeAutoRun
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Facial Features
Write-Host "#########>Begin Facial Features audit<#########" -ForegroundColor DarkGreen


#Use enhanced anti-spoofing when available'
$id = "FF" + "18.10.8.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Use enhanced anti-spoofing when available' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" |Select-Object EnhancedAntiSpoofing
 $traitement = $traitement.EnhancedAntiSpoofing
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#BitLocker Drive Encryption
Write-Host "#########>Begin BitLocker Drive Encryption audit<#########" -ForegroundColor DarkGreen


#Allow access to BitLocker-protected fixed data drives from earlier versions of Windows'
$id = "BDE" + "18.10.9.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow access to BitLocker-protected fixed data drives from earlier versions of Windows' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVDiscoveryVolumeType
 $traitement = $traitement.FDVDiscoveryVolumeType
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected fixed drives can be recovered'

$id = "BDE" + "18.10.9.1.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecovery
 $traitement = $traitement.FDVRecovery
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True'

$id = "BDE" + "18.10.9.1.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVManageDRA
 $traitement = $traitement.FDVManageDRA
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected fixed drives can be recovered: Recovery Password'
$id = "BDE" + "18.10.9.1.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Password' is set to 'Enabled: Allow 48-digit recovery password', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecoveryPassword
 $traitement = $traitement.FDVRecoveryPassword
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected fixed drives can be recovered: Recovery Key'
$id = "BDE" + "18.10.9.1.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Recovery Key' is set to 'Enabled: Allow 256-bit recovery key', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRecoveryKey
 $traitement = $traitement.FDVRecoveryKey
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard
$id = "BDE" + "18.10.9.1.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVHideRecoveryPage
 $traitement = $traitement.FDVHideRecoveryPage
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives'
$id = "BDE" + "18.10.9.1.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVActiveDirectoryBackup
 $traitement = $traitement.FDVActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS'
$id = "BDE" + "18.10.9.1.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVActiveDirectoryBackup
 $traitement = $traitement.FDVActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives
$id = "BDE" + "18.10.9.1.9"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVRequireActiveDirectoryBackup
 $traitement = $traitement.FDVRequireActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Configure use of hardware-based encryption for fixed data drives'
$id = "BDE" + "18.10.9.1.10"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of hardware-based encryption for fixed data drives' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVHardwareEncryption
 $traitement = $traitement.FDVHardwareEncryption
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configure use of passwords for fixed data drives'
$id = "BDE" + "18.10.9.1.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for fixed data drives' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVPassphrase
 $traitement = $traitement.FDVPassphrase
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Configure use of smart cards on fixed data drives
$id = "BDE" + "18.10.9.1.12"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on fixed data drives' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVAllowUserCert
 $traitement = $traitement.FDVAllowUserCert
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives
$id = "BDE" + "18.10.9.1.13"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object FDVEnforceUserCert
 $traitement = $traitement.FDVEnforceUserCert
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Operating System Drives
Write-Host "#########>Begin Operating System Drivesn audit<#########" -ForegroundColor DarkGreen


#Allow enhanced PINs for startup' is set to 'Enabled'
$id = "OSD" + "18.10.9.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow enhanced PINs for startup' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object UseEnhancedPin
 $traitement = $traitement.UseEnhancedPin
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Allow Secure Boot for integrity validation
$id = "OSD" + "18.10.9.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Secure Boot for integrity validation' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSAllowSecureBootForIntegrity
 $traitement = $traitement.OSAllowSecureBootForIntegrity
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected operating system drives can be recovered'
$id = "OSD" + "18.10.9.2.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecovery
 $traitement = $traitement.OSRecovery
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent
$id = "OSD" + "18.10.9.2.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSManageDRA
 $traitement = $traitement.OSManageDRA
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected operating system drives can be recovered: Recovery Password
$id = "OSD" + "18.10.9.2.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Password' is set to 'Enabled: Require 48-digit recovery password', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecoveryPassword
 $traitement = $traitement.OSRecoveryPassword
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected operating system drives can be recovered: Recovery Key
$id = "OSD" + "18.10.9.2.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRecoveryKey
 $traitement = $traitement.OSRecoveryKey
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard
$id = "OSD" + "18.10.9.2.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSHideRecoveryPage
 $traitement = $traitement.OSHideRecoveryPage
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drive
$id = "OSD" + "18.10.9.2.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSActiveDirectoryBackup
 $traitement = $traitement.OSActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected operating system drives can be recovered: Save BitLocker recovery information to AD DS for operating system drive
$id = "OSD" + "18.10.9.2.9"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Store recovery passwords and key packages'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSActiveDirectoryInfoToStore
 $traitement = $traitement.OSActiveDirectoryInfoToStore
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives
$id = "OSD" + "18.10.9.2.10"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for operating system drives', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSRequireActiveDirectoryBackup
 $traitement = $traitement.OSRequireActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure use of hardware-based encryption for operating system drives' is set to 'Disabled
$id = "OSD" + "18.10.9.2.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of hardware-based encryption for operating system drives' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSHardwareEncryption
 $traitement = $traitement.OSHardwareEncryption
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configure use of passwords for operating system drives' is set to 'Disabled'
$id = "OSD" + "18.10.9.2.12"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for operating system drives' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object OSPassphrase
 $traitement = $traitement.OSPassphrase
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Require additional authentication at startup'
$id = "OSD" + "18.10.9.2.13"
$chaine = "$id" + ";" + "Ensure 'Require additional authentication at startup' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object UseAdvancedStartup
 $traitement = $traitement.UseAdvancedStartup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Require additional authentication at startup: Allow BitLocker without a compatible TPM
$id = "OSD" + "18.10.9.2.14"
$chaine = "$id" + ";" + "Ensure 'Require additional authentication at startup: Allow BitLocker without a compatible TPM' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object EnableBDEWithNoTPM
 $traitement = $traitement.EnableBDEWithNoTPM
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Removable Data Drives
Write-Host "#########>Begin Removable Data Drives audit<#########" -ForegroundColor DarkGreen


#Allow access to BitLocker-protected removable data drives from earlier versions of Windows
$id = "RDD" + "18.10.9.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow access to BitLocker-protected removable data drives from earlier versions of Windows' is set to 'Disabled', value must be empty " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDiscoveryVolumeType
 $traitement = $traitement.RDVDiscoveryVolumeType
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected removable drives can be recovered'
$id = "RDD" + "18.10.9.3.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecovery
 $traitement = $traitement.RDVRecovery
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent'
$id = "RDD" + "18.10.9.3.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVManageDRA
 $traitement = $traitement.RDVManageDRA
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password'
$id = "RDD" + "18.10.9.3.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Password' is set to 'Enabled: Do not allow 48-digit recovery password', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecoveryPassword
 $traitement = $traitement.RDVRecoveryPassword
}
else {
 $traitement = "not configure"
}
Clean-Value($chaine)
Clean-Value($traitement)



#'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key'
$id = "RDD" + "18.10.9.3.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Recovery Key' is set to 'Enabled: Do not allow 256-bit recovery key', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRecoveryKey
 $traitement = $traitement.RDVRecoveryKey
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to
$id = "RDD" + "18.10.9.3.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVHideRecoveryPage
 $traitement = $traitement.RDVHideRecoveryPage
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives
$id = "RDD" + "18.10.9.3.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVActiveDirectoryBackup
 $traitement = $traitement.RDVActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:
$id = "RDD" + "18.10.9.3.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:' is set to 'Enabled: Backup recovery passwords and key packages', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVActiveDirectoryInfoToStore
 $traitement = $traitement.RDVActiveDirectoryInfoToStore
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives
$id = "RDD" + "18.10.9.3.9"
$chaine = "$id" + ";" + "(L1)Ensure 'Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for removable data drives' is set to 'Enabled: False', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVRequireActiveDirectoryBackup
 $traitement = $traitement.RDVRequireActiveDirectoryBackup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configure use of hardware-based encryption for removable data drives'
$id = "RDD" + "18.10.9.3.10"
$chaine = "$id" + ";" + "(L1)Ensure 'Ensure 'Configure use of hardware-based encryption for removable data drives' is set to 'Disabled'', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVHardwareEncryption
 $traitement = $traitement.RDVHardwareEncryption
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure use of passwords for removable data drives
$id = "RDD" + "18.10.9.3.11"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of passwords for removable data drives' is set to 'Disable, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVPassphrase
 $traitement = $traitement.RDVPassphrase
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure use of smart cards on removable data drives'
$id = "RDD" + "18.10.9.3.12"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on removable data drives' is set to 'Enabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVAllowUserCert
 $traitement = $traitement.RDVAllowUserCert
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives
$id = "RDD" + "18.10.9.3.13"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives' is set to 'Enabled: True', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVEnforceUserCert
 $traitement = $traitement.RDVEnforceUserCert
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Deny write access to removable drives not protected by BitLocker
$id = "RDD" + "18.10.9.3.14"
$chaine = "$id" + ";" + "(L1)Ensure 'Deny write access to removable drives not protected by BitLocker' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDenyWriteAccess
 $traitement = $traitement.RDVDenyWriteAccess
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization'
$id = "RDD" + "18.10.9.3.15"
$chaine = "$id" + ";" + "(L1)Ensure 'Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization' is set to 'Enabled: False', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object RDVDenyCrossOrg
 $traitement = $traitement.RDVDenyCrossOrg
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Disable new DMA devices when this computer is locked'
$id = "RDD" + "18.10.9.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Disable new DMA devices when this computer is locked' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\FVE" |Select-Object DisableExternalDMAUnderLock
 $traitement = $traitement.DisableExternalDMAUnderLock
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Camera
Write-Host "#########>Begin Camera audit<#########" -ForegroundColor DarkGreen


#Allow Use of Camera
$id = "CAM" + "18.10.10.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow Use of Camera' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Camera" |Select-Object AllowCamera
 $traitement = $traitement.AllowCamera
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Cloud Content
Write-Host "#########>Begin Cloud Content audit<#########" -ForegroundColor DarkGreen



#Turn off Microsoft consumer experiences'
$id = "CLOUD" + "18.10.12.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off cloud consumer account state content' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableConsumerAccountStateContent
 $traitement = $traitement.DisableConsumerAccountStateContent
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off cloud optimized content
$id = "CLOUD" + "18.10.12.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off cloud optimized content' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableCloudOptimizedContent
 $traitement = $traitement.DisableCloudOptimizedContent
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off Microsoft consumer experiences'
$id = "CLOUD" + "18.10.12.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableWindowsConsumerFeatures
 $traitement = $traitement.DisableWindowsConsumerFeatures
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Connect
Write-Host "#########>Begin Connect audit<#########" -ForegroundColor DarkGreen



#Require pin for pairing'
$id = "CONNECT" + "18.10.13.1"
$chaine = "$id" + ";" + "(L1)Ensure Require pin for pairing is set to Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" |Select-Object RequirePinForPairing
 $traitement = $traitement.RequirePinForPairing
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Credential User Interface
Write-Host "#########>Begin Credential User Interface audit<#########" -ForegroundColor DarkGreen



#Do not display the password reveal button
$id = "CUI" + "18.10.14.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not display the password reveal button' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" |Select-Object DisablePasswordReveal
 $traitement = $traitement.DisablePasswordReveal
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Enumerate administrator accounts on elevation'
$id = "CUI" + "18.10.14.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" |Select-Object EnumerateAdministrators
 $traitement = $traitement.EnumerateAdministrators
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Prevent the use of security questions for local accounts
$id = "CUI" + "18.10.14.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object NoLocalPasswordResetQuestions
 $traitement = $traitement.NoLocalPasswordResetQuestions
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Data Collection and Preview Builds
Write-Host "#########>Begin Data Collection and Preview Builds audit<#########" -ForegroundColor DarkGreen

#Allow Telemetry'
$id = "DCPB" + "18.10.15.1"

$chaine = "$id" + ";" + "(L1)Ensure'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'' , value must be 0(recommended) or 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object AllowTelemetry
 $traitement = $traitement.AllowTelemetry
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)



#Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'
$id = "DCPB" + "18.10.15.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DisableEnterpriseAuthProxy
 $traitement = $traitement.DisableEnterpriseAuthProxy
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Disable OneSettings Downloads'
$id = "DCPB" + "18.10.15.3"
$chaine = "$id" + ";" + "(L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DisableOneSettingsDownloads
 $traitement = $traitement.DisableOneSettingsDownloads
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Do not show feedback notifications'
$id = "DCPB" + "18.10.15.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not show feedback notifications' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object DoNotShowFeedbackNotifications
 $traitement = $traitement.DoNotShowFeedbackNotifications
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Enable OneSettings Auditing'
$id = "DCPB" + "18.10.15.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable OneSettings Auditing' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object EnableOneSettingsAuditing
 $traitement = $traitement.EnableOneSettingsAuditing
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Limit Diagnostic Log Collection
$id = "DCPB" + "18.10.15.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Limit Diagnostic Log Collection is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object LimitDiagnosticLogCollection
 $traitement = $traitement.LimitDiagnosticLogCollection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Limit Dump Collection'
$id = "DCPB" + "18.10.15.7"
$chaine = "$id" + ";" + "(L1)Ensure 'Limit Dump Collection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" |Select-Object LimitDumpCollection
 $traitement = $traitement.LimitDumpCollection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Limit Dump Collection'
$id = "DCPB" + "18.10.15.8"
$chaine = "$id" + ";" + "(L1)Ensure 'Toggle user control over Insider builds'is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" |Select-Object AllowBuildPreview
 $traitement = $traitement.AllowBuildPreview
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Delivery Optimization
Write-Host "#########>Begin Delivery Optimization audit<#########" -ForegroundColor DarkGreen

#Download Mode' is NOT set to 'Enabled: Internet
$id = "DO" + "18.10.16"
$chaine = "$id" + ";" + "Ensure 'Download Mode' is NOT set to 'Enabled: Internet' , value must be anything other than 3" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" |Select-Object DODownloadMode
 $traitement = $traitement.DODownloadMode
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Application
Write-Host "#########>Begin Desktop App Installer audit<#########" -ForegroundColor DarkGreen

#Enable App Installer
$id = "DAI" + "18.10.17.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable App Installer' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableAppInstaller
 $traitement = $traitement.EnableAppInstaller
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Enable App Installer Experimental Features
$id = "DAI" + "18.10.17.2"
$chaine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Experimental Features' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableExperimentalFeatures
 $traitement = $traitement.EnableExperimentalFeatures
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#'Enable App Installer Hash Override'
$id = "DAI" + "18.10.17.3"
$chaine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableHashOverride
 $traitement = $traitement.EnableHashOverride
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Enable App Installer ms-appinstaller protocol'
$id = "DAI" + "18.10.17.4"
$chaine = "$id" + ";" + "Ensure Ensure 'Enable App Installer Hash Override' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" |Select-Object EnableMSAppInstallerProtocol
 $traitement = $traitement.EnableMSAppInstallerProtocol
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Application
Write-Host "#########>Begin Application Log audit<#########" -ForegroundColor DarkGreen



#Application: Control Event Log behavior when the log file reaches its maximum size'
$id = "APP" + "18.10.26.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" |Select-Object Retention
 $traitement = $traitement.Retention
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Application: Specify the maximum log file size
$id = "APP" + "18.10.26.1.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" |Select-Object MaxSize
 $traitement = $traitement.MaxSize
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Security 
Write-Host "#########>Begin Security Log audit<#########" -ForegroundColor DarkGreen


#Security: Control Event Log behavior when the log file reaches its maximum size
$id = "SECL" + "18.10.26.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" |Select-Object Retention
 $traitement = $traitement.Retention
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Security: Specify the maximum log file size (KB)'
$id = "SECL" + "18.10.26.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater', value must be 196,608 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" |Select-Object MaxSize
 $traitement = $traitement.MaxSize
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Setup 
Write-Host "#########>Begin Setup Log audit<#########" -ForegroundColor DarkGreen



#Setup: Control Event Log behavior when the log file reaches its maximum size'
$id = "SETL" + "18.10.26.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" |Select-Object Retention
 $traitement = $traitement.Retention
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Setup: Specify the maximum log file size (KB)'
$id = "SETL" + "18.10.26.3.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" |Select-Object MaxSize
 $traitement = $traitement.MaxSize
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#System 
Write-Host "#########>Begin System Log audit<#########" -ForegroundColor DarkGreen



#System: Control Event Log behavior when the log file reaches its maximum size'
$id = "SYSL" + "18.10.26.4.1"

$chaine = "$id" + ";" + "(L1)Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" |Select-Object Retention
 $traitement = $traitement.Retention
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Setup: Specify the maximum log file size (KB)'
$id = "SYSL" + "18.10.26.4.2"
$chaine = "$id" + ";" + "(L1)Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater', value must be 32,768 or greater " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" |Select-Object MaxSize
 $traitement = $traitement.MaxSize
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#File Explorer
Write-Host "#########>Begin File Explorer audit<#########" -ForegroundColor DarkGreen


#Turn off Data Execution Prevention for Explorer'
$id = "FE" + "18.10.29.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoDataExecutionPrevention
 $traitement = $traitement.NoDataExecutionPrevention
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)

#Turn off files from Office.com in Quick access view'
$id = "FE" + "18.10.29.3"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off files from Office.com in Quick access view' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object DisableGraphRecentItems
 $traitement = $traitement.DisableGraphRecentItems
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Turn off heap termination on corruption'
$id = "FE" + "18.10.29.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off heap termination on corruption' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" |Select-Object NoHeapTerminationOnCorruption
 $traitement = $traitement.NoHeapTerminationOnCorruption
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off shell protocol protected mode'
$id = "FE" + "18.10.29.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off shell protocol protected mode' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object PreXPSP2ShellProtocolBehavior
 $traitement = $traitement.PreXPSP2ShellProtocolBehavior
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#HomeGroup
Write-Host "#########>Begin HomeGroup audit<#########" -ForegroundColor DarkGreen


#Prevent the computer from joining a homegroup
$id = "HOME" + "18.10.33.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" |Select-Object DisableHomeGroup
 $traitement = $traitement.DisableHomeGroup
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Windows Location Provider
Write-Host "#########>Begin Windows Location Provider audit<#########" -ForegroundColor DarkGreen



#Turn off location'
$id = "WLP" + "18.10.37.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off location' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" |Select-Object DisableLocation
 $traitement = $traitement.DisableLocation
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Messaging
Write-Host "#########>Begin Messaging audit<#########" -ForegroundColor DarkGreen


#Allow Message Service Cloud Sync'
$id = "MES" + "18.10.41.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" |Select-Object AllowMessageSync
 $traitement = $traitement.AllowMessageSync
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Microsoft account
Write-Host "#########>Begin Microsoft account audit<#########" -ForegroundColor DarkGreen


#Block all consumer Microsoft account user authentication
$id = "MA" + "18.10.42.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" |Select-Object DisableUserAuth
 $traitement = $traitement.DisableUserAuth
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Microsoft Defender Antivirus
Write-Host "#########>Begin Microsoft Defender Antivirus <#########" -ForegroundColor DarkGreen
#'Configure local setting override for reporting to Microsoft MAPS'
$id = "MDA" + "18.10.43.5.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" |Select-Object LocalSettingOverrideSpynetReporting
 $traitement = $traitement.LocalSettingOverrideSpynetReporting
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Join Microsoft MAPS'
$id = "MDA" + "18.10.43.5.2"
$chaine = "$id" + ";" + " (L2)Ensure 'Join Microsoft MAPS' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" |Select-Object SpynetReporting
 $traitement = $traitement.SpynetReporting
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure Attack Surface Reduction rules'
$id = "MDA" + "18.10.43.6.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" |Select-Object ExploitGuard_ASR_Rules
 $traitement = $traitement.ExploitGuard_ASR_Rules
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Configure Attack Surface Reduction rules'
$id = "MDA" + "18.10.43.6.1.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is 'configured', value must be 1 foreach key " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
 $traitement = $traitement."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
 $traitementtemp = "Block Office applications from injecting code into other processes" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "3b576869-a4ec-4529-8536-b80a7769e899"
 $traitement = $traitement."3b576869-a4ec-4529-8536-b80a7769e899"
 $traitementtemp += "Block Office applications from creating executable content" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
 $traitement = $traitement."d4f940ab-401b-4efc-aadc-ad5f3c50688a"
 $traitementtemp += "Block Office applications from creating child processes" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
 $traitement = $traitement."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
 $traitementtemp += "Block Win32 API calls from Office macro" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
 $traitement = $traitement."5beb7efe-fd9a-4556-801d-275e5ffc04cc"
 $traitementtemp += "Block execution of potentially obfuscated scripts" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "d3e037e1-3eb8-44c8-a917-57927947596d"
 $traitement = $traitement."d3e037e1-3eb8-44c8-a917-57927947596d"
 $traitementtemp += "Block JavaScript or VBScript from launching downloaded executable content" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" |Select-Object "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
 $traitement = $traitement."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
 $traitementtemp += "Block executable content from email client and webmail" + ":" + "$traitement" + "|"
 }
else {
 $traitement = "not configure"
}
$chaine += $traitementtemp
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Prevent users and apps from accessing dangerous websites'
$id = "MDA" + "18.10.43.6.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" |Select-Object EnableNetworkProtection
 $traitement = $traitement.EnableNetworkProtection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Enable file hash computation feature
$id = "MDA" + "18.10.43.6.3.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Enable file hash computation feature' is set to 'Enabled' value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" |Select-Object EnableFileHashComputation
 $traitement = $traitement.EnableFileHashComputation
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Scan all downloaded files and attachments
$id = "MDA" + "18.10.43.10.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled', value must be 1 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableIOAVProtection
 $traitement = $traitement.DisableIOAVProtection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Scan all downloaded files and attachments
$id = "MDA" + "18.10.43.10.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Turn off real-time protection' is set to 'Disabled' (Automated), value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableRealtimeMonitoring
 $traitement = $traitement.DisableRealtimeMonitoring
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Turn on behavior monitoring'
$id = "MDA" + "18.10.43.10.3"
$chaine = "$id" + ";" + "(L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled', value must be 0  or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableBehaviorMonitoring
 $traitement = $traitement.DisableBehaviorMonitoring
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn on script scanning
$id = "MDA" + "18.10.43.10.4"
$chaine = "$id" + ";" + "(L1) Ensure 'Turn on script scanning' is set to 'Enabled', value must be 0  or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" |Select-Object DisableScriptScanning
 $traitement = $traitement.DisableScriptScanning
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Configure Watson events'
$id = "MDA" + "18.10.43.12.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Configure Watson events' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" |Select-Object DisableGenericRePorts
 $traitement = $traitement.DisableGenericRePorts
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Scan removable drives'
$id = "MDA" + "18.10.43.13.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Scan removable drives' is set to 'Enabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" |Select-Object DisableRemovableDriveScanning
 $traitement = $traitement.DisableRemovableDriveScanning
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn on e-mail scanning'
$id = "MDA" + "18.10.43.13.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" |Select-Object DisableEmailScanning
 $traitement = $traitement.DisableEmailScanning
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure detection for potentially unwanted applications
$id = "MDA" + "18.10.43.16"
$chaine = "$id" + ";" + "(L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block', value must be 1 or disable if you have another EPP " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" |Select-Object PUAProtection
 $traitement = $traitement.PUAProtection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off Windows Defender AntiVirus'
$id = "MDA" + "18.10.43.17"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled', value must be 0 or disable if you have another EPP" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" |Select-Object DisableAntiSpyware
 $traitement = $traitement.DisableAntiSpyware
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Allow auditing events in Windows Defender Application Guard'
$id = "MDA" + "18.10.44.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow auditing events in Windows Defender Application Guard' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AuditApplicationGuard
 $traitement = $traitement.AuditApplicationGuard
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Allow camera and microphone access in Windows Defender Application Guard
$id = "MDA" + "18.10.44.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow camera and microphone access in Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowCameraMicrophoneRedirection
 $traitement = $traitement.AllowCameraMicrophoneRedirection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow data persistence for Windows Defender Application Guard
$id = "MDA" + "18.10.44.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow data persistence for Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowPersistence
 $traitement = $traitement.AllowPersistence
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow files to download and save to the host operating system from Windows Defender Application Guard'
$id = "MDA" + "18.10.44.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow files to download and save to the host operating system from Windows Defender Application Guard' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object SaveFilesToHost
 $traitement = $traitement.SaveFilesToHost
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Configure Windows Defender Application Guard clipboard settings: Clipboard behavior setting'
$id = "MDA" + "18.10.44.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Windows Defender Application Guard clipboard settings: Clipboard behavior setting' is set to 'Enabled: Enable clipboard operation from an isolated session to the host', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AppHVSIClipboardSettings
 $traitement = $traitement.AppHVSIClipboardSettings
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn on Windows Defender Application Guard in Enterprise Mode'
$id = "MDA" + "18.10.44.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn on Windows Defender Application Guard in Enterprise Mode' is set to 'Enabled', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI" |Select-Object AllowAppHVSI_ProviderSet
 $traitement = $traitement.AllowAppHVSI_ProviderSet
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows Game Recording and Broadcasting
Write-Host "#########>Begin News and interests audit<#########" -ForegroundColor DarkGreen

#Enable news and interests on the taskbar
$id = "NI" + "18.10.50.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Enable news and interests on the taskbar' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds:"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds:" |Select-Object EnableFeeds
 $traitement = $traitement.EnableFeeds
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#OneDrive
Write-Host "#########>Begin OneDrive audit<#########" -ForegroundColor DarkGreen



#Prevent the usage of OneDrive for file storage'
$id = "OD" + "18.10.50.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" |Select-Object DisableFileSyncNGSC
 $traitement = $traitement.DisableFileSyncNGSC
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier

Clean-Value($chaine)
Clean-Value($traitement)


#Push to Install 
Write-Host "#########>Begin Push To Install audit<#########" -ForegroundColor DarkGreen



#Turn off Push To Install service'

$id = "PTI" + "18.10.56.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off Push To Install service' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" |Select-Object DisablePushToInstall
 $traitement = $traitement.DisablePushToInstall
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Remote Desktop Connection Client
Write-Host "#########>Begin Remote Desktop Services audit<#########" -ForegroundColor DarkGreen

#Disable Cloud Clipboard integration for server-to-client data transfer

$id = "RDS" + "18.10.57.2.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Disable Cloud Clipboard integration for server-to-client data transfer' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DisableCloudClipboardIntegration
 $traitement = $traitement.DisableCloudClipboardIntegration
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Do not allow passwords to be saved'
$id = "RDS" + "18.10.57.2.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not allow passwords to be saved' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DisablePasswordSaving
 $traitement = $traitement.DisablePasswordSaving
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow users to connect remotely by using Remote Desktop Services
$id = "RDS" + "18.10.57.3.2.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow users to connect remotely by using Remote Desktop Services' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDenyTSConnections
 $traitement = $traitement.fDenyTSConnections
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow UI Automation redirection
$id = "RDS" + "18.10.57.3.3.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow UI Automation redirection' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object EnableUiaRedirection
 $traitement = $traitement.EnableUiaRedirection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not allow COM port redirection'
$id = "RDS" + "18.10.57.3.3.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Do not allow COM port redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableCcm
 $traitement = $traitement.fDisableCcm
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not allow drive redirection'
$id = "RDS" + "18.10.57.3.3.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not allow drive redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableCdm
 $traitement = $traitement.fDisableCdm
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not allow location redirection
$id = "RDS" + "18.10.57.3.3.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not allow location redirection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableLocationRedir
 $traitement = $traitement.fDisableLocationRedir
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not allow LPT port redirection'
$id = "RDS" + "18.10.57.3.3.5"
$chaine = "$id" + ";" + "(L2)Ensure 'Do not allow LPT port redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableLPT
 $traitement = $traitement.fDisableLPT
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Do not allow supported Plug and Play device redirection'
$id = "RDS" + "18.10.57.3.3.6"
$chaine = "$id" + ";" + "(L2)Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisablePNPRedir
 $traitement = $traitement.fDisablePNPRedir
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not allow WebAuthn redirection
$id = "RDS" + "18.10.57.3.3.7"
$chaine = "$id" + ";" + "(L2)Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fDisableWebAuthn
 $traitement = $traitement.fDisableWebAuthn
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Always prompt for password upon connection'
$id = "RDS" + "18.10.57.3.9.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Always prompt for password upon connection' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fPromptForPassword
 $traitement = $traitement.fPromptForPassword
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Require secure RPC communication'
$id = "RDS" + "18.10.57.3.9.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fEncryptRPCTraffic
 $traitement = $traitement.fEncryptRPCTraffic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Require secure RPC communication'
$id = "RDS" + "18.10.57.3.9.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Require secure RPC communication' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object fEncryptRPCTraffic
 $traitement = $traitement.fEncryptRPCTraffic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#'Require use of specific security layer for remote (RDP) connections
$id = "RDS" + "18.10.57.3.9.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL', value must be 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object SecurityLayer
 $traitement = $traitement.SecurityLayer
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#'Require user authentication for remote connections by using Network Level Authentication
$id = "RDS" + "18.10.57.3.9.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object UserAuthentication
 $traitement = $traitement.UserAuthentication
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Set client connection encryption level
$id = "RDS" + "18.10.57.3.9.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Set client connection encryption level' is set to 'Enabled: High Level', value must be 3 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MinEncryptionLevel
 $traitement = $traitement.MinEncryptionLevel
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Set time limit for active but idle Remote Desktop Services sessions'
$id = "RDS" + "18.10.57.3.10.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less', value must be 15 or less " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MaxIdleTime
 $traitement = $traitement.MaxIdleTime
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Set time limit for disconnected sessions'
$id = "RDS" + "18.10.57.3.10.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute', value must 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object MaxDisconnectionTime
 $traitement = $traitement.MaxDisconnectionTime
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Do not delete temp folders upon exit'
$id = "RDS" + "18.10.57.3.11.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not delete temp folders upon exit' is set to 'Disabled', value must 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" |Select-Object DeleteTempDirsOnExit
 $traitement = $traitement.DeleteTempDirsOnExit
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#RSS Feeds
Write-Host "#########>Begin RSS Feeds audit<#########" -ForegroundColor DarkGreen



#Prevent downloading of enclosures'

$id = "RSS" + "18.10.58.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent downloading of enclosures' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" |Select-Object DisableEnclosureDownload
 $traitement = $traitement.DisableEnclosureDownload
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#OCR
Write-Host "#########>Begin OCR audit<#########" -ForegroundColor DarkGreen



#Allow Cloud Search'

$id = "OCR" + "18.10.59.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCloudSearch
 $traitement = $traitement.AllowCloudSearch
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow Cortana'
$id = "OCR" + "18.10.59.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Cortana' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCortana
 $traitement = $traitement.AllowCortana
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow Cortana above lock screen'
$id = "OCR" + "18.10.59.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Cortana above lock screen' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowCortanaAboveLock
 $traitement = $traitement.AllowCortanaAboveLock
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow indexing of encrypted files'
$id = "OCR" + "18.10.59.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow indexing of encrypted files' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowIndexingEncryptedStoresOrItems
 $traitement = $traitement.AllowIndexingEncryptedStoresOrItems
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Ensure 'Allow search and Cortana to use location' is set to 'Disabled'
$id = "OCR" + "18.10.59.6"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow search and Cortana to use location' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object AllowSearchToUseLocation
 $traitement = $traitement.AllowSearchToUseLocation
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Allow search highlights'
$id = "OCR" + "18.10.59.7"
$chaine = "$id" + ";" + "(L2)'Ensure 'Allow search highlights' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" |Select-Object EnableDynamicContentInWSB
 $traitement = $traitement.EnableDynamicContentInWSB
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)





#Software Protection Platform
Write-Host "#########>Begin Software Protection Platform audit<#########" -ForegroundColor DarkGreen


#Turn off KMS Client Online AVS Validation'

$id = "SPP" + "18.10.63.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" |Select-Object NoGenTicket
 $traitement = $traitement.NoGenTicket
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Store
Write-Host "#########>Begin Store audit<#########" -ForegroundColor DarkGreen


#Disable all apps from Windows Store'

$id = "STORE" + "18.10.66.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Disable all apps from Windows Store' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object DisableStoreApps
 $traitement = $traitement.DisableStoreApps
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Only display the private store within the Microsoft Store
$id = "STORE" + "18.10.66.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object RequirePrivateStoreOnly
 $traitement = $traitement.RequirePrivateStoreOnly
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off Automatic Download and Install of updates'
$id = "STORE" + "18.10.66.3"
$chaine = "$id" + ";" + "(L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object AutoDownload
 $traitement = $traitement.AutoDownload
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Turn off the offer to update to the latest version of Windows'
$id = "STORE" + "18.10.66.4"
$chaine = "$id" + ";" + " (L1)Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled, value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object DisableOSUpgrade
 $traitement = $traitement.DisableOSUpgrade
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off the Store application'
$id = "STORE" + "18.10.66.5"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off the Store application' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" |Select-Object RemoveWindowsStore
 $traitement = $traitement.RemoveWindowsStore
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows
Write-Host "#########>Begin Widgets audit<#########" -ForegroundColor DarkGreen

#Allow widgets'
$id = "WID" + "18.10.72.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow widgets' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" |Select-Object AllowNewsAndInterests
 $traitement = $traitement.AllowNewsAndInterests
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Defender SmartScreen 
Write-Host "#########>Begin Windows Defender SmartScreen audit<#########" -ForegroundColor DarkGreen

#Notify Malicious'
$id = "WDS" + "18.10.72.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Notify Malicious' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyMalicious
 $traitement = $traitement.NotifyMalicious
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Notify Password Reuse
$id = "WDS" + "18.10.72.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Notify Password Reuse' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyPasswordReuse
 $traitement = $traitement.NotifyPasswordReuse
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Notify Unsafe App'
$id = "WDS" + "18.10.72.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Notify Unsafe App'' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object NotifyUnsafeApp
 $traitement = $traitement.NotifyUnsafeApp
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Service Enabled'
$id = "WDS" + "18.10.72.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Service Enabled' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" |Select-Object ServiceEnabled
 $traitement = $traitement.ServiceEnabled
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure Windows Defender SmartScreen'
$id = "WDS" + "18.10.76.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object EnableSmartScreen
 $traitement = $traitement.EnableSmartScreen
 $traitementtemp = "EnableSmartScreen" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" |Select-Object ShellSmartScreenLevel
 $traitement = $traitement.ShellSmartScreenLevel
 $traitementtemp += "ShellSmartScreenLevel" + ":" + "$traitement" + "|"

 
}
else {
 $traitementtemp = "not configure"
}
$chaine += $traitementtemp
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Microsoft Edge 
Write-Host "#########>Begin Microsoft Edge audit<#########" -ForegroundColor DarkGreen

#Configure Windows Defender SmartScreen 
$id = "ME" + "18.10.76.3.1"
$chaine = "$id" + ";" + "(L1)Ensure Configure Windows Defender SmartScreen is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" |Select-Object EnabledV9
 $traitement = $traitement.EnabledV9
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Prevent bypassing Windows Defender SmartScreen prompts for sites
$id = "ME" + "18.10.76.3.1"
$chaine = "$id" + ";" + "(L1)Ensure Prevent bypassing Windows Defender SmartScreen prompts for sites is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" |Select-Object PreventOverride
 $traitement = $traitement.PreventOverride
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows Game Recording and Broadcasting
Write-Host "#########>Begin Windows Game Recording and Broadcasting audit<#########" -ForegroundColor DarkGreen


#Enables or disables Windows Game Recording and Broadcasting'

$id = "WGRB" + "18.10.78.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" |Select-Object AllowGameDVR
 $traitement = $traitement.AllowGameDVR
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Hello for Business
Write-Host "#########>Begin Windows Hello for Business audit<#########" -ForegroundColor DarkGreen


#Enables or disables Windows Game Recording and Broadcasting'

$id = "WGRB" + "18.10.78.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable ESS with Supported Peripherals' is set to 'Enabled: 1', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics" |Select-Object EnableESSwithSupportedPeripherals
 $traitement = $traitement.EnableESSwithSupportedPeripherals
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Ink Workspace
Write-Host "#########>Begin Windows Ink Workspace audit<#########" -ForegroundColor DarkGreen


#Allow suggested apps in Windows Ink Workspace'

$id = "WIW" + "18.10.80.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled, value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" |Select-Object AllowSuggestedAppsInWindowsInkWorkspace
 $traitement = $traitement.AllowSuggestedAppsInWindowsInkWorkspace
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Ink Workspace'
$id = "WIW" + "18.10.80.2"
$chaine = "$id" + ";" + "(L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On', value must be 0 or 1 but not 2 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" |Select-Object AllowWindowsInkWorkspace
 $traitement = $traitement.AllowWindowsInkWorkspace
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Installer

Write-Host "#########>Begin Windows Installer audit<#########" -ForegroundColor DarkGreen

#Allow user control over installs'

$id = "WI" + "18.10.81.1"
$chaine = "$id" + ";" + "Ensure 'Allow user control over installs' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object EnableUserControl
 $traitement = $traitement.EnableUserControl
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Always install with elevated privileges'
$id = "WI" + "18.10.81.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object AlwaysInstallElevated
 $traitement = $traitement.AlwaysInstallElevated
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Prevent Internet Explorer security prompt for Windows Installer scripts'
$id = "WI" + "18.10.81.3"
$chaine = "$id" + ";" + "(L2)Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object SafeForScripting
 $traitement = $traitement.SafeForScripting
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows Logon Options

Write-Host "#########>Begin Windows Logon Options audit<#########" -ForegroundColor DarkGreen

#Enable MPR notifications for the system

$id = "WLO" + "18.10.82.1"
$chaine = "$id" + ";" + "(L1)Ensure ''Enable MPR notifications for the system' is set to 'Disabled', value must be 0 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object EnableMPR
 $traitement = $traitement.EnableMPR
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)




#Sign-in last interactive user automatically after a system-initiated restart'

$id = "WLO" + "18.10.82.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |Select-Object DisableAutomaticRestartSignOn
 $traitement = $traitement.DisableAutomaticRestartSignOn
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Windows PowerShell

Write-Host "#########>Begin Windows PowerShell audit<#########" -ForegroundColor DarkGreen

#Turn on PowerShell Script Block Logging'

$id = "WP" + "18.10.87.1"
$chaine = "$id" + ";" + "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" |Select-Object EnableScriptBlockLogging
 $traitement = $traitement.EnableScriptBlockLogging
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Turn on PowerShell Transcription'
$id = "WP" + "18.10.87.2"
$chaine = "$id" + ";" + "Ensure 'urn on PowerShell Transcription' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" |Select-Object EnableTranscripting
 $traitement = $traitement.EnableTranscripting
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
#Windows Remote Management



Write-Host "#########>Begin Windows Remote Management audit<#########" -ForegroundColor DarkGreen

#Allow Basic authentication'

$id = "WRR" + "18.10.89.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowBasic
 $traitement = $traitement.AllowBasic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow unencrypted traffic'
$id = "WRR" + "18.10.89.1.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowUnencryptedTraffic
 $traitement = $traitement.AllowUnencryptedTraffic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Disallow Digest authentication'
$id = "WRR" + "18.10.89.1.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Disallow Digest authentication' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" |Select-Object AllowDigest
 $traitement = $traitement.AllowDigest
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

Write-Host "#########>Begin WinRM Service audit<#########" -ForegroundColor DarkGreen
#Allow Basic authentication'

$id = "WRR" + "18.10.89.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow Basic authentication' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowBasic
 $traitement = $traitement.AllowBasic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow remote server management through WinRM'

$id = "WRR" + "18.10.89.2.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow remote server management through WinRM' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowAutoConfig
 $traitement = $traitement.AllowAutoConfig
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow unencrypted traffic'

$id = "WRR" + "18.10.89.2.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow unencrypted traffic' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object AllowUnencryptedTraffic
 $traitement = $traitement.AllowUnencryptedTraffic
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Disallow WinRM from storing RunAs credentials'
$id = "WRR" + "18.10.89.2.4"
$chaine = "$id" + ";" + "(L1)Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" |Select-Object DisableRunAs
 $traitement = $traitement.DisableRunAs
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows Remote Shell

Write-Host "#########>Begin Windows Remote Shell audit<#########" -ForegroundColor DarkGreen

#Allow Remote Shell Access'

$id = "WRS" + "18.10.90.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Allow Remote Shell Access' is set to 'Disabled, value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" |Select-Object AllowRemoteShellAccess
 $traitement = $traitement.AllowRemoteShellAccess
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Windows Sandbox

Write-Host "#########>Begin Windows Sandbox audit<#########" -ForegroundColor DarkGreen

#Allow clipboard sharing with Windows Sandbox

$id = "WS" + "18.10.90.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" |Select-Object AllowClipboardRedirection
 $traitement = $traitement.AllowClipboardRedirection
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Allow clipboard sharing with Windows Sandbox

$id = "WS" + "18.10.90.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" |Select-Object AllowNetworking
 $traitement = $traitement.AllowNetworking
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#App and browser protection

Write-Host "#########>Begin App and browser protection audit<#########" -ForegroundColor DarkGreen


#Prevent users from modifying settings
$id = "ABP" + "18.10.92.2.1"
$chaine = "$id" + ";" + "(L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled', value must be 1 " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" |Select-Object DisallowExploitProtectionOverride
 $traitement = $traitement.DisallowExploitProtectionOverride
 }
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Windows Update

Write-Host "#########>Begin Windows Update audit<#########" -ForegroundColor DarkGreen



#Configure Automatic Updates'

$id = "WU" + "18.10.93.2.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Automatic Updates' is set to 'Enabled', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" |Select-Object NoAutoUpdate
 $traitement = $traitement.NoAutoUpdate
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Configure Automatic Updates: Scheduled install day'

$id = "WU" + "18.10.93.2.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'', value must be 0" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" |Select-Object ScheduledInstallDay
 $traitement = $traitement.ScheduledInstallDay
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Remove access to “Pause updates” feature'
$id = "WU" + "18.10.93.2.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Remove access to “Pause updates” feature' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object SetDisablePauseUXAccess
 $traitement = $traitement.SetDisablePauseUXAccess
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Manage preview builds

$id = "WU" + "18.10.93.4.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds' value must be 0 foreach key" + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object ManagePreviewBuilds
 $traitement = $traitement.ManagePreviewBuilds
 $traitementtemp = "ManagePreviewBuilds" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object ManagePreviewBuildsPolicyValue
 $traitement = $traitement.ManagePreviewBuildsPolicyValue
 $traitementtemp += "ManagePreviewBuildsPolicyValue" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}
$chaine += $traitementtemp
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Select when Feature Updates are received'
$id = "WU" + "18.10.93.4.2"
$chaine = "$id" + ";" + "(L2)Ensure 'Select when Feature Updates are received' is set to 'Enabled: Current Branch for Business, 180 days' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferFeatureUpdates
 $traitement = $traitement.DeferFeatureUpdates
 $traitementtemp = "DeferFeatureUpdates" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferFeatureUpdatesPeriodInDays
 $traitement = $traitement.DeferFeatureUpdatesPeriodInDays
 $traitementtemp += "DeferFeatureUpdatesPeriodInDays" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object BranchReadinessLevel
 $traitement = $traitement.BranchReadinessLevel
 $traitementtemp += "BranchReadinessLevel" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}
$chaine += $traitementtemp
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



#Select when Quality Updates are received'
$id = "WU" + "18.10.93.4.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days''' " + ";"
$exist = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferQualityUpdates
 $traitement = $traitement.DeferQualityUpdates
 $traitementtemp = "DeferQualityUpdates" + ":" + "$traitement" + "|"
 $traitement = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Select-Object DeferQualityUpdatesPeriodInDays
 $traitement = $traitement.DeferQualityUpdatesPeriodInDays
 $traitementtemp += "DeferQualityUpdatesPeriodInDays" + ":" + "$traitement" + "|"
}
else {
 $traitementtemp = "not configure"
}
$chaine += $traitementtemp
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Personalization

Write-Host "#########>Begin Personalization audit<#########" -ForegroundColor DarkGreen

#Enable screen saver'

$id = "PERS" + "19.1.3.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Enable screen saver' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaveActive
 $traitement = $traitement.ScreenSaveActive
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Password protect the screen saver'
$id = "PERS" + "19.1.3.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Password protect the screen saver' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaverIsSecure
 $traitement = $traitement.ScreenSaverIsSecure
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Screen saver timeout'
$id = "PERS" + "19.1.3.3"
$chaine = "$id" + ";" + "(L1)Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0', value must be 900 or less but not 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" |Select-Object ScreenSaveTimeOut
 $traitement = $traitement.ScreenSaveTimeOut
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Notifications

Write-Host "#########>Begin Notifications audit<#########" -ForegroundColor DarkGreen

#Turn off toast notifications on the lock screen'
$id = "NOTIF" + "19.5.1.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled, value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" |Select-Object NoToastApplicationNotificationOnLockScreen
 $traitement = $traitement.NoToastApplicationNotificationOnLockScreen
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Internet Communication Management

Write-Host "#########>Begin Internet Communication Management audit<#########" -ForegroundColor DarkGreen

#Turn off Help Experience Improvement Program

$id = "ICC" + "19.6.6.1.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" |Select-Object NoImplicitFeedback
 $traitement = $traitement.NoImplicitFeedback
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Attachment Manager

Write-Host "#########>Begin Attachment Manager audit<#########" -ForegroundColor DarkGreen

#Do not preserve zone information in file attachments'

$id = "ATTM" + "19.7.4.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" |Select-Object SaveZoneInformation
 $traitement = $traitement.SaveZoneInformation
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Notify antivirus programs when opening attachments'

$id = "ATTM" + "19.7.4.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" |Select-Object ScanWithAntiVirus
 $traitement = $traitement.ScanWithAntiVirus
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Cloud Content

Write-Host "#########>Begin Cloud Content audit<#########" -ForegroundColor DarkGreen

#Configure Windows spotlight on Lock Screen'

$id = "CLOUDC" + "19.7.7.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Configure Windows spotlight on lock screen' is set to Disabled, value must be 0" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object ConfigureWindowsSpotlight
 $traitement = $traitement.ConfigureWindowsSpotlight
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Do not suggest third-party content in Windows spotlight'
$id = "CLOUDC" + "19.7.7.2"
$chaine = "$id" + ";" + "(L1)Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableThirdPartySuggestions
 $traitement = $traitement.DisableThirdPartySuggestions
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)


#Do not use diagnostic data for tailored experiences'
$id = "CLOUDC" + "19.7.7.3"
$chaine = "$id" + ";" + "(L2)Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableTailoredExperiencesWithDiagnosticData
 $traitement = $traitement.DisableTailoredExperiencesWithDiagnosticData
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off all Windows spotlight features'
$id = "CLOUDC" + "19.7.7.4"
$chaine = "$id" + ";" + "(L2)Ensure 'Turn off all Windows spotlight features' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableWindowsSpotlightFeatures
 $traitement = $traitement.DisableWindowsSpotlightFeatures
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Turn off Spotlight collection on Desktop
$id = "CLOUDC" + "19.7.7.5"
$chaine = "$id" + ";" + "(L1)Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" 
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" |Select-Object DisableSpotlightCollectionOnDesktop
 $traitement = $traitement.DisableSpotlightCollectionOnDesktop
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)





#Network Sharing

Write-Host "#########>Begin Network Sharing audit<#########" -ForegroundColor DarkGreen

#Prevent users from sharing files within their profile

$id = "NSHARE" + "19.7.25.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" |Select-Object NoInplaceSharing
 $traitement = $traitement.NoInplaceSharing
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)



# User Windows Installer

Write-Host "#########>Begin User Windows Installer audit<#########" -ForegroundColor DarkGreen

#Always install with elevated privileges'

$id = "UWI" + "19.7.40.1"
$chaine = "$id" + ";" + "(L1)Ensure 'Always install with elevated privileges' is set to 'Disabled', value must be 0" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" |Select-Object AlwaysInstallElevated
 $traitement = $traitement.AlwaysInstallElevated
}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)

#Playback

Write-Host "#########>Begin Playback audit<#########" -ForegroundColor DarkGreen

#Prevent Codec Download'

$id = "PLB" + "19.7.42.2.1"
$chaine = "$id" + ";" + "(L2)Ensure 'Prevent Codec Download' is set to 'Enabled', value must be 1" + ";"
$exist = Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer"
if ( $exist -eq $true) {
 $traitement = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" |Select-Object PreventCodecDownload
 $traitement = $traitement.PreventCodecDownload

}
else {
 $traitement = "not configure"
}
$chaine += $traitement
$chaine>> $nomfichier
Clean-Value($chaine)
Clean-Value($traitement)
Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen
Set-Location ..






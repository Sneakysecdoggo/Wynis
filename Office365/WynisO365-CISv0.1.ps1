#Requires -RunAsAdministrator
#Requires -Version 4.0
#Author:Sneakysecdoggo
#Be awesome send me cookie
#This script must be run with admin rights 
#Check Windows Security Best Practice CIS 
#https://github.com/Sneakysecdoggo/
#https://twitter.com/SneakyWafWaf
#Script Server Version
#MIT License

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
Write-Host "     OOOOOOOOO      333333333333333           66666666   555555555555555555  "-ForegroundColor Black
Write-Host "   OO:::::::::OO   3:::::::::::::::33        6::::::6    5::::::::::::::::5  "-ForegroundColor Black
Write-Host " OO:::::::::::::OO 3::::::33333::::::3      6::::::6     5::::::::::::::::5  "-ForegroundColor Black
Write-Host "O:::::::OOO:::::::O3333333     3:::::3     6::::::6      5:::::555555555555  "-ForegroundColor Black
Write-Host "O::::::O   O::::::O            3:::::3    6::::::6       5:::::5             "-ForegroundColor Black
Write-Host "O:::::O     O:::::O            3:::::3   6::::::6        5:::::5             "-ForegroundColor Black
Write-Host "O:::::O     O:::::O    33333333:::::3   6::::::6         5:::::5555555555    "-ForegroundColor Black
Write-Host "O:::::O     O:::::O    3:::::::::::3   6::::::::66666    5:::::::::::::::5   "-ForegroundColor Black
Write-Host "O:::::O     O:::::O    33333333:::::3 6::::::::::::::66  555555555555:::::5  "-ForegroundColor Black
Write-Host "O:::::O     O:::::O            3:::::36::::::66666:::::6             5:::::5 "-ForegroundColor Black
Write-Host "O:::::O     O:::::O            3:::::36:::::6     6:::::6            5:::::5 "-ForegroundColor Black
Write-Host "O::::::O   O::::::O            3:::::36:::::6     6:::::65555555     5:::::5 "-ForegroundColor Black
Write-Host "O:::::::OOO:::::::O3333333     3:::::36::::::66666::::::65::::::55555::::::5 "-ForegroundColor Black
Write-Host " OO:::::::::::::OO 3::::::33333::::::3 66:::::::::::::66  55:::::::::::::55  "-ForegroundColor Black
Write-Host "   OO:::::::::OO   3:::::::::::::::33    66:::::::::66      55:::::::::55    "-ForegroundColor Black
Write-Host "     OOOOOOOOO      333333333333333        666666666          555555555      "-ForegroundColor Black

Write-Host "#########>Install & Load Powershell Module for audit <#########" -ForegroundColor DarkGreen
#INSTALL & LOAD Powershell Module
#install -Name AzureAD
$MAAD =Get-InstalledModule -Name AzureAD
 if($MAAD -eq $null){
   $MAADI = Read-Host "It seem AzureAD module isnot installed, do you want to installed it [Y/N]"
   switch($MAADI.ToLower()) 
{     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name AzureAD} 
    default { "You entered No, the script may not work" } 
}
    
 }
Import-Module -Name AzureAD
Connect-AzureAD
#install -Name MsoOnlinge
$MMSO =Get-InstalledModule -Name MSOnline
 if($MMSO -eq $null){
   $MMSOI = Read-Host "It seem MSOnline module isnot installed, do you want to installed it [Y/N]"
   switch($MMSOI.ToLower()) 
        {     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name MSOnline} 
    default { "You entered No, the script may not work" } 
}
    
 }
 Import-Module -Name MSOnline
 Connect-MsolService

 #install -Name MicrosoftGraphSecurity 
 $MMGS =Get-InstalledModule -Name MicrosoftGraphSecurity 
 if( $MMGS -eq $null){
  $MMGSI = Read-Host "It seem MicrosoftGraphSecurity module isnot installed, do you want to installed it [Y/N]"
   switch( $MMGSI.ToLower()) 
        {     {($_ -eq "y") -or ($_ -eq "yes") -or ($_ -eq "o")-or ($_ -eq "oui") } {Install-Module -Name MicrosoftGraphSecurity} 
    default { "You entered No, the script may not work" } 
}
    
 }
 Import-Module  -Name MicrosoftGraphSecurity 
 $cert = New-SelfSignedCertificate -Subject "CN=MSGraph_ReportingAPI" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA25
 
#get the date
$Date = Get-Date -U %d%m%Y


$nomfichier = "audit" + $date + ".txt"

Write-Host "#########>Create Audit directory<#########" -ForegroundColor DarkGreen

$nomdossier = "Audit_CONF_O365" + $date


New-Item -ItemType Directory -Name $nomdossier

Set-Location $nomdossier




Write-Host "#########>Begin CIS audit<#########" -ForegroundColor Green
#Begin Account / Authentication audit
Write-Host "#########>Begin Account / Authentication audit<#########" -ForegroundColor DarkGreen


#Multifactor authentication for admin
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1)Ensure multifactor authentication is enabled for all users in administrative roles" + ";"
$allgroupadmin = Get-MsolRole |Where {$_.name -match "administrator" -or $_.name -match "administrateurs"}|Select Name, ObjectId
"Group;UserPrincipalName;StrongPasswordRequired;PasswordNeverExpires;LastPasswordChangeTimestamp">alladmins.csv
$nbadmins = 0
$nbMFAdmins =0

foreach ( $groupadmin in $allgroupadmin){
  $admins = Get-MsolRoleMember -RoleObjectId $groupadmin.ObjectId | Select  EmailAddress
  
  foreach ( $useradmin in $admins){
    $adminlist = Get-MsolUser | Where {$_.UserPrincipalName -eq $useradmin.EmailAddress} | Select  UserPrincipalName, StrongPasswordRequired , PasswordNeverExpires, LastPasswordChangeTimestamp
    
    $ligne= $null
    $ligne += $groupadmin | Select -ExpandProperty Name
    $ligne += ";"
    $ligne += $adminlist | Select -ExpandProperty UserPrincipalName
    $ligne += ";"
    $ligne += $adminlist | Select -ExpandProperty StrongPasswordRequired
    $ligne += ";"
    $ligne += $adminlist | Select -ExpandProperty PasswordNeverExpires
    $ligne += ";"
    $ligne += $adminlist | Select -ExpandProperty LastPasswordChangeTimestamp
    $ligne >>alladmins.csv
    
    $nbadmins +=1
    if($adminlist.StrongPasswordRequired -ne $null){
      $nbMFAdmins += 1
  }
  }
}
$traitement = "$nbMFAdmins / $nbadmins | Details list in alladmins.csv "

$chaine += $traitement

$chaine>> $nomfichier
#Multifactor authentication for all user in role
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L2) Ensure multifactor authentication is enabled for all users in all roles" + ";"
$allroleuser = Get-MsolRole |Select Name, ObjectId
"Group;UserPrincipalName;StrongPasswordRequired;PasswordNeverExpires;LastPasswordChangeTimestamp">alluserrole.csv
$nbadmins = 0
$nbMFAdmins =0

foreach ( $groupuser in $allroleuser){
  $users = Get-MsolRoleMember -RoleObjectId $groupuser.ObjectId | Select  EmailAddress
  
  foreach ( $user in $users){
    $userlist = Get-MsolUser | Where {$_.UserPrincipalName -eq $user.EmailAddress} | Select  UserPrincipalName, StrongPasswordRequired , PasswordNeverExpires, LastPasswordChangeTimestamp
    
    $ligne= $null
    $ligne += $groupuser | Select -ExpandProperty Name
    $ligne += ";"
    $ligne += $userlist | Select -ExpandProperty UserPrincipalName
    $ligne += ";"
    $ligne += $userlist | Select -ExpandProperty StrongPasswordRequired
    $ligne += ";"
    $ligne += $userlist | Select -ExpandProperty PasswordNeverExpires
    $ligne += ";"
    $ligne += $userlist | Select -ExpandProperty LastPasswordChangeTimestamp
    $ligne >>alluserrole.csv
    
    $nbuser +=1
    if($userlist.StrongPasswordRequired -ne $null){
      $nbMFAuser += 1
  }
  }
}
$traitement = "$nbMFAuser / $nbuser | Details list in alluserrole.csv"

$chaine += $traitement

$chaine>> $nomfichier

#Ensure that between two and four global admins are designated
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that between two and four global admins are designated" + ";"
$GlobalAdminsGroup = Get-MsolRole |Where {$_.name -match "Company Administrator" -or $_.name -match "Administrateurs global"}
$GlobalAdmin = Get-MsolRoleMember -RoleObjectId $GlobalAdminsGroup.objectid
$GlobalAdmin | Export-Csv -NoTypeInformation ListGlobalAdmin.csv
$nombreGlobalAdmin = $GlobalAdmin | Measure-Object
$nombreGlobalAdmin = $nombreGlobalAdmin.count

$traitement = "$nombreGlobalAdmin"

$chaine += $traitement

$chaine>> $nomfichier

#Ensure self-service password reset is enabled
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure self-service password reset is enabled, But if disabled less risk" + ";"
Write-Host "Work-in progess, this Check require an API KEY, so please check https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
$traitement = "What is the value Disabled/Limited/ ALL ?"

$chaine += $traitement

$chaine>> $nomfichier

#Ensure that password protection is enabled for Active Directory
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that password protection is enabled for Active Directory" + ";"
Write-Host "Work-in progess, this Check require an API KEY, so please check https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/UsersManagementMenuBlade/PasswordReset"
$traitement = Read-Host "What is the value Disabled/Limited/ ALL ?"


$chaine += $traitement

$chaine>> $nomfichier

#Enable Conditional Access policies to block legacy authentication
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1)Enable Conditional Access policies to block legacy authentication (Automated)" + ";"


$AllPolicies = Get-AzureADMSConditionalAccessPolicy

foreach ($Policy in $AllPolicies) {
    Write-Host "Export $($Policy.DisplayName)"
    $PolicyJSON = $Policy | ConvertTo-Json -Depth 6
    $PolicyJSON | Out-File "./Accesspolicy/$($Policy.Id).json"
}
$traitement = "Check the Accesspolicy directory"
$chaine += $traitement

$chaine>> $nomfichier

#Ensure that password hash sync is enabled for resiliency and leaked credential detection
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E3 : (L1) Ensure that password hash sync is enabled for resiliency and leaked credential detection, Mode should be Managed and not federated " + ";"


$traitement =  Get-MsolDomain | Select Authentication

$traitement = $traitement.Authentication

$chaine += $traitement

$chaine>> $nomfichier

#Enabled Identity Protection to identify anomalous logon behavior
$indextest += 1
$id = "AA" + "$indextest"
$chaine = "$id" + ";" + "E5 (L1) Enabled Identity Protection to identify anomalous logon behavior " + ";"


$traitement =  Get-MsolDomain | Select Authentication

$traitement = $traitement.Authentication

$chaine += $traitement

$chaine>> $nomfichier


Write-Host "#########>END Audit<#########" -ForegroundColor DarkGreen
Set-Location ..






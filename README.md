# Wynis
Just a powershell scripts for auditing security with CIS BEST Practices Windows 10 and Window Server 2016
You just need to run the script, it will create a directory named : AUDIT_CONF_%DATE%
![W1](../master/Exemples/W1-ScriptOverView.png)





The directory output will contain the files belows:

![W2](../master/Exemples/W2-FilesList.png)


-Antivirus-%COMPUTERNAME% : List installed Antivirus software

![W3](../master/Exemples/W3-Antivirus.jpg)

-APPDATA%COMPUTERNAME% : List all executable file in APPDATA directory
![W4](../master/Exemples/W3-Appdataa.jpg)


-Audit%DATE%: list the result of all CIS tests

![W4](../master/Exemples/W4-OutPutExemple.jpg)

-auditpolicy-%COMPUTERNAME% : audit policy configured

![W5](../master/Exemples/W5-AuditConfiguration.jpg)

-firewall-rules-%COMPUTERNAME% : List all local windows firewall rules

![W6](../master/Exemples/W6-FirewallRules.jpg)

-gpo-%COMPUTERNAME% : Gpresult for applied GPO

-Installed-Software-%COMPUTERNAME% : List installed software

![W6](../master/Exemples/W6-InstalledSoftware.jpg)

-Listen-port-%COMPUTERNAME% : netstat with associate executable

-localuser-%COMPUTERNAME% : list all local users

-OptionnalFeature-%COMPUTERNAME% :List all enabled optional feature

![W7](../master/Exemples/W7-InstalledOptionnalFeature.jpg)

-Scheduled-task-%COMPUTERNAME% : list all scheduled task

![W8](../master/Exemples/W8-SchedulTaks.jpg)
-Service-%COMPUTERNAME% : list all service

![W9](../master/Exemples/W9-ListService.jpg)

-Share-%COMPUTERNAME% : list all share

![W10](../master/Exemples/W10-ListService.jpg)

-StartUp-%COMPUTERNAME% : check registry to identify start-up executable

-System-%COMPUTERNAME%  : systeminfo

-SystemUpdate : Check Wmi Quickfix to identify installed update


Work In Progress

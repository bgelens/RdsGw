# RdsGw
Simple PowerShell module to configure RDS Gateway servers by wrapping over WMI classes
````powershell
#Create RD CAP
New-RdsGwCap -Name 'RD CAP' -UserGroupNames "$env:COMPUTERNAME\RDS Gateway Users"

#Create RD RAP
New-RdsGwCap -Name 'RD RAP' -UserGroupNames "$env:COMPUTERNAME\RDS Gateway Users"

#Create and assign self signed certificate
New-RdsGwSelfSignedCertificate -SubjectName $env:COMPUTERNAME

#Assign existing certificate
Get-Item Cert:\LocalMachine\My\E477984BD2098BD46A84A7592F1251A53DCC4758 | Set-RdsGwCertificate

#Enable RDGW Services
Enable-RdsGwServer

#Get RDGW Config
Get-RdsGwServerConfiguration
```
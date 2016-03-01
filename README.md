# RdsGw
Simple PowerShell module to configure RDS Gateway servers by wrapping over WMI classes
````powershell
#Create RD CAP
New-RdsGwCap -Name 'RD CAP' -UserGroupNames "$env:COMPUTERNAME\RDS Gateway Users"

#Create RD RAP
New-RdsGwRap -Name 'RD RAP' -UserGroupNames "$env:COMPUTERNAME\RDS Gateway Users"

#Create and assign self signed certificate
New-RdsGwSelfSignedCertificate -SubjectName $env:COMPUTERNAME

#Assign existing certificate
Get-Item Cert:\LocalMachine\My\E477984BD2098BD46A84A7592F1251A53DCC4758 | Set-RdsGwCertificate

#Enable RDGW Services
Enable-RdsGwServer

#Get RDGW Config
Get-RdsGwServerConfiguration

#CAP and RAP management
Get-RdsGwCap
Get-RdsGwCap -Name 'RD CAP' | Disable-RdsGwCap
Get-RdsGwCap -Name 'RD CAP' | Enable-RdsGwCap
Get-RdsGwCap -Name 'RD CAP' | Remove-RdsGwCap

Get-RdsGwRap
Get-RdsGwRap -Name 'RD RAP' | Disable-RdsGwRap
Get-RdsGwRap -Name 'RD RAP' | Enable-RdsGwRap
Get-RdsGwRap -Name 'RD RAP' | Remove-RdsGwRap
```
function New-RdsGwCap {
    param (
        [Parameter(Mandatory)]
        [String] $Name,
        
        [bool] $Enable = $true,
        
        [bool] $Password = $true,
        
        [bool] $Smartcard = $false,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $UserGroupNames,
        
        [uint32] $SessionTimeout = 0
    )

    $CapArgs = @{
        AllowOnlySDRServers = $false
        ClipboardDisabled = $false
        ComputerGroupNames = [string]::Empty
        CookieAuthentication = $true
        DeviceRedirectionType = [uint32]0
        DiskDrivesDisabled = $false
        Enabled = $Enable
        IdleTimeout = [uint32]0
        Name = $Name
        Password = $Password
        PlugAndPlayDevicesDisabled = $false
        PrintersDisabled = $false
        SecureId = $false
        SerialPortsDisabled = $false
        SessionTimeout = $SessionTimeout
        SessionTimeoutAction = [uint32]0
        Smartcard = $Smartcard
        UserGroupNames = $UserGroupNames   
    }
    try {
        $Invoke = Invoke-CimMethod -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayConnectionAuthorizationPolicy -MethodName Create -Arguments $CapArgs
        if ($Invoke.ReturnValue -ne 0) {
            throw ('CAP Policy was not created succesfully. Returnvalue: {0}' -f $Invoke.ReturnValue)
        } else {
            Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayConnectionAuthorizationPolicy -Filter ('Name = "{0}"' -f $Name)
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function New-RdsGwRap {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Name,
        
        [String] $Description = [String]::Empty,
        
        [bool] $Enabled = $true,
        
        [ValidateSet('RG','CG','ALL')]
        [string] $ResourceGroupType = 'ALL',
        
        [string] $ResourceGroupName = [string]::Empty,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UserGroupNames,
        
        [ValidateSet('3389','*')]
        [string] $PortNumbers = '3389'
    )
    
    $RapArgs = @{
        Name = $Name
        Description = $Description
        Enabled = $Enabled
        ResourceGroupType = $ResourceGroupType
        ResourceGroupName = $ResourceGroupName
        UserGroupNames = $UserGroupNames
        ProtocolNames = 'RDP'
        PortNumbers = $PortNumbers
    }
    try {
        $Invoke = Invoke-CimMethod -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayResourceAuthorizationPolicy -MethodName Create -Arguments $RapArgs
        if ($Invoke.ReturnValue -ne 0) {
            throw ('RAP Policy was not created succesfully. Returnvalue: {0}' -f $Invoke.ReturnValue)
        } else {
            Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayResourceAuthorizationPolicy -Filter ('Name = "{0}"' -f $Name)
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function New-RdsGwSelfSignedCertificate {
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $SubjectName
    )
    try {
        $Invoke = Invoke-CimMethod -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServer -MethodName CreateSelfSignedCertificate -Arguments @{SubjectName = $SubjectName}
        if ($Invoke.ReturnValue -ne 0) {
            throw ('Failed Certificate creation. Returnvalue: {0}' -f $Invoke.ReturnValue)
        }
        $Invoke | Set-RdsGwCertificate
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Set-RdsGwCertificate {
    [cmdletbinding(DefaultParameterSetName='Thumbprint')]
    param (
        [Parameter(Mandatory, ParameterSetName='CertHash', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [byte[]]$CertHash,
        
        [Parameter(Mandatory, ParameterSetName='Thumbprint', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $Thumbprint
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Thumbprint') {
            if ($Cert = Get-Item -Path  Cert:\LocalMachine\My\$Thumbprint -ErrorAction SilentlyContinue) {
                $CertHash = $Cert.GetCertHash()
            } else {
                throw ('Certificate matching thumbprint {0} was not found' -f $Thumbprint)
            }
        }
        
        #remove current SSL configuration if exists and restart
        if (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo\0.0.0.0:443 -Name SslCertHash -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\SslBindingInfo\0.0.0.0:443 -Name SslCertHash
            Restart-Service -Name TSGateway -Force
        }
        
        $SSLConfigure = Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServerSettings | 
            Invoke-CimMethod -MethodName SetCertificate -Arguments @{CertHash = $CertHash}
        if ($SSLConfigure.ReturnValue -ne 0) {
            throw ('Failed assigning generated Certificate. Returnvalue: {0}' -f $SSLConfigure.ReturnValue)
        }
        $SSLACLConfigure = Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServerSettings | 
            Invoke-CimMethod -MethodName SetCertificateACL -Arguments @{CertHash = $CertHash}
        if ($SSLACLConfigure.ReturnValue -ne 0) {
            throw ('Failed assigning ACL to generated Certificate. Returnvalue: {0}' -f $SSLACLConfigure.ReturnValue)
        }
        $SSLContextConfigure = Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServerSettings | 
            Invoke-CimMethod -MethodName RefreshCertContext -Arguments @{CertHash = $CertHash}
        if ($SSLContextConfigure.ReturnValue -ne 0) {
            throw ('Failed refreshing context for generated Certificate. Returnvalue: {0}' -f $SSLContextConfigure.ReturnValue)
        }
    }
}

function Enable-RdsGwServer {
    $Configure = Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServerSettings |  Invoke-CimMethod  -MethodName Configure
    if ($Configure.ReturnValue -ne 0) {
        throw ('Failed configuring Rds GW. Returnvalue: {0}' -f $Configure.ReturnValue)
    }
}

function Get-RdsGwServerConfiguration {
    Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayServerSettings
}
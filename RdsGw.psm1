function New-RdsGwCap {
    param (
        [Parameter(Mandatory)]
        [String] $Name,
        
        [bool] $Enable = $true,
        
        [bool] $PasswordAuthentication = $true,
        
        [bool] $SmartcardAuthentication = $false,
        
        [switch] $DiskDrivesDisabled,
        
        [switch] $PlugAndPlayDevicesDisabled,

        [switch] $PrintersDisabled,

        [switch] $SerialPortsDisabled,

        [switch] $ClipboardDisabled,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $UserGroupNames,
        
        [uint32] $SessionTimeout = 0
    )

    #Somehow, only when all options are set to false AND DeviceRedirectionType is set to 2, the AllowOnlySDRServers setting is ingored and set to $true, so correct this behavior
    if ((!($DiskDrivesDisabled)) -and (!($PlugAndPlayDevicesDisabled)) -and (!($PrintersDisabled)) -and (!($SerialPortsDisabled)) -and (!($ClipboardDisabled))) {
        $DeviceRedirectionType = [uint32]0
    } else {
        $DeviceRedirectionType = [uint32]2
    }

    $CapArgs = @{
        AllowOnlySDRServers = $false
        ClipboardDisabled = $ClipboardDisabled
        ComputerGroupNames = [string]::Empty
        CookieAuthentication = $true
        DeviceRedirectionType = $DeviceRedirectionType
        <#
        Specifies which devices will be redirected.
        0 All devices will be redirected.
        1 No devices will be redirected.
        2 Specified devices will not be redirected. The DiskDrivesDisabled, PrintersDisabled, SerialPortsDisabled, ClipboardDisabled, and PlugAndPlayDevicesDisabled properties control which devices will not be redirected.
        #>
        DiskDrivesDisabled  = $DiskDrivesDisabled
        Enabled = $Enable
        #HasNapAttributes = $false
        IdleTimeout = [uint32]0
        Name = $Name
        #Order                       : 1
        Password = $PasswordAuthentication
        PlugAndPlayDevicesDisabled = $PlugAndPlayDevicesDisabled
        PrintersDisabled = $PrintersDisabled
        SecureId = $false
        SerialPortsDisabled = $SerialPortsDisabled
        SessionTimeout  = $SessionTimeout
        SessionTimeoutAction = [uint32]0
        Smartcard = $SmartcardAuthentication
        UserGroupNames = $UserGroupNames
    }


    try {
        $Invoke = Invoke-CimMethod -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayConnectionAuthorizationPolicy -MethodName Create -Arguments $CapArgs
        if ($Invoke.ReturnValue -ne 0) {
            throw ('Failed creating CAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
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
            throw ('Failed creating RAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
        } else {
            Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGatewayResourceAuthorizationPolicy -Filter ('Name = "{0}"' -f $Name)
        }
    } catch {
        Write-Error -ErrorRecord $_
    }
}

function Get-RdsGwCap {
    [cmdletbinding(DefaultParameterSetName='list')]
    param (
        [Parameter(Mandatory, ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )
    $QueryParams = @{
        Namespace = 'root/CIMV2/TerminalServices'
        ClassName = 'Win32_TSGatewayConnectionAuthorizationPolicy'
    }
    if ($PSCmdlet.ParameterSetName -eq 'Named') {
        $QueryParams.Add('Filter',('Name = "{0}"' -f $Name))
    }
    Get-CimInstance @QueryParams
}

function Get-RdsGwRap {
    [cmdletbinding(DefaultParameterSetName='list')]
    param (
        [Parameter(Mandatory, ParameterSetName='Named')]
        [ValidateNotNullOrEmpty()]
        [string] $Name
    )
    $QueryParams = @{
        Namespace = 'root/CIMV2/TerminalServices'
        ClassName = 'Win32_TSGatewayResourceAuthorizationPolicy'
    }
    if ($PSCmdlet.ParameterSetName -eq 'Named') {
        $QueryParams.Add('Filter',('Name = "{0}"' -f $Name))
    }
    Get-CimInstance @QueryParams
}

function Remove-RdsGwRap {
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwRap
    )
    if ($PSCmdlet.ShouldProcess($RdsGwRap)) {
        $Invoke = $RdsGwRap | Invoke-CimMethod -MethodName Delete
        if ($Invoke.ReturnValue -ne 0) {
            throw ('Failed removing CAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
        }
    }
}

function Remove-RdsGwCap {
    [cmdletbinding(SupportsShouldProcess, ConfirmImpact='High')]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ciminstance] $RdsGwCap
    )
    if ($PSCmdlet.ShouldProcess($RdsGwCap)) {
        $Invoke = $RdsGwCap | Invoke-CimMethod -MethodName Delete
        if ($Invoke.ReturnValue -ne 0) {
            throw ('Failed removing CAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
        }
    }
}

function Enable-RdsGwCap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwCap
    )
    $Invoke = $RdsGwCap | SetRdsGwCap -Enable $true
    if ($Invoke.ReturnValue -ne 0) {
        throw ('Failed enabling CAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
    }
}

function Disable-RdsGwCap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwCap
    )
    $Invoke = $RdsGwCap | SetRdsGwCap -Enable $false
    if ($Invoke.ReturnValue -ne 0) {
        throw ('Failed disabling CAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
    }
}

function SetRdsGwCap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwCap,
        
        [bool] $Enable
    )
    $RdsGwCap | Invoke-CimMethod -MethodName SetEnabled -Arguments @{Enabled = $Enable}
}

function Enable-RdsGwRap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwRap
    )
    $Invoke = $RdsGwRap | SetRdsGwRap -Enable $true
    if ($Invoke.ReturnValue -ne 0) {
        throw ('Failed enabling RAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
    }
}

function Disable-RdsGwRap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwRap
    )
    $Invoke = $RdsGwRap | SetRdsGwRap -Enable $false
    if ($Invoke.ReturnValue -ne 0) {
        throw ('Failed disabling RAP Policy. Returnvalue: {0}' -f $Invoke.ReturnValue)
    }
}

function SetRdsGwRap {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        $RdsGwRap,
        
        [bool] $Enable
    )
    $RdsGwRap | Invoke-CimMethod -MethodName SetEnabled -Arguments @{Enabled = $Enable}
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

Export-ModuleMember -Function *-RdsGw*

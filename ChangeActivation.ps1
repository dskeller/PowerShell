<#
  ChangeActivation.ps1 (c) 2021 dskeller
#>
<# 
  .SYNOPSIS
  Helper script to change kms to mak activation and vice versa for Windows 10 and Office 2016.

  .DESCRIPTION
  Activates Windows 10 and Office 2016 with encrypted license file(s).
  It is not possible to check if provided key matches Windows or Office version or if Key is KMS or MAK.

  .PARAMETER WindowsLicense
  file with encrypted Windows license.

  .PARAMETER OfficeLicense
  file with encrypted Office license.

  .PARAMETER OfficeVersion
  Office version to be activated by officelicense parameter. Default is 'Office16'.

  .PARAMETER EncryptionKey
  file with encryption key for license files. Please make sure that this file is only readable by necessary users/computers.

  .PARAMETER UseProxy

  .PARAMETER ProxyServer
  WinHTTP proxy; Maybe needed of MAK license activation.

  .PARAMETER ProxyExceptionList
  Exception list for WinHTTP proxy;

  .PARAMETER LogFile
  Log file of script 

  .EXAMPLE
  PS> .\ChangeActivation.ps1 -WindowsLicense "<Path to lic>" -OfficeLicense "<Path to lic>"
  Changing Windows license
  Changing Office license

  .EXAMPLE
  PS> .\ChangeActivation.ps1 -WindowsLicense "<Path to lic>"
  Changing Windows license

  .EXAMPLE
  PS> .\ChangeActivation.ps1 -OfficeLicense "<Path to lic>"
  Changing Office license

  .EXAMPLE
  PS> .\ChangeActivation.ps1 -WindowsLicense "<Path to lic>" -OfficeLicense "<Path to lic>" -ProxyServer "10.0.0.254:3128" -ProxyException "10.*;*.CONTOSO.COM;<local>"
  Changing Windows license using Proxy
  Changing Office license using Proxy
  
  .INPUTS
  None. The script does not accept value from pipeline.

  .OUTPUTS
  None. The script does not output to pipeline.

  .NOTES
  Script uses slmgr.vbs and OSPP.vbs to change activation.

  .FUNCTIONALITY
  Changes licensing of specified product.

  .LINK
  https://github.com/dskeller/ChangeActivation

  .LINK
  https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider

  .LINK
  https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal

  .LINK
  https://docs.microsoft.com/en-us/windows-server/get-started/activation-slmgr-vbs-options

  .LINK
  https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-proxy-internet

#>
[CmdletBinding(DefaultParameterSetName="Both")]
param(
  [Parameter(Mandatory=$true,ParameterSetName="Windows")]
  [Parameter(Mandatory=$true,ParameterSetName="Both")]
  [System.IO.FileInfo]$WindowsLicense,
  [Parameter(Mandatory=$true,ParameterSetName="Office")]
  [Parameter(Mandatory=$true,ParameterSetName="Both")]
  [System.IO.FileInfo]$OfficeLicense,
  [Parameter(Mandatory=$true,ParameterSetName="Office")]
  [Parameter(Mandatory=$true,ParameterSetName="Windows")]
  [Parameter(Mandatory=$true,ParameterSetName="Both")]
  [System.IO.FileInfo]$EncryptionKey,
  [Parameter(Mandatory=$false,ParameterSetName="Office")]
  [Parameter(Mandatory=$false,ParameterSetName="Both")]
  [String]$OfficeVersion="Office16",
  [Parameter(Mandatory=$true,ParameterSetName="UseProxy")]
  [switch]$UseProxy,
  [Parameter(Mandatory=$true,ParameterSetName="UseProxy")]
  [string]$ProxyServer,
  [Parameter(Mandatory=$true,ParameterSetName="UseProxy")]
  [string]$ProxyPort,
  [Parameter(Mandatory=$false,ParameterSetName="UseProxy")]
  [string]$ProxyExceptionList,
  [Parameter(Mandatory=$false,ParameterSetName="Windows")]
  [Parameter(Mandatory=$false,ParameterSetName="Office")]
  [Parameter(Mandatory=$false,ParameterSetName="Both")]
  [System.IO.FileInfo]$LogFile
)
#requires -RunAsAdministrator

begin{
  #==================================================================	
  # Function: Initialize-ScriptVariables | sets script variables
  #================================================================== 
  #region Initialize-ScriptVariables
  function Initialize-ScriptVariables()
  {
    # fix variables
    $script:Title="ChangeActivation"
    $script:version="1.0.0"
    $script:Modules=@()
    $script:ErrorLevel=0
      
    # dynamically builded variables
    if (-not($PSScriptRoot))
    {
      $script:ScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
    }
    else
    {
      $script:ScriptRoot = $PSScriptRoot
    }
  
    if ($script:WindowsLicense -like ".\*")
    {
      $script:WindowsLicense = $script:ScriptRoot+'\'+$script:WindowsLicense.TrimStart('.\')
    }
  
    if ($script:OfficeLicense -like ".\*")
    {
      $script:OfficeLicense = $script:ScriptRoot+'\'+$script:OfficeLicense.TrimStart('.\')
    }
  }
  #endregion

  #=====================================================================
  # Function: Stop-TranscriptPlus | finishes Log-File and stops logging.
  #=====================================================================
  #region Stop-TranscriptPlus
  Function Stop-TranscriptPlus ($ScriptTitle,$ScriptVersion,$ScriptTranscript)
  {
    $time = Get-Date
    $Message = '==== '+$time+': Script '+$ScriptTitle+' '+$ScriptVersion+' stopped. ===='
    Write-Output $Message
    if ($ScriptTranscript -eq $true)
    {
      Stop-Transcript
    }
  }
  #endregion

  #region MAIN
  #region Initialization
  trap {continue} #keeps script running on throw
  
  Initialize-ScriptVariables
  
  # prepare Logfile and use Start-Transcript for logging
  #region Logging
  if ($LogFile -ne "")
  {
      if (-not(Test-Path $LogFile))
      {
        New-Item $LogFile -ItemType File -Force -Verbose
      }
      Start-Transcript -path $LogFile -append
      $Transcript=$true
  }
  #endregion Logging
  
  $time = Get-Date
  $Message = '==== '+$time+': Starting '+$script:Title+' '+$script:Version+' ===='
  Write-Output -InputObject $message
}

process{

  # set proxy if specified
  if ($ProxyServer -ne "")
  {
    if (-not($((Test-NetConnection -ComputerName $ProxyServer -Port $ProxyPort).TcpTestSucceeded) -eq $true))
    {
      throw 'Specified proxy server not reachable.'
    }
    else
    {
      $Script:Proxy = $ProxyServer+':'+$ProxyPort
      $Message = 'Set WinHTTP proxy '+$Script:Proxy+' for time of script execution.'
      Write-Output -InputObject $Message
      if ($ProxyExceptionList -ne "")
      {
        $Script:netshParams = "winhttp set proxy-server='$Script:Proxy' bypass-list='$ProxyExceptionList'"
      }
      else
      {
        $Script:netshParams = "winhttp set proxy-server='$Script:Proxy'"
      }
      Start-Process -wait -NoNewWindow -FilePath "$env:windir\System32\netsh.exe" -Argumentlist $Script:netshParams
    }
  }

  # set windows license if specified
  if ($script:WindowsLicense)
  {
    a
  }

  if ($script:OfficeLicense)
  {
    a
  }

  # reset proxy if specified
  if ($ProxyServer -ne "")
  {
    $Message = 'Reset WinHTTP proxy.'
    Write-Output -InputObject $Message
    $Script:netshParams = "winhttp reset proxy"
    Start-Process -wait -NoNewWindow -FilePath "$env:windir\System32\netsh.exe" -Argumentlist $Script:netshParams
  }
}

end
{
  Stop-TranscriptPlus -ScriptTitle $Title -ScriptVersion $Version -ScriptTranscript $Transcript
}

<#

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

vbs cant handle secure strings. so it is necessary to revert encryption with used key.
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($(Get-Content "PATHNAME-FOR-LICENSE-FILE"| ConvertTo-SecureString -key $(Get-Content "PATHNAME-FOR-AES-KEY"))))

# Key-File to decrypt lics
$KEY     = Get-Content "AES.key"

#W10E-MAK-Lizenzdatei
$W10LIC = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($(Get-Content "$WindowsLicense"| ConvertTo-SecureString -key $Key)))

#O16S-MAK-Lizenzdatei
$OFFLIC = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($(Get-Content "$OfficeLicense"| ConvertTo-SecureString -key $Key)))


# 1. Set WinHTTP Proxy
netsh winhttp set proxy $proxyserver:$proxyport | Out-Null

# 2. W10 Activation
C:\Windows\system32\cscript.exe C:\Windows\System32\slmgr.vbs /ipk $W10LIC | Out-Null
C:\Windows\system32\cscript.exe C:\Windows\System32\slmgr.vbs /ato | Out-Null

# 3. Office Activation
C:\Windows\System32\cscript.exe 'C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS' /inpkey:$O16SD | Out-Null
C:\Windows\System32\cscript.exe 'C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS' /act | Out-Null

# 5. Reset WinHTTP Proxy
netsh winhttp reset proxy

#>

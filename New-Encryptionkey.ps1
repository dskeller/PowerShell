<#
  New-EncryptionKey.ps1 (c) 2021 dskeller
#>
[CmdletBinding()]
param(
    # Name of new encryption key
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty]
    [string]$Name,
    # Path of new encryption key
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      if(-not(Test-Path -Path "$_" -PathType Container)){
        throw "Path is invalid"
      }
      return $true
    })]
    [System.IO.FileInfo]$Path
)

$Script:target = $Path.trimEnd('\')+'\'+$Name
if (Test-Path -Path "$Script:target" -PathType Container){
  throw "Key already exist. Please check and rerun script."
}
$Key = New-Object Byte[] 32
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
$Key | out-file $Script:target -Force

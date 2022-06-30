<#
  New-Licensefile.ps1 (c) 2021 dskeller
#>
[CmdletBinding()]
param(
    # License to encrypt
    [Parameter(Mandatory=$true)]
    [ValidatePattern]
    [string]$License,
    # Encryption key file
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      if(-not(Test-Path -Path "$_" -PathType Container)){
        throw "Path to encryption key is invalid"
      }
      return $true
    })]
    [System.IO.FileInfo]$EncryptionKey,
    # File to write encrypted license
    [Parameter(Mandatory=$true)]
    [ValidateScript({
      if (-not(Test-Path -Path "$($_.Parent)" -PathType Container)){
        throw "Path to save encrypted license is invalid"
      }elseif(Test-Path -Path "$_" -PathType Leaf){
        throw "File tp save encrypted license already exist."
      }
      return $true
    })]
    [System.IO.FileInfo]$EncryptedLicenseFile
)
"$License" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString -Key $(Get-Content "$EncryptionKey") | Out-File "$EncryptedLicenseFile"

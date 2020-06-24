# Process function Secrets passed in
# Process function Secrets passed in
$VC_CONFIG_FILE = "/var/openfaas/secrets/vc-ds-config"
$VC_CONFIG = (Get-Content -Raw -Path $VC_CONFIG_FILE | ConvertFrom-Json)
if($env:function_debug -eq "true") {
    Write-host "DEBUG: `"$VC_CONFIG`""
}

# Process payload sent from vCenter Server Event
$json = $args | ConvertFrom-Json
if($env:function_debug -eq "true") {
    Write-Host "DEBUG: json=`"$($json | Format-List | Out-String)`""
}

# import and configure Slack
Import-Module PSSlack | Out-Null
Import-module purestoragepowershellsdk| Out-Null
function Get-pfaVolfromVMFS2 {
  <#
  .SYNOPSIS
    Retrieves the FlashArray volume that hosts a VMFS datastore.
  .DESCRIPTION
    Takes in a VMFS datastore and one or more FlashArrays and returns the volume if found.
  .INPUTS
    FlashArray connection(s) and a VMFS datastore.
  .OUTPUTS
    Returns FlashArray volume or null if not found.
  .NOTES
    Version:        3.0
    Author:         Cody Hosterman https://codyhosterman.com
    Creation Date:  12/17/2019
    Purpose/Change: Added parameter sets, validation 
  .EXAMPLE
    PS C:\ $faCreds = get-credential
    PS C:\ $fa = New-PfaConnection -endpoint flasharray-m20-2 -credentials $faCreds -defaultArray
    PS C:\ $ds = get-datastore myVMFS
    PS C:\ Get-PfaVMFSVol -datastore $ds -flasharray $fa
    
    Returns the volume that hosts the VMFS datastore.
  .EXAMPLE
    PS C:\ $faCreds = get-credential
    PS C:\ New-PfaConnection -endpoint flasharray-m20-2 -credentials $faCreds -defaultArray
    PS C:\ New-PfaConnection -endpoint flasharray-x20-1 -credentials $faCreds -nondefaultArray
    PS C:\ $ds = get-datastore myVMFS
    PS C:\ Get-PfaVMFSVol -datastore $ds
    
    Returns the volume that hosts the VMFS datastore by finding it on one of the connected FlashArrays.
  *******Disclaimer:******************************************************
  This scripts are offered "as is" with no warranty.  While this 
  scripts is tested and working in my environment, it is recommended that you test 
  this script in a test lab before using in a production environment. Everyone can 
  use the scripts/commands provided here without any written permission but I
  will not be liable for any damage or loss to the system.
  ************************************************************************
  #>

  [CmdletBinding()]
  Param(
          [Parameter(Position=0,mandatory=$true,ValueFromPipeline=$True)]
          [ValidateScript({
            if ($_.Type -ne 'VMFS')
            {
                throw "The entered datastore is not a VMFS datastore. It is type $($_.Type). Please only enter a VMFS datastore"
            }
            else {
              $true
            }
          })]
          [VMware.VimAutomation.ViCore.Types.V1.DatastoreManagement.Datastore]$datastore,

          [Parameter(Position=1,ValueFromPipeline=$True)]
          [PurePowerShell.PureArray[]]$flasharray
  )

  if ($null -eq $flasharray)
  {
      $fa = get-pfaConnectionOfDatastore2 -datastore $datastore
  }
  else {
    $fa = get-pfaConnectionOfDatastore2 -datastore $datastore -flasharrays $flasharray
  }
  $SessionAction = @{
      api_token = $fa.ApiToken
  }
  Invoke-RestMethod -Method Post -Uri "https://$($fa.Endpoint)/api/$($fa.apiversion)/auth/session" -Body $SessionAction -SessionVariable Session -ErrorAction Stop -SkipCertificateCheck |Out-Null
  $purevolumes =  Invoke-RestMethod -Method Get -Uri "https://$($fa.Endpoint)/api/$($fa.apiversion)/volume" -WebSession $Session -ErrorAction Stop -SkipCertificateCheck
  $lun = $datastore.ExtensionData.Info.Vmfs.Extent.DiskName |select-object -unique
  $volserial = ($lun.ToUpper()).substring(12)
  $purevol = $purevolumes | where-object { $_.serial -eq $volserial }
  if ($null -ne $purevol.name)
  {
      return $purevol
  }
  else {
      throw "The volume was not found."
  }
}
function getAllFlashArrays {
  if ($null -ne $Global:AllFlashArrays)
  {
      return $Global:AllFlashArrays
  }
  else
  {
      throw "Please either pass in one or more FlashArray connections or create connections via the new-pfaConnection cmdlet."
  }
}
Function Get-SSLThumbprint {
  param(
  [Parameter(
      Position=0,
      Mandatory=$true,
      ValueFromPipeline=$true,
      ValueFromPipelineByPropertyName=$true)
  ]
  [Alias('FullName')]
  [String]$URL
  )
  if ($URL -notlike "https://*")
  { 
    $URL = "https://" + $URL
  }
  $Code = @'
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace CertificateCapture
{
  public class Utility
  {
      public static Func<HttpRequestMessage,X509Certificate2,X509Chain,SslPolicyErrors,Boolean> ValidationCallback =
          (message, cert, chain, errors) => {
              var newCert = new X509Certificate2(cert);
              var newChain = new X509Chain();
              newChain.Build(newCert);
              CapturedCertificates.Add(new CapturedCertificate(){
                  Certificate =  newCert,
                  CertificateChain = newChain,
                  PolicyErrors = errors,
                  URI = message.RequestUri
              });
              return true;
          };
      public static List<CapturedCertificate> CapturedCertificates = new List<CapturedCertificate>();
  }
  public class CapturedCertificate
  {
      public X509Certificate2 Certificate { get; set; }
      public X509Chain CertificateChain { get; set; }
      public SslPolicyErrors PolicyErrors { get; set; }
      public Uri URI { get; set; }
  }
}
'@
  if ($PSEdition -ne 'Core'){
      Add-Type -AssemblyName System.Net.Http
      if (-not ("CertificateCapture" -as [type])) {
          Add-Type $Code -ReferencedAssemblies System.Net.Http 
      }
  } else {
      if (-not ("CertificateCapture" -as [type])) {
          Add-Type $Code 
      }
  }

  $Certs = [CertificateCapture.Utility]::CapturedCertificates
  $Handler = [System.Net.Http.HttpClientHandler]::new()
  $Handler.ServerCertificateCustomValidationCallback = [CertificateCapture.Utility]::ValidationCallback
  $Client = [System.Net.Http.HttpClient]::new($Handler)
  $Client.GetAsync($Url).Result |Out-Null
  $sha1 = [Security.Cryptography.SHA1]::Create()
  $certBytes = $Certs[-1].Certificate.GetRawCertData()
  $hash = $sha1.ComputeHash($certBytes)
  $thumbprint = [BitConverter]::ToString($hash).Replace('-',':')
  return $thumbprint
}

function Get-PfaVolumes {
    [CmdletBinding()]
    Param(
    
      [Parameter(Position=0,mandatory=$true,ValueFromPipeline=$True)]
      [PurePowerShell.PureArray[]]$flasharray
    )
            $SessionAction = @{
                api_token = $flasharray.ApiToken
            }
            Invoke-RestMethod -Method Post -Uri "https://$($flasharray.Endpoint)/api/$($flasharray.apiversion)/auth/session" -Body $SessionAction -SessionVariable Session -ErrorAction Stop -SkipCertificateCheck |Out-Null
            $purevolumes =  Invoke-RestMethod -Method Get -Uri "https://$($flasharray.Endpoint)/api/$($flasharray.apiversion)/volume" -WebSession $Session -ErrorAction Stop -SkipCertificateCheck
            return $purevolumes
}

function Get-PfaConnectionOfDatastore2 {
  <#
  .SYNOPSIS
    Takes in a vVol or VMFS datastore, one or more FlashArray connections and returns the correct connection.
  .DESCRIPTION
    Will iterate through any connections stored in $Global:AllFlashArrays or whatever is passed in directly.
  .INPUTS
    A datastore and one or more FlashArray connections
  .OUTPUTS
    Returns the correct FlashArray connection.
  .NOTES
    Version:        1.1
    Author:         Cody Hosterman https://codyhosterman.com
    Creation Date:  12/08/2019
    Purpose/Change: Added parameter validation
  .EXAMPLE
      PS C:\ $faCreds = get-credential
      PS C:\ New-PfaConnection -endpoint flasharray-m20-2 -credentials $faCreds -defaultArray
      PS C:\ New-PfaConnection -endpoint flasharray-x70-1 -credentials $faCreds -nondefaultArray
      PS C:\ New-PfaConnection -endpoint flasharray-x70-2 -credentials $faCreds -nondefaultArray
      PS C:\ $ds = get-datastore MyDatastore
      PS C:\ Get-PfaConnectionOfDatastore -datastore $ds
      
      Returns the connection of the FlashArray that hosts the specified datastore
  *******Disclaimer:******************************************************
  This scripts are offered "as is" with no warranty.  While this 
  scripts is tested and working in my environment, it is recommended that you test 
  this script in a test lab before using in a production environment. Everyone can 
  use the scripts/commands provided here without any written permission but I
  will not be liable for any damage or loss to the system.
  ************************************************************************
  #>
  
  [CmdletBinding()]
  Param(
  
    [Parameter(Position=0,ValueFromPipeline=$True)]
    [PurePowerShell.PureArray[]]$flasharrays,
  
    [Parameter(Position=1,mandatory=$true,ValueFromPipeline=$True)]
    [ValidateScript({
      if (($_.Type -ne 'VMFS') -and ($_.Type -ne 'VVOL'))
      {
          throw "The entered datastore is not a VMFS or vVol datastore. It is type $($_.Type). Please only enter a VMFS or vVol datastore"
      }
      else {
        $true
      }
    })]
    [VMware.VimAutomation.ViCore.Types.V1.DatastoreManagement.Datastore]$datastore
  )
    if ($null -eq $flasharrays)
    {
        $flasharrays = getAllFlashArrays 
    }
    if ($datastore.Type -eq 'VMFS')
    {
        $lun = $datastore.ExtensionData.Info.Vmfs.Extent.DiskName |select-object -unique
        if ($lun -like 'naa.624a9370*')
        { 
            $volserial = ($lun.ToUpper()).substring(12)
            foreach ($flasharray in $flasharrays) {
              $SessionAction = @{
                  api_token = $flasharray.ApiToken
              }
              Invoke-RestMethod -Method Post -Uri "https://$($flasharray.Endpoint)/api/$($flasharray.apiversion)/auth/session" -Body $SessionAction -SessionVariable Session -ErrorAction Stop -SkipCertificateCheck |Out-Null
              $purevolumes =  Invoke-RestMethod -Method Get -Uri "https://$($flasharray.Endpoint)/api/$($flasharray.apiversion)/volume" -WebSession $Session -ErrorAction Stop -SkipCertificateCheck
              $purevol = $purevolumes | where-object { $_.serial -eq $volserial }
                if ($null -ne $purevol.name)
                {
                    return $flasharray
                }
            }
        }
        else 
        {
            throw "This VMFS is not hosted on FlashArray storage."
        }
    }
    elseif ($datastore.Type -eq 'VVOL') 
    {
        $datastoreArraySerial = $datastore.ExtensionData.Info.VvolDS.StorageArray[0].uuid.Substring(16)
        foreach ($flasharray in $flasharrays)
        {
            $arraySerial = (Get-PfaArrayAttributes -array $flasharray).id
            if ($arraySerial -eq $datastoreArraySerial)
            {
                $Global:CurrentFlashArray = $flasharray
                return $flasharray
            }
        }
    }
    $Global:CurrentFlashArray = $null
    throw "The datastore was not found on any of the FlashArray connections."
}

#script
$alarmName = ($json.data.alarm.name -replace "\n"," ")
$datastoreName = $json.data.ds.name
$alarmStatus = $json.data.to
$vcenter = ($json.source -replace "/sdk","")
$datacenter = $json.data.datacenter.name

if($env:function_debug -eq "true") {
    Write-Host "DEBUG: alarmName: `"$alarmName`""
    Write-host "DEBUG: datastoreName: `"$datastoreName`""
    Write-Host "DEBUG: alarmStatus: `"$alarmStatus`""
    Write-Host "DEBUG: vcenter: `"$vcenter`""
}

if( ("$alarmName" -match "$($VC_CONFIG.VC_ALARM_NAME)") -and ([bool]($VC_CONFIG.DATASTORE_NAMES -match "$datastoreName")) -and ($alarmStatus -eq "yellow" -or $alarmStatus -eq "red" -or $alarmStatus -eq "green") ) {
    # Warning Email Body
    if($alarmStatus -eq "yellow") {
        $subject = ":warning: $($VC_CONFIG.SUBJECT)"
        $threshold = "warning"

        #takeaction
        $username = "$($VC_CONFIG.PURE_USERNAME)"
        $password = ConvertTo-SecureString "$($VC_CONFIG.PURE_PASSWORD)" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
        $fa1 = New-PfaConnection -endpoint {myflasharray.lab.local} -credentials $cred -defaultarray -ignoreCertificateError
        $fa2 = New-PfaConnection -endpoint {myflasharray2.lab.local} -credentials $cred -nonDefaultArray -ignoreCertificateError
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore  -DisplayDeprecationWarnings $false -ParticipateInCeip $false -Confirm:$false -Scope AllUsers| Out-Null
        $Server = Connect-VIServer $($VC_CONFIG.VC) -User $($VC_CONFIG.VC_USERNAME) -Password $($VC_CONFIG.VC_PASSWORD) -Force | out-null
        $datastore = Get-Datastore $datastoreName -Server $Server
        write-host "This is the " $datastore
        $connection = Get-PfaConnectionOfDatastore2 -flasharrays $fa1,$fa2 -datastore $datastore
        write-host "this is the Array" $connection.Endpoint
        $volume = get-pfaVolfromVMFS2 -datastore $datastore -flasharray $connection
        Write-Host $Datastore "is on" $connection.endpoint "and is" ($volume.size/1024/1024/1024) "GB"
        Resize-PfaVolume -Array $connection -VolumeName $volume.name -NewSize ($volume.size + 10737418240) -ErrorAction SilentlyContinue
        $volume = get-pfaVolfromVMFS2 -datastore $datastore -flasharray $connection
        $esxi = Get-View -Id ($Datastore.ExtensionData.Host |Select-Object -last 1 | Select-Object -ExpandProperty Key)
        $datastoreSystem = Get-View -Id $esxi.ConfigManager.DatastoreSystem
        $expandOptions = $datastoreSystem.QueryVmfsDatastoreExpandOptions($datastore.ExtensionData.MoRef)
        $expandOptions = $datastoreSystem.QueryVmfsDatastoreExpandOptions($datastore.ExtensionData.MoRef)
        $datastoreSystem.ExpandVmfsDatastore($datastore.ExtensionData.MoRef,$expandOptions.spec) | Out-Null
        Write-Host $Datastore "is now"($volume.size/1024/1024/1024) "GB"
        Disconnect-viserver * -confirm:$false

        $Body = "Datastore usage on $datastoreName has reached $threshold threshold.`r`n"
        $Body = $Body + @"
        vCenter Server: $vcenter
        Datacenter: $datacenter
        Datastore: $datastoreName

        $Datastore has been automatically expanded by 10GB
"@

    } 
    elseif($alarmStatus -eq "red") {
        $subject = ":rotating_light: $($VC_CONFIG.SUBJECT)"
        $threshold = "error"

         #takeaction
        $username = "$($VC_CONFIG.PURE_USERNAME)"
        $password = ConvertTo-SecureString "$($VC_CONFIG.PURE_PASSWORD)" -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential -ArgumentList ($username, $password)
        $fa1 = New-PfaConnection -endpoint {myflasharray.lab.local} -credentials $cred -defaultarray -ignoreCertificateError
        $fa2 = New-PfaConnection -endpoint {myflasharray2.lab.local} -credentials $cred -nonDefaultArray -ignoreCertificateError
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore  -DisplayDeprecationWarnings $false -ParticipateInCeip $false -Confirm:$false -Scope AllUsers| Out-Null
        $Server = Connect-VIServer $($VC_CONFIG.VC) -User $($VC_CONFIG.VC_USERNAME) -Password $($VC_CONFIG.VC_PASSWORD) -Force | out-null
        $datastore = Get-Datastore $datastoreName -Server $Server
        write-host "This is the " $datastore
        $connection = Get-PfaConnectionOfDatastore2 -flasharrays $fa1,$fa2 -datastore $datastore
        write-host "this is the Array" $connection.Endpoint
        $volume = get-pfaVolfromVMFS2 -datastore $datastore -flasharray $connection
        Write-Host $Datastore "is on" $connection.endpoint "and is" ($volume.size/1024/1024/1024) "GB"
        Resize-PfaVolume -Array $connection -VolumeName $volume.name -NewSize ($volume.size + 21474836480) -ErrorAction SilentlyContinue
        $volume = get-pfaVolfromVMFS2 -datastore $datastore -flasharray $connection
        $esxi = Get-View -Id ($Datastore.ExtensionData.Host |Select-Object -last 1 | Select-Object -ExpandProperty Key)
        $datastoreSystem = Get-View -Id $esxi.ConfigManager.DatastoreSystem
        $expandOptions = $datastoreSystem.QueryVmfsDatastoreExpandOptions($datastore.ExtensionData.MoRef)
        $expandOptions = $datastoreSystem.QueryVmfsDatastoreExpandOptions($datastore.ExtensionData.MoRef)
        $datastoreSystem.ExpandVmfsDatastore($datastore.ExtensionData.MoRef,$expandOptions.spec) | Out-Null
        Write-Host $Datastore "is now"($volume.size/1024/1024/1024) "GB"
        Disconnect-viserver * -confirm:$false

        $Body = "Datastore usage on $datastoreName has reached $threshold threshold.`r`n"
        $Body = $Body + @"
        vCenter Server: $vcenter
        Datacenter: $datacenter
        Datastore: $datastoreName

        $Datastore has been automatically expanded by 20GB
"@


    }
    elseif($alarmStatus -eq "green") {
        $subject = "$($VC_CONFIG.SUBJECT)"
        $threshold = "normal"

        $Body = "Datastore usage on $datastoreName has reached $threshold threshold.`r`n"
        $Body = $Body + @"
        vCenter Server: $vcenter
        Datacenter: $datacenter
        Datastore: $datastoreName
"@

}

New-SlackMessageAttachment -Color $([System.Drawing.Color]::red) `
    -Title "$Subject" `
    -Text "$Body" `
    -Fallback "$Subject" |
New-SlackMessage -Channel $($VC_CONFIG.SLACK_CHANNEL) `
    -IconEmoji :veba: |
Send-SlackMessage -Uri $($VC_CONFIG.SLACK_URL)

}
param (       
        [Parameter(Mandatory=$true, Position=1)]
        [string]$localSettings_file,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$resourceGroupName,
        [Parameter(Mandatory=$true, Position=3)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$true, Position=3)]
        [string]$functionName
    )

Function ConfigExits{
    param(
        [psobject]$configprop1, 
        [string]$configName
    )
  if ($configprop1.psobject.properties.where({ $_.Name -eq $configName })){
    return 1}
 else{
    return 0}
}
Function GetAzureManagementApiVersion{
 return ((Get-AzResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes | Where-Object ResourceTypeName -eq sites).ApiVersions | Sort-Object ApiVersion -Descending | Select-object -First 1 
}

Write-Host "Get Access token"
$c = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
$token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($c.Account, $c.Environment, $c.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://management.azure.com").AccessToken

Write-Host "localSettings_file: $localSettings_file"

Write-Host "Reading local.settings.json..."
$localConfig = Get-Content $localSettings_file |out-string |ConvertFrom-Json
$configAdded = 0

Write-Host "Getting Azure management api version..."
$apiVersion= GetAzureManagementApiVersion

$resourceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Web/sites/$functionName"
$apiUrl="https://management.azure.com$resourceId/config/appsettings/list?api-version=$apiVersion"

Write-Host "Retrieveing $functionName configuration..."
$configs = Invoke-RestMethod -Uri $apiUrl -Headers @{ Authorization="Bearer "+$token; "Content-Type"="application/json"} -Method Post |ConvertTo-Json|ConvertFrom-Json
$configprop = $configs.properties

Write-Host "Checking for missing configuration..."
foreach($item in ($localConfig.Values |Get-Member |Select-Object NAme,MemberType | Where-Object MemberType -eq "NoteProperty")){
    $n=$item.Name
    $v = $localConfig.Values.$n
    If ((ConfigExits $configprop $n) -eq 0){
        $configprop | Add-Member -Type NoteProperty -Name $n -Value $v  
        $configAdded = 1
        write-host "Added $n : $v"
    }
}
if ($configAdded -eq 1){
    $j =@{"properties"=$configprop} |ConvertTo-Json
    Write-Host "Updating configuration..."
    $apiUrl1="https://management.azure.com$resourceId/config/appsettings?api-version=$apiVersion"
    Invoke-RestMethod -Uri $apiUrl1 -Headers @{ Authorization="Bearer "+$token; "Content-Type"="application/json"} -Method Put -Body $j
}

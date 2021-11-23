Param( 
    [Parameter(Mandatory = $true)] 
    [string] $ResourceGroupName, 
    [Parameter(Mandatory = $true)] 
    [string] $AppServiceName, 
    [Parameter(Mandatory = $true)]
    [string] $Command
)
Function GetBuildAgentIP{
    $agentIP = Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
    return @{
        ipAddress = $agentIP+"/32"; 
        action = "Allow";
        priority = 65000;
        name = "Added-By-DEVOPS";
        description = "Add by Azure Devops";
        tag = "Default";
    }
}

if ($Command -ne "Add" -and $Command -ne "Remove"){
    throw "Command not specified Add or Remove"
}

$APIVersion = ((Get-AzResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes | Where-Object ResourceTypeName -eq sites).ApiVersions[0]

$WebAppConfig = Get-AzResource -ResourceName $AppServiceName -ResourceType Microsoft.Web/sites/config -ResourceGroupName $ResourceGroupName -ApiVersion $APIVersion

If ($Command -eq "Add"){
    $NewIpRule = GetBuildAgentIP |ConvertTo-Json|ConvertFrom-Json
    $WebAppConfig.Properties.ipSecurityRestrictions += $NewIpRule
}
If ($Command -eq "Remove"){
    $NewIpRule = $WebAppConfig.Properties.ipSecurityRestrictions | where-object {($_.priority -ne 65000) -and ($_.name -ne 'Added-By-DEVOPS')}
    $WebAppConfig.Properties.ipSecurityRestrictions = $NewIpRule
}

Set-AzResource -ResourceId $WebAppConfig.ResourceId -Properties $WebAppConfig.Properties -ApiVersion $APIVersion -Force

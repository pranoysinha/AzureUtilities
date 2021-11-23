param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$resourceGroupName_APIM,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$serviceName,
        [Parameter(Mandatory=$true, Position=3)]
        [boolean]$isVersioned,
        [Parameter(Mandatory=$true, Position=4)]
        [AllowEmptyString()]
        [string]$apiVersionSetName,
        [Parameter(Mandatory=$true, Position=5)]
        [AllowEmptyString()]
        [string]$apiVersionSetId,
        [Parameter(Mandatory=$true, Position=6)]
        [AllowEmptyString()]
        [string]$apiName,
        [Parameter(Mandatory=$true, Position=7)]
        [string]$specificationUrl,
        [Parameter(Mandatory=$true, Position=8)]
        [string]$apiPath,
        [Parameter(Mandatory=$true, Position=9)]
        [string]$functionName,
        [Parameter(Mandatory=$true, Position=10)]
        [string]$productId,
        [Parameter(Mandatory=$true, Position=11)]
        [string]$resourceGroupName_FnApp,
        [Parameter(Mandatory=$true, Position=12)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$true, Position=13)]
        [array]$APITags,
        [Parameter(Mandatory=$true, Position=14)]
        [string]$app_clientId,
        [Parameter(Mandatory=$true, Position=15)]
        [string]$client_secret,        
        [Parameter(Mandatory=$true, Position=16)]
        [string]$APIMUrl,
        [Parameter(Mandatory=$true, Position=17)]
        [string]$Environment,
        [Parameter(Position=18)]
        [string]$APIOutboundOperations        
    )
Function GetAzureManagementApiVersion{
 return ((Get-AzResourceProvider -ProviderNamespace Microsoft.Web).ResourceTypes | Where-Object ResourceTypeName -eq sites).ApiVersions | Sort-Object ApiVersion -Descending | Select-object -First 1 
}
Function GetFunctionKey{
    param(
        [string]$subscriptionId,
        [string]$resourceGroupName_FnApp,
        [string]$functionAppName,
        [string]$accessToken
    )
    #Write-host $accessToken
    $apiVersion= GetAzureManagementApiVersion
    $apimKeyName="apim-CBHSPOCGateway"
    $resourceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName_FnApp/providers/Microsoft.Web/sites/$functionAppName"
    $azureUri= "https://management.azure.com$resourceId/host/default/listKeys?api-version=$ApiVersion"
    #write-host $azureUri
    $keys=Invoke-RestMethod -Method Post -Uri $azureUri -Headers @{ Authorization="Bearer "+$accessToken; "Content-Type"="application/json"}
    if (([string]::IsNullOrEmpty($keys.functionKeys.$apimKeyName))){
        $keyValue = $keys.functionKeys.default
    }
    else{
        $keyValue = $keys.functionKeys.$apimKeyName
    }
    return $keyValue
}
Function TagAPI{
    param(
        [string]$subscriptionId,
        [string]$resourceGroupName_APIM,
        [string]$APIMName,
        [string]$accessToken,
        [string]$apiId,
        [array] $tags
    )
    #Write-host $accessToken
    $apiVersion= ((Get-AzResourceProvider -ProviderNamespace Microsoft.ApiManagement).ResourceTypes | Where-Object ResourceTypeName -eq service).ApiVersions -notlike "*preview" | Sort-Object ApiVersion -Descending | Select-object -First 1
    $resourceId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName_APIM/providers/Microsoft.ApiManagement/service/$APIMName"
    $azureGetTagUri= "https://management.azure.com$resourceId/tags?api-version=$ApiVersion"
    #$apiTags = "Eclipse", "Utility"
    write-host "Tags - $tags"
    $existingTags=Invoke-RestMethod -Method GET $azureGetTagUri  -Headers @{ Authorization="Bearer "+$accessToken;} 
    
    foreach($apiTag in $tags){
        write-host "Updating tag - $apiTag"
        if ($existingTags.value.Where({$_.Name -eq $apiTag}).Count -eq 0){
            $tagProperty = @{"name"="$apiTag";"properties"= @{"displayName" ="$apiTag"}}|ConvertTo-Json
            $azureCreateTagUri= "https://management.azure.com$resourceId/tags/$apiTag/?api-version=$ApiVersion"
            #write-host $azureCreateTagUri
            Invoke-RestMethod -Method PUT $azureCreateTagUri  -Headers @{ Authorization="Bearer "+$accessToken;"Content-Type"="application/json"} -Body $tagProperty |out-null
            }
        #write-host $azureSetTagURI
        $azureSetTagURI="https://management.azure.com$resourceId/apis/$apiId/tags/$apiTag/?api-version=$ApiVersion"
        Invoke-RestMethod -Method PUT -Uri $azureSetTagURI -Headers @{ Authorization="Bearer "+$accessToken; "Content-Type"="application/json"} |out-null

    }
}
Function GetVersionSet{
    param (
        [string]$azureContext,
        [string]$versionSetId
    )
    
    Try{
        $a = Get-AzApiManagementApiVersionSet -Context $context -ApiVersionSetId $versionSetId -ErrorAction Stop |Select-object '1'
    }
    Catch{ $a='0'}
    return $a
}

Function GetNextAPIVersion{
    param(
        [string]$azureContext,
        [string]$name
    )
    $maxVersion=''
    Try{
        $ret = (Get-AzApiManagementApi -Context $context -Name $name  -ErrorAction Stop | Sort-Object ApiVersion -Descending | Select-object -First 1 ApiVersion).psobject.Members | where-object MemberType -Like "NoteProperty"
        if (([string]::IsNullOrEmpty($ret))){
            $maxVersion=''
            }
        else{
            $maxVersion = $ret.value
            }
    }
    Catch{ 
        $maxVersion=''
    }
    if ($maxVersion -eq ''){
        $NextVersionNo='v1'
    }
    else{
        $maxVersionNo = [int]$maxVersion.Substring(1)
        $NextVersionNo = $maxVersion.Substring(0,1) + ($maxVersionNo + 1).ToString()
    }
    return $NextVersionNo

}
Function CreateAPIMPolicy{
    param(
        [string]$policy_template_path,
        [string]$functionKeyName,
        [string]$appClientId,
        [string]$APIMUrl
    )
    $policy = [io.file]::ReadAllLines($policy_template_path)
    $policy = $policy -replace 'FUNCTION-KEY',$functionKeyName
    $policy = $policy -replace 'CLIENTID',$appClientId
    $policy = $policy -replace 'APIM-URL',$APIMUrl
    return $policy
}

Function ImportFunction{
    param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$resourceGroupName_APIM,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$serviceName,
        [Parameter(Mandatory=$true, Position=3)]
        [boolean]$isVersioned,
        [Parameter(Mandatory=$true, Position=4)]
        [AllowEmptyString()]
        [string]$apiVersionSetName,
        [Parameter(Mandatory=$true, Position=5)]
        [AllowEmptyString()]
        [string]$apiVersionSetId,
        [Parameter(Mandatory=$true, Position=6)]
        [AllowEmptyString()]
        [string]$apiName,
        [Parameter(Mandatory=$true, Position=7)]
        [string]$specificationUrl,
        [Parameter(Mandatory=$true, Position=8)]
        [string]$apiPath,
        [Parameter(Mandatory=$true, Position=9)]
        [string]$functionName,
        [Parameter(Mandatory=$true, Position=10)]
        [string]$productId,
        [Parameter(Mandatory=$true, Position=11)]
        [string]$resourceGroupName_FnApp,
        [Parameter(Mandatory=$true, Position=12)]
        [string]$subscriptionId,
        [Parameter(Mandatory=$true, Position=13)]
        [array]$APITags,
        [Parameter(Mandatory=$true, Position=14)]
        [string]$app_clientId,
        [Parameter(Mandatory=$true, Position=15)]
        [string]$client_secret,
        [Parameter(Mandatory=$true, Position=16)]
        [string]$APIMUrl,
        [Parameter(Mandatory=$true, Position=17)]
        [string]$Environment,
        [Parameter(Position=18)]
        [string]$APIOutboundOperations
    )

    $OPSPolicyFile=''
    $functionKeyName = "$functionName-key"
    #$inboundpolicy ='<policies><inbound><base /><set-header name="x-functions-key" exists-action="append"><value>{{'+$functionKeyName+'}}</value></set-header></inbound></policies>'
    if ($APIOutboundOperations -eq 'ALL' ){
        $GlobalPolicyFile = 'APIM-Inbound-Policy.xml' 
    }
    elseif ($APIOutboundOperations -ne 'None' ){
        $OPSPolicyFile = 'APIM-Inbound-Policy-JWT-Validation-Only.xml' 
        $GlobalPolicyFile = 'APIM-Inbound-Policy-No-JWT-Validation.xml' 
    }
    else {
        $GlobalPolicyFile = 'APIM-Inbound-Policy-No-JWT-Validation.xml' 
    }
    write-output "Global Policy file to apply Files\$GlobalPolicyFile"
    $globalinboundpolicy = CreateAPIMPolicy "Files\$GlobalPolicyFile" $functionKeyName $app_clientId $APIMUrl |out-string
    write-output "OPS Policy file to apply Files\$OPSPolicyFile"
    if ($OPSPolicyFile -ne '') {
        $opsinboundpolicy = CreateAPIMPolicy "Files\$OPSPolicyFile" $functionKeyName $app_clientId $APIMUrl |out-string
        #write-output $opsinboundpolicy
        }

    #$pwd = ConvertTo-SecureString $password -AsPlainText -Force
    #$pc = New-Object System.Management.Automation.PSCredential($userId,$pwd)

    #write-output "Connecting to Azure..."
    #$profile = Connect-AzAccount -Credential $pc -Subscription $subscriptionId

    write-output "Retrieve access token.."
    $c = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($c.Account, $c.Environment, $c.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://management.azure.com").AccessToken

    write-output "Retrieving Azure context..."
    $context = New-AzApiManagementContext -ResourceGroupName $resourceGroupName_APIM -ServiceName $serviceName

    Write-Output "Retrieving function keys.."

    #$token =  ($profile.Context.TokenCache.ReadItems() | where-object{$_.DisplayableId -eq $userId}|Select AccessToken).AccessToken
    $functionKey = GetFunctionKey $subscriptionId $resourceGroupName_FnApp $functionName $token

    Write-Output "Checking if function key exists...$functionKeyName"
    #$namedValue = Get-AzApiManagementProperty -Context $context -Name $functionKeyName
    $namedValue = Get-AzApiManagementNamedValue -Context $context -Name $functionKeyName 

    Write-Output "Save swagger definition to file.."
    $swaggerFile = "swagger.json"
    $tbody = "grant_type=client_credentials&client_id="+$app_clientid+"&client_secret="+$client_secret+"&scope="+$app_clientId+"/.default&roles=Read"
    $tresponse = Invoke-RestMethod 'https://login.microsoftonline.com/'+$c.Tenant.Id.ToString()+'/oauth2/v2.0/token' -Method 'POST' -Headers @{"Content-Type"="application/x-www-form-urlencoded"} -Body $tbody
    $t = $tresponse.access_token -replace "`n|`r"
    $swagger = Invoke-Restmethod $specificationUrl"?code="$functionKey -Headers @{ Authorization="Bearer "+$t; "Content-Type"="application/json"} |ConvertTo-Json -Depth 100
    $swaggerMod = $swagger |ConvertFrom-Json
    $swaggerMod.info.Title = $Environment+" "+$swaggerMod.info.title
    $newSwagger =$swaggerMod |ConvertTo-Json -Depth 100
    [io.file]::WriteAllLines($swaggerFile,$newSwagger)

    if ([string]::IsNullOrEmpty($namedValue)){
        Write-Output "Creating named value for function key..."
        $tags = "key", "function", "auto"
        #New-AzApiManagementProperty -Context $context -Name $functionKeyName -Value $functionKey -Secret -PropertyId $functionKeyName -Tag $tags | Out-Null
        New-AzApiManagementNamedValue -Context $context -Name $functionKeyName -Value $functionKey -Secret -NamedValueId $functionKeyName -Tag $tags | Out-Null
    }

    Write-Output "Versioning required?..$isVersioned"
    if ($isVersioned){
        $versionSetExists = GetVersionSet $context $apiVersionSetId
        if ($versionSetExists -eq '0'){
            write-output "Creating new API version set..."
            New-AzApiManagementApiVersionSet -Context $context -Name $apiVersionSetName -Scheme Segment -ApiVersionSetId $apiVersionSetId | Out-null
        }

        write-output "Getting API version..."
        $apiVersion = GetNextAPIVersion $context $apiName
        $apiId = $apiVersionSetName+"-"+$apiVersion

        write-output "Importing Api version $apiVersion...."
        Import-AzApiManagementApi -Context $context -SpecificationFormat OpenApi -SpecificationPath $swaggerFile -Path $apiPath -ApiVersion $apiVersion -ApiId $apiId -ApiVersionSetId $apiVersionSetId | Out-null
    }
    else
    {
        write-output "Importing Api..."
        #write-output $specificationUrl"?code="$functionKey
        $apiId=$apiName
        #$apiSpecification = (Get-AzApiManagementApi -Context $context) | Where-Object { $_.APiId -eq  $apiId}
        $ApiRevision = (Get-AzApiManagementApiRevision -Context $context -ApiId $apiId |measure-object -Property ApiRevision -Maximum).Maximum
        if ([string]::IsNullOrEmpty($ApiRevision )){
            $ApiRevision = 1   
        }
        else {
            $ApiRevision = $ApiRevision+1
        }
        Import-AzApiManagementApi -Context $context -SpecificationFormat OpenApi -SpecificationPath $swaggerFile -Path $apiPath -ApiId $apiId -ApiRevision $ApiRevision | Out-null    
        if([int]$ApiRevision -gt 1){
            New-AzApiManagementApiRelease -Context $context -ApiId $apiId -ApiRevision $ApiRevision
        }
        #Import-AzApiManagementApi -Context $context -SpecificationFormat OpenApi -SpecificationUrl $specificationUrl"?code="$functionKey -Path $apiPath -ApiId $apiId | Out-null    
    }

    write-output "Tagging API..."
    TagAPI -subscriptionId $subscriptionId -resourceGroupName_APIM $resourceGroupName_APIM -APIMName $serviceName -apiId $apiId -accessToken $token -tags $APITags

    write-output "Updating Global inbound policy for Api..."
    Set-AzApiManagementPolicy -Context $context  -Policy $globalinboundpolicy -ApiId $apiId | Out-null
     if ($OPSPolicyFile -ne ''){
        foreach($OperationId in $APIOutboundOperations){
            write-output "Updating OPS inbound policy for Api...$OperationId"
            Set-AzApiManagementPolicy -Context $context  -Policy $opsinboundpolicy -ApiId $apiId -OperationId $OperationId | Out-null
        }
    }


    write-output "Adding Api to product..."
    Add-AzApiManagementApiToProduct -Context $context -ApiId $apiId -ProductId $productId | Out-null

    #write-output "Logging out from Azure..."
    #Disconnect-AzAccount -Scope CurrentUser | Out-null
    write-output "Import complete.."
}

ImportFunction -resourceGroupName_APIM $resourceGroupName_APIM -serviceName $serviceName -isVersioned $isVersioned -apiVersionSetName $apiVersionSetName -apiVersionSetId $apiVersionSetId -apiName $apiName -specificationUrl $specificationUrl -apiPath $apiPath -functionName $functionName -productId $productId -resourceGroupName_FnApp $resourceGroupName_FnApp -subscriptionId $subscriptionId -ApiTags $APITags -app_clientId $app_clientId -client_secret $client_secret -APIMUrl $APIMUrl -Environment $environment -APIOutboundOperations $APIOutboundOperations

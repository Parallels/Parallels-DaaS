<#
.SYNOPSIS
    Script to prepare a Microsoft Azure subscription for use with Parallels DaaS // Desktop-as-a-Service
.DESCRIPTION
    The script will ask for Azure Tenant ID, Subscription ID, App name, location, infrastructure resource group name,
    Virtual machines resource group name and Keyvault. It outputs the information needed to be passed in Parallels DaaS administrative portal during initial setup.
.PARAMETER
    None, all parameters are collected at runtime.
.OUTPUTS
    - Azure Tenant ID
    - Azure Subscription ID
    - Application client ID
    - Client secrect value (stored in KeyVault)
    - Infrastructure resource group name
    - Virtual machines resource group name
.NOTES
    Copyright © 2024 Parallels International GmbH. All rights reserved.
    Version: 1.0
    Authors: Freek Berson, Sergii Shepelenko, John Zammit, Vasilis Koutsomanis, Mark Plettenberg
    Last update: 20/03/24
    Changelog:  1.0 - Initial published version
.LICENSE
    Released under the terms of MIT license (see LICENSE for details)
#>

# Check the PowerShell version
if ($PSVersionTable.PSVersion -lt [Version]"7.3") {
    Write-host "Please execute with PowerShell version 7.3 or above" -ForegroundColor Red
    exit
}

param([string]$localEnvJson = "")

function import-AzureModule {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    # Check if the module is already imported
    $module = Get-Module -Name $ModuleName -ListAvailable
    if (-not $module) {
        Write-Host "Required module '$ModuleName' is not imported. Installing and importing..."
        # Install the module if not already installed
        if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force
        }
        # Import the module
        Import-Module -Name $ModuleName -Force
    }
}

function set-AzureTenant {
    # Retrieve Azure tenants
    $tenants = Get-AzTenant

    # Display the list of tenants and prompt the user to select one
    $i = 1
    $selectedTenant = $null

    Write-Host "Azure Tenants:" -ForegroundColor Yellow
    foreach ($tenant in $tenants) {
        Write-Host "$i. $($tenant.Name) - $($tenant.TenantId)"
        $i++
    }

    $validSelection = $false
    while (-not $validSelection) {
        $selection = Read-Host ('>> Select a tenant by entering the corresponding number')

        if ($selection -match '^\d+$') {
            $selection = [int]$selection
            if ($selection -ge 1 -and $selection -le $tenants.Count) {
                $validSelection = $true
            }
        }

        if (-not $validSelection) {
            Write-Host "Invalid input. Please enter a valid number between 1 and $($tenants.Count)" -ForegroundColor Red
        }
    }

    $selectedTenant = $tenants[$selection - 1]

    # Store the selected tenant ID in tenantId variable
    $tenantId = $selectedTenant.TenantId

    Write-Host "Selected Tenant ID: $tenantId`n" -ForegroundColor Green

    # Return the selected tenant ID
    return $tenantId
}

function set-AzureSubscription {
    # Check if the user is authenticated
    if (-not (Get-AzContext)) {
        Write-Host "Failed to authenticate against Azure. Please check your credentials and try again."
        return
    }

    $warnings = @()

    Write-Host "Getting subscriptions from selected tenant $selectedTenantId"
    # Get the list of Azure subscriptions
    $subscriptions = Get-AzSubscription -TenantId $selectedTenantId -WarningVariable warnings

    if ($warnings.Count -gt 0) {
        Write-Host "MFA authentication is required. Reconnecting to the selected tenant"
        $currentUser = Connect-AzAccount -TenantId $selectedTenantId -AuthScope MicrosoftGraphEndpointResourceId
        $subscriptions = Get-AzSubscription -TenantId $selectedTenantId
    }

    # Check if the user has access to any subscriptions
    if ($subscriptions) {
        # Display the list of subscriptions and prompt the user to select one
        $i = 1
        $selectedSubscription = $null

        Write-Host "Azure Subscriptions:" -ForegroundColor Yellow
        foreach ($subscription in $subscriptions) {
            Write-Host "$i. $($subscription.Name) - $($subscription.Id)"
            $i++
        }

        $validSelection = $false
        while (-not $validSelection) {
            $selection = Read-Host ('>> Select a subscription by entering the corresponding number')

            if ($selection -match '^\d+$') {
                $selection = [int]$selection
                if ($selection -ge 1 -and $selection -le $subscriptions.Count) {
                    $validSelection = $true
                }
            }

            if (-not $validSelection) {
                Write-Host "Invalid input. Please enter a valid number between 1 and $($subscriptions.Count)" -ForegroundColor Red
            }
        }

        $selectedSubscription = $subscriptions[$selection - 1]

        # Store the selected subscription ID in subscriptionId variable
        $subscriptionId = $selectedSubscription.Id

        Write-Host "Selected Subscription ID: $subscriptionId`n" -ForegroundColor Green

        Set-AzContext -SubscriptionId $subscriptionId

        # Return the selected subscription object
        return $selectedSubscription
    }
    else {
        Write-Host "You do not have access to any Azure subscriptions."
    }
}

function set-AzureLocation {

    # Retrieve Azure locations
    $locations = @(Get-AzLocation | Where-Object { $_.Providers -contains "Microsoft.Network" -and $_.Providers -contains "Microsoft.Compute" } | Select-Object -ExpandProperty Location | Sort-Object)

    # Display the list of locations and prompt the user to select one
    $selectedLocation = $null

    # Determine the number of columns for display
    $columnCount = 3
    $rowCount = [Math]::Ceiling($locations.Count / $columnCount)

    # Display the list of locations in multiple columns
    Write-Host "Azure Locations:" -ForegroundColor Yellow

    for ($row = 0; $row -lt $rowCount; $row++) {
        for ($col = 0; $col -lt $columnCount; $col++) {
            $index = $row + ($col * $rowCount)

            if ($index -lt $locations.Count) {
                $location = $locations[$index]
                $label = ($index + 1).ToString().PadRight(3)

                Write-Host "$label. $location" -NoNewline

                $padding = 20 - $location.Length
                Write-Host (" " * $padding) -NoNewline
            }
        }

        # Stop if the total count is reached
        if ($index -eq $locations.Count - 1) {
            break
        }

        Write-Host
    }
    Write-Host `n

    $validSelection = $false
    while (-not $validSelection) {
        $selection = Read-Host ('>> Select the location of where you want to deploy the resources')
        if ($selection -match '^\d+$') {
            $selection = [int]$selection
            if ($selection -ge 1 -and $selection -le $locations.Count) {
                $validSelection = $true
                $selectedLocation = $locations[$selection - 1]
                Write-Host "Selected Location: $selectedLocation" -ForegroundColor Green
                return $selectedLocation
            }
        }
        if (-not $validSelection) {
            Write-Host "Invalid input. Please enter location number between 1 and $($locations.Count)" -ForegroundColor Red
        }
    }
}

function create-CustomRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )
    #Create custom role definition
    $existingRoleDefinition = Get-AzRoleDefinition -Name $RoleName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($null -eq $existingRoleDefinition) {
        $role = Get-AzRoleDefinition "Virtual Machine Contributor"
        $role.Id = $null
        $role.Name = $RoleName
        $role.Description = "Custom role for managing access and operational settings in DaaS environment"
        $role.Actions.Clear()
        $role.Actions.Add("Microsoft.Authorization/roleAssignments/write")
        $role.Actions.Add("Microsoft.Authorization/roleAssignments/delete")
        $role.Actions.Add("Microsoft.Quota/quotas/read")
        $role.AssignableScopes.clear()
        $role.AssignableScopes.Add("/subscriptions/$SubscriptionId")
        New-AzRoleDefinition -Role $role | Out-Null
    }
}

function add-AppRegistrationToCustomRole {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectId,

        [Parameter(Mandatory = $true)]
        [string]$SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]$RoleName
    )
    # Assign VM Reader role to the app registration at the subscription level
    New-AzRoleAssignment -ObjectId $ObjectId -RoleDefinitionName $RoleName -Scope "/subscriptions/$SubscriptionId" | Out-Null
}

function new-AzureAppRegistration {
    $validAppName = $false
    $invalidChars = @('<', '>', ';', '&', '%')

    Write-Host `n"App registrations:" -ForegroundColor Yellow

    while (-not $validAppName) {
        $appName = Read-Host '>> Provide the App Registration name'

        if (-not [string]::IsNullOrWhiteSpace($appName) -and $appName.Length -gt 0) {
            if ($appName.Length -le 120) {
                $containsInvalidChars = $false
                foreach ($invalidChar in $invalidChars) {
                    if ($appName.Contains($invalidChar)) {
                        $containsInvalidChars = $true
                        break
                    }
                }

                if (-not $containsInvalidChars) {
                    # Check if the app name already exists
                    $existingAppName = Get-AzADApplication | Where-Object { $_.DisplayName -eq $appName }
                    if ($existingAppName) {
                        Write-Host "The provided App Registration name already exists. Please provide a different name." -ForegroundColor Red
                    }
                    else {
                        $validAppName = $true
                    }
                }
                else {
                    Write-Host "The provided App Registration name contains invalid characters. Please avoid using <, >, ;, &, or %." -ForegroundColor Red
                }
            }
            else {
                Write-Host "The provided App Registration name exceeds the maximum allowed length of 120 characters." -ForegroundColor Red
            }
        }
        else {
            Write-Host "The App Registration name cannot be empty or have a length of 0." -ForegroundColor Red
        }
    }

    $ADServicePrincipal = Get-AzADServicePrincipal -DisplayName $appName
    if ($null -ne $ADServicePrincipal) {
        Write-Host "AD Service Principal with name '$appName' already exists. Please choose a different name."
        return
    }

    if (!($myApp = Get-AzADServicePrincipal -DisplayName $appName -ErrorAction SilentlyContinue)) {
        $myApp = New-AzADServicePrincipal -DisplayName $appName
    }
    return (Get-AzADServicePrincipal -DisplayName $appName)
}

function new-AzureADAppClientSecret {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [string]$applicationID
    )

    # Get the ObjectId of the application based on the AppId
    $appObjectId = (Get-AzADApplication -Filter "AppId eq '$applicationID'").Id

    # Get the KeyId of the password credential where CustomKeyIdentifier is null
    $credentialKeyId = (Get-AzADAppCredential -ObjectId $appObjectId | Where-Object CustomKeyIdentifier -eq $null).KeyId

    # Remove the password credential based on the KeyId
    Remove-AzADAppCredential -ObjectId $appObjectId -KeyId $credentialKeyId


    $secretStartDate = Get-Date
    $secretEndDate = $secretStartDate.AddYears(1)
    $webApiSecret = New-AzADAppCredential -StartDate $secretStartDate -EndDate $secretEndDate -ApplicationId $applicationID -CustomKeyIdentifier ([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("DaaS secret")))
    return $webApiSecret
}

function new-AzureResourceGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$resourceGroupLocation
    )

    $validResourceGroupName = $false

    while (-not $validResourceGroupName) {
        $resourceGroupName = Read-Host '>> Provide the name:'

        if (-not [string]::IsNullOrWhiteSpace($resourceGroupName)) {
            if ($resourceGroupName -match '^[A-Za-z0-9_-]+$' -and $resourceGroupName.Length -le 90) {
                # Check if the resource group already exists
                $existingResourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue

                if ($existingResourceGroup) {
                    $validInput = $false
                    while (!$validInput) {
                        $confirm = Read-Host "The resource group '$resourceGroupName' already exists. Do you want to use it? (Y/N)"
                        if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                            $validInput = $true
                            $validResourceGroupName = $true
                        }
                        elseif ($confirm -eq 'N' -or $confirm -eq 'n') {
                            $validInput = $true
                            $validResourceGroupName = $false
                        }
                        else {
                            Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor red
                        }
                    }
                }
                else {
                    $validResourceGroupName = $true
                }
            }
            else {
                Write-Host "The provided resource group name contains invalid characters, or is too long. Please use only alphanumeric characters, hyphens, underscores, and up to 90 characters." -ForegroundColor Red
            }
        }
        else {
            Write-Host "The resource group name cannot be empty." -ForegroundColor Red
        }
    }

    # Check if the resource group already exists
    $existingResourceGroup = Get-AzResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue

    if ($existingResourceGroup) {
        # Return the existing resource group
        return $existingResourceGroup
    }
    else {
        # Create the resource group since it doesn't exist
        $resourceGroup = New-AzResourceGroup -Name $resourceGroupName -Location $resourceGroupLocation -Force
        return $resourceGroup
    }
}

function new-AzureKeyVaultWithSecret {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]$Location,

        [Parameter(Mandatory = $true)]
        [string]$SecretValue,

        [Parameter(Mandatory = $true)]
        [string]$SecretName,

        [Parameter(Mandatory = $true)]
        [string]$SubsciptionID
    )

    Write-Host `n"Azure Keyvault:" -ForegroundColor Yellow

    # Prompt the user to enter the Key Vault name and validate it
    $validSelection = $false
    while (-not $validSelection) {
        $KeyVaultName = Read-Host ">> Enter the name for the new Azure Key Vault to store secrets"
        if ($KeyVaultName -match '^[A-Za-z][\w-]{1,22}[A-Za-z0-9]$') {
            $validSelection = $true
        }

        if (-not $validSelection) {
            Write-Host "Invalid Key Vault name. Key Vault names must be between 3 and 24 characters in length. They must begin with a letter, end with a letter or digit, and contain only alphanumeric characters and dashes. Consecutive dashes are not allowed." -ForegroundColor Red
        }
    }

    Set-AzContext -SubscriptionId $SubsciptionID

    # Check if the Key Vault already exists
    $existingKeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue

    if ($existingKeyVault) {
        # Key Vault already exists
        $useExisting = Read-Host "A Key Vault with the name '$KeyVaultName' already exists. Do you want to use the existing Key Vault? (Y/N)"
        if ($useExisting -eq 'Y') {
            Write-Output "Using the existing Key Vault '$KeyVaultName'."
            $keyVault = $existingKeyVault
        }
        else {
            Write-Output "Aborting operation."
            return
        }
    }
    else {
        # Create a new Key Vault
        $keyVault = New-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -Location $Location
    }

    # Add the secret to the Key Vault
    $secret = ConvertTo-SecureString -String $SecretValue -AsPlainText -Force
    Set-AzKeyVaultSecret -VaultName $KeyVault.VaultName  -Name $SecretName -SecretValue $secret | Out-Null
    Write-Host "Added a new secret with the name $($SecretName) to the Key Vault $($KeyVaultName.VaultName)." -ForegroundColor Green

    return $KeyVaultName
}

function set-AdminConsent {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $Context = Get-AzContext

    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $context.Account, $context.Environment, $TenantId, $null, "Never", $null, "74658136-14ec-4630-ad9b-26e160ff0fc6")

    $headers = @{
        'Authorization'          = 'Bearer ' + $token.AccessToken
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$ApplicationId/Consent?onBehalfOfAll=true"
    Invoke-RestMethod -Uri $url -Headers $headers -Method POST -ErrorAction Stop
}

function add-AzureAppRegistrationPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]$appName,

        [Parameter(Mandatory = $false)]
        [string]$localEnvJson
    )
    # Get the app registration
    $applicationID = (Get-AzADApplication -Filter "displayName eq '$appName'").AppId

    $apiId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph's API ID

    # Get the Microsoft Graph Service Principal
    $graphSP = Get-AzADServicePrincipal -Filter "displayName eq 'Microsoft Graph'"

    # Define the desired permissions
    $desiredApplicationPermissions = @(
        "User.Read.All",
        "Domain.Read.All",
        "GroupMember.Read.All",
        "Application.Read.All"
    )

    # Iterate over the desired permissions and add them to your application
    foreach ($permissionValue in $desiredApplicationPermissions) {
        $permissionId = ($graphSP.AppRole | Where-Object { $_.Value -eq $permissionValue }).Id
        if ($permissionId) {
            Add-AzADAppPermission -ApplicationId $applicationID -ApiId $apiId -PermissionId $permissionId -Type Role
            Write-Host "Added permission: $permissionValue with ID: $permissionId"
        }
        else {
            Write-Host "Failed to find application permission: $permissionValue"
        }
    }

    $desiredDelegatedPermissions = @(
        "email",
        "openid",
        "profile",
        "Group.Read.All"
    )

    # Iterate over the desired delegated permissions and add them to your application
    foreach ($permissionValue in $desiredDelegatedPermissions) {
        $permissionId = ($graphSP.Oauth2PermissionScope | Where-Object { $_.Value -eq $permissionValue }).Id
        if ($permissionId) {
            Add-AzADAppPermission -ApplicationId $applicationID -ApiId $apiId -PermissionId $permissionId -Type Scope
            Write-Host "Added permission: $permissionValue with ID: $permissionId"
        }
        else {
            Write-Host "Failed to find delegated permission: $permissionValue"
        }
    }

    $optionalClaimsJson = @"
        {
         "idToken": [
            {
                "name": "upn"
            },
            {
                "name": "email"
            },
            {
                "name": "groups"
            },
            {
                "name": "login_hint"
            }
        ],
        "accessToken": [
            {
                "name": "groups"
            }
        ],
        "saml2Token": [
            {
                "name": "groups"
            }
        ]
    }
"@

    $authenticationJson = @"
        {
            "RedirectUri": [
                "https://daas.parallels.com/discovery",
                "https://daas.parallels.com/signin-oidc",
                "https://daas.parallels.com/admin/login"
            ]
        }
"@
    if ($localEnvJson.Length -gt 0) {
        $authenticationJson = $localEnvJson
    }


    $AppReg = Get-AzADApplication -Filter "displayName eq '$appName'"
    $WebData = $AppReg.Web | ConvertFrom-Json
    $WebData.implicitGrantSettings.enableIdTokenIssuance = $true
    $JsonOutput = $WebData | ConvertTo-Json
    $AppReg | Update-AzADApplication -Web $JsonOutput

    # add optionalclaims to application
    $AppReg | Update-AzADApplication  -OptionalClaim $optionalClaimsJson
    # add logout url to application
    $authenticationObj = $authenticationJson | ConvertFrom-Json -AsHashtable
    $AppReg | Update-AzADApplication -Web $authenticationObj
    $AppReg | Update-AzADApplication -GroupMembershipClaim "SecurityGroup"
}

Clear-Host

# Check and import the required Azure PowerShell module
try {
    import-AzureModule "Az.Accounts"
    import-AzureModule "Az.Resources"
    import-AzureModule "Az.keyVault"
}
Catch {
    Write-Host "ERROR: trying to import required modules import Az.Accounts, Az.Resources, and Az.keyVault"
    Write-Host $_.Exception.Message
    exit
}

# Connect to Azure account
try {
    $currentUser = Connect-AzAccount -AuthScope MicrosoftGraphEndpointResourceId
}
Catch {
    Write-Host "ERROR: trying to run Connect-AzAccount"
    Write-Host $_.Exception.Message
    exit
}

# Set Tenant
try {
    $selectedTenantId = set-AzureTenant
}
Catch {
    Write-Host "ERROR: trying to get Azure Tenants"
    Write-Host $_.Exception.Message
    exit
}

# Provide list of available Azure subscriptions and allow setting active subscription
try {
    $selectedSubscriptionID = (set-AzureSubscription).Id
}
Catch {
    Write-Host "ERROR: trying to set Azure subscription"
    Write-Host $_.Exception.Message
    exit
}

# Provide list of available Azure locations and allow setting active location
try {
    $selectedAzureLocation = set-AzureLocation
}
Catch {
    Write-Host "ERROR: trying to get Azure Location"
    Write-Host $_.Exception.Message
    exit
}

# Register the required Azure resource providers
try {
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Network"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Compute"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Quota"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.DesktopVirtualization"
}
Catch {
    Write-Host "ERROR: trying to register required Azure resource providers"
    Write-Host $_.Exception.Message
    exit
}

# Create a custom role to allow adding and deleting role assinments
try {
    create-CustomRole -SubscriptionId $selectedSubscriptionID -RoleName "Parallels Daas Role"
}
Catch {
    Write-Host "ERROR: creating custom role to allow adding and deleting role assinments"
    Write-Host $_.Exception.Message
    exit
}

# Prompt for the resource group name, create the Resource Group and add the app registration contributor permissions
try {
    Write-Host "Azure Resource Group for the Infrastructure:" -ForegroundColor Yellow
    $rgInfra = new-AzureResourceGroup -resourceGroupLocation $selectedAzureLocation
    Write-Host "Resource Group name: "$rgInfra.ResourceGroupName -ForegroundColor Green
}
Catch {
    Write-Host "ERROR: trying to create the resource group and set contributor permissions"
    Write-Host $_.Exception.Message
    exit
}

# Prompt for the resource group name, create the Resource Group and add the app registration contributor permissions
try {
    Write-Host "Azure Resource Group for the Virtual Machines:" -ForegroundColor Yellow
    $rgVms = new-AzureResourceGroup -resourceGroupLocation $selectedAzureLocation
    Write-Host "Resource Group name: "$rgVms.ResourceGroupName -ForegroundColor Green
}
Catch {
    Write-Host "ERROR: trying to create the resource group and set contributor permissions"
    Write-Host $_.Exception.Message
    exit
}

# Prompt for the app name and create the app registration
try {
    $app = new-AzureAppRegistration
    Write-Host "App registration name: "$app.DisplayName -ForegroundColor Green
}
Catch {
    Write-Host "ERROR: trying to create the App Registration"
    Write-Host $_.Exception.Message
    exit
}

# Assign Contributor role to the app registration on Infrastructure RG
try {
    New-AzRoleAssignment -ObjectId $app.Id -RoleDefinitionName "Contributor" -Scope $rgInfra.ResourceId | Out-Null
}
Catch {
    Write-Host "ERROR: trying to assign contributor role to the app registration on Infrastructure RG"
    Write-Host $_.Exception.Message
    exit
}

# Assign Contributor role to the app registration on VMs RG
try {
    New-AzRoleAssignment -ObjectId $app.Id -RoleDefinitionName "Contributor" -Scope $rgVms.ResourceId | Out-Null
}
Catch {
    Write-Host "ERROR: trying to assign contributor role to the app registration on VMs RG"
    Write-Host $_.Exception.Message
    exit
}

# Set the required Graph API permissions on the created app registration
try {
    add-AzureAppRegistrationPermissions -appName $app.DisplayName -localEnvJson $localEnvJson
}
Catch {
    Write-Host "ERROR: trying to set app registration Graph API permissions"
    Write-Host $_.Exception.Message
    exit
}

# Create a client secret on the app registration and capture the secret key
try {
    $secret = new-AzureADAppClientSecret -TenantId $selectedTenantId -applicationID $app.AppId
}
Catch {
    Write-Host "ERROR: trying to create the App Registration client secret"
    Write-Host $_.Exception.Message
    exit
}

# Add DaaS Role Assignment Role permission on subscription to the app registration
try {
    add-AppRegistrationToCustomRole -objectId $app.Id -SubscriptionId $selectedSubscriptionID -RoleName "Parallels Daas Role"
}
Catch {
    Write-Host "ERROR: trying to set User Access Administration role"
    WWrite-Host $_.Exception.Message
    exit
}

# Grant admin consent to an the app registration
try {
    set-AdminConsent -ApplicationId $app.AppId -TenantId $selectedTenantId
}
Catch {
    Write-Host "ERROR: trying to grant admin consent to an the app registration"
    Write-Host $_.Exception.Message
    exit
}

# Add an Azure Keyvault and store the Client Secret in it
try {
    $selectedKeyVaultName = new-AzureKeyVaultWithSecret -ResourceGroupName $rgInfra.ResourceGroupName -Location $selectedAzureLocation -SecretValue $secret.SecretText -SecretName "daas-spn-client-secret" -SubsciptionID $selectedSubscriptionID
}
Catch {
    Write-Host "ERROR: trying to create a new Azure KeyVault and adding the client secret"
    Write-Host $_.Exception.Message
    exit
}

#Create summary information
Write-Host "`n* App registration created, permissions configured and secret created." -ForegroundColor Cyan
Write-host "* Below is the information that has to be provided via Parallels DaaS portal!" -ForegroundColor Cyan
Write-Host "1. Tenant ID: "$selectedTenantId
Write-Host "2. Subscription ID: "$selectedSubscriptionID
Write-Host "3. Application(client) ID: "$app.AppId
Write-Host "4. Client secret value stored in KV "$selectedKeyVaultName
Write-Host "5. Infrastructure resource group name: "$rgInfra.ResourceGroupName
Write-Host "6. VMs resource group name: "$rgVms.ResourceGroupName

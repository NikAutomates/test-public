$token_response = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
$secure_token = $token_response.Token
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_token)
$azure_token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)

# Get Graph token for group creation and PIM policy settings
$graph_token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/07dd2703-e92c-46c0-a5d8-9586bd4bac95/oauth2/v2.0/token" `
    -Method POST `
    -Body @{
        client_id     = "0cf25843-45b2-46e2-a142-b057712d79f0"
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
        client_secret = ""
    }
).access_token

$headers = @{
    Authorization  = "Bearer $($azure_token)"
    "Content-Type" = "application/json"
}

$lookup_table = @(
    @{
        ResourceName = "test-sub-1"
        RoleName     = "Contributor"
        UsePIM       = $true
        Members      = @("nik.chikersal@azurecloudsecurity.com", "eric.williams@automateyourpowershell.com")
    }
    @{
        ResourceName = "Terraform"
        RoleName     = "Reader"
        UsePIM       = $false
        Members      = @("nik.chikersal@azurecloudsecurity.com", "eric.williams@automateyourpowershell.com")
    }
)


foreach ($item in $lookup_table) {

    # --- reset per iteration ---
    $found_resource = $null
    $subscription_id = $null

    Write-Host "Resolving scope for $($item.ResourceName)..." -ForegroundColor Cyan

    # --- 1) MANAGEMENT GROUP ---
    $mg = (Invoke-RestMethod `
        -Uri "https://management.azure.com/providers/Microsoft.Management/managementGroups?api-version=2021-04-01" `
        -Method GET `
        -Headers $headers).value

    $mg_match = $mg | Where-Object { $_.name -eq $item.ResourceName -or $_.properties.displayName -eq $item.ResourceName }

    if ($mg_match) {
        $found_resource = "/providers/Microsoft.Management/managementGroups/$($mg_match.name)"
    }

    # --- 2) SUBSCRIPTION ---
    if (-not $found_resource) {
        $subs = (Invoke-RestMethod `
            -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
            -Method GET `
            -Headers $headers).value

        $sub_match = $subs | Where-Object { $_.displayName -eq $item.ResourceName -or $_.subscriptionId -eq $item.ResourceName }

        if ($sub_match) {
            $found_resource = "/subscriptions/$($sub_match.subscriptionId)"
        }
    }

    # --- 3) RESOURCE GROUP ---
    if (-not $found_resource) {

        $rg_query = @"
{
    "query": "ResourceContainers | where type == 'microsoft.resources/subscriptions/resourcegroups' and name =~ '$($item.ResourceName)' | project id"
}
"@

        $rg_result = (Invoke-RestMethod `
            -Uri "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" `
            -Method POST `
            -Headers $headers `
            -Body $rg_query).data

        if ($rg_result.Count -eq 1) {
            $found_resource = $rg_result[0].id
        }
        elseif ($rg_result.Count -gt 1) {
            throw "Multiple resource groups named '$($item.ResourceName)' found. Ambiguous. Stopping."
        }
    }

    # --- 4) RESOURCE EXACT ---
    if (-not $found_resource) {

        $resource_query = @"
{
    "query": "Resources | where name =~ '$($item.ResourceName)' | project id"
}
"@

        $resource_result = (Invoke-RestMethod `
            -Uri "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" `
            -Method POST `
            -Headers $headers `
            -Body $resource_query).data

        if ($resource_result.Count -eq 1) {
            $found_resource = $resource_result[0].id
        }
        elseif ($resource_result.Count -gt 1) {
            throw "Multiple resources named '$($item.ResourceName)' found. Ambiguous. Stopping."
        }
    }

    # --- HARD STOP IF NOT FOUND ---
    if (-not $found_resource) {
        throw "Scope '$($item.ResourceName)' not found as management group, subscription, resource group, or resource. Stopping."
    }

    Write-Host "Resolved scope: $found_resource" -ForegroundColor Green


















   
    
    switch ($item.UsePIM) {
        #IF PIM Group block
        $true {
            $group_name = "sec-pim-" + $item.ResourceName + "-" + $item.RoleName.Replace(" ", "-").ToLower()
            $group_exists = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($group_name)'" -Method GET -AccessToken $graph_token)

            #if group exists, add members to eligible assignment
            if ($group_exists.id) {
                foreach ($member in $item.Members) {
                    $user_object_id = Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users?`$filter=userprincipalname eq '$($member)'" -Method GET -AccessToken $graph_token
                        
                    #check if user already has eligible assignment to group
                    $existing_entra_group_id = ([string]$group_exists.id).Trim()
                    $existing_user_object_id = ([string]$user_object_id.id).Trim()
                    $existing_eligible_assignment = (Invoke-GraphAPIRequest `
  -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances?`$filter=groupId eq '$($existing_entra_group_id)'" `
  -Method GET `
  -AccessToken $graph_token).principalId -contains $existing_user_object_id
  
                    if ($existing_eligible_assignment -eq $false) {
                        #set eligible assignment for user to existing PIM Group
                        New-PIMForGroupsEligibleAssignment -EntraGroupID $existing_entra_group_id -PrincipalID $existing_user_object_id -AccessToken $graph_token -Verbose
                    }
                    else {
                        Write-Warning "User $($member) already has an eligible assignment to group $($group_name)"
                    }
                }
            }
            elseif (-not ($group_exists.id)) {
                #create PIM group
                $new_entra_group = New-EntraGroup -EntraGroupName $group_name.ToLower() -AccessToken $graph_token
                Start-Sleep -Seconds 10
                if ($new_entra_group) {
                    #enable PIM For groups on new group
                    Write-Host "Enabling PIM for Groups on $($new_entra_group.displayName)..." -ForegroundColor Green
                    Enable-EntraPIMGroup -EntraGroupID $new_entra_group.id -PIMActivationGroupID 'b74dfcb8-2a55-404f-ad45-00c14307e286' -AccessToken $graph_token | Out-Null

                    #get Azure Role ID for new PIM policy settings on Azure Role
                    $role_id = Get-AzureRoleGUID -RoleName $item.RoleName -AccessToken $azure_token

                    Write-Host "Creating PIM policy settings for $($new_entra_group.displayName)..." -ForegroundColor Green

                    #New PIM policy settings on the Azure Role
                    New-PIMAzureRoleSettingsRule -NotificationRecipients "test@pim.com" -RoleID $role_id -ResourceScopeID $found_resource -AccessToken $azure_token

                    Write-Host "Assigning $($new_entra_group.displayName) as an active assignment to Azure Role $($item.RoleName) on resource $($item.ResourceName)..." -ForegroundColor Green
                    #assign the PIM entra group as an active assignment on the Azure PIM Role
                    New-PIMAzureRoleActiveAssignment -EntraGroupID $new_entra_group.id -ResourceScopeID $found_resource -RoleID $role_id -AccessToken $azure_token
                    
                    Write-Host "Retrieving PIM policy IDs for $($new_entra_group.displayName)..." -ForegroundColor Green
                    #get owner and member policy IDs 
                    $pim_group_policy_ids = (Invoke-GraphAPIRequest `
                            -GraphURL "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '$($new_entra_group.id)' and scopeType eq 'Group'" `
                            -Method GET `
                            -AccessToken $graph_token).id 
                            

                    foreach ($pim_group_policy_id in $pim_group_policy_ids) {
                        #New PIM policy settings on the PIM Entra Group
                    
                        Write-Host "Creating PIM policy settings for $($new_entra_group.displayName)..." -ForegroundColor Green

                        function New-PIMGroupSettingsRule {
    param (
        [string]$RolePolicyID,
        [string]$NotificationRecipients,
        [string]$AccessToken
    )

    $headers = @{
        Authorization  = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }

    # --- RULE 1: Expiration_Admin_Eligibility ---
    $expiration_body = @"
{
  "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule",
  "id": "Expiration_Admin_Eligibility",
  "isExpirationRequired": false,
  "maximumDuration": "P0D",
  "target": {
    "caller": "Admin",
    "operations": [ "All" ],
    "level": "Eligibility",
    "targetObjects": [],
    "inheritableSettings": [],
    "enforcedSettings": []
  }
}
"@

    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$RolePolicyID/rules/Expiration_Admin_Eligibility" `
        -Method PATCH `
        -Headers $headers `
        -Body $expiration_body


    # --- RULE 2: Enablement_EndUser_Assignment ---
    $enablement_body = @"
{
  "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
  "id": "Enablement_EndUser_Assignment",
  "enabledRules": [ "MultiFactorAuthentication", "Justification" ],
  "target": {
    "caller": "EndUser",
    "operations": [ "All" ],
    "level": "Assignment",
    "targetObjects": [],
    "inheritableSettings": [],
    "enforcedSettings": []
  }
}
"@

    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$RolePolicyID/rules/Enablement_EndUser_Assignment" `
        -Method PATCH `
        -Headers $headers `
        -Body $enablement_body


    # --- RULE 3: Notification_Admin_Admin_Eligibility ---
    $notif_admin_admin_elig_body = @"
{
  "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
  "id": "Notification_Admin_Admin_Eligibility",
  "notificationType": "Email",
  "recipientType": "Admin",
  "notificationLevel": "All",
  "isDefaultRecipientsEnabled": true,
  "notificationRecipients": [ "$NotificationRecipients" ],
  "target": {
    "caller": "Admin",
    "operations": [ "All" ],
    "level": "Eligibility",
    "targetObjects": [],
    "inheritableSettings": [],
    "enforcedSettings": []
  }
}
"@

    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$RolePolicyID/rules/Notification_Admin_Admin_Eligibility" `
        -Method PATCH `
        -Headers $headers `
        -Body $notif_admin_admin_elig_body


    # --- RULE 4: Notification_Admin_Admin_Assignment ---
    $notif_admin_admin_assign_body = @"
{
  "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
  "id": "Notification_Admin_Admin_Assignment",
  "notificationType": "Email",
  "recipientType": "Admin",
  "notificationLevel": "All",
  "isDefaultRecipientsEnabled": true,
  "notificationRecipients": [ "$NotificationRecipients" ],
  "target": {
    "caller": "Admin",
    "operations": [ "All" ],
    "level": "Assignment",
    "targetObjects": [],
    "inheritableSettings": [],
    "enforcedSettings": []
  }
}
"@

    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$RolePolicyID/rules/Notification_Admin_Admin_Assignment" `
        -Method PATCH `
        -Headers $headers `
        -Body $notif_admin_admin_assign_body


    # --- RULE 5: Notification_Admin_EndUser_Assignment ---
    $notif_admin_enduser_assign_body = @"
{
  "@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule",
  "id": "Notification_Admin_EndUser_Assignment",
  "notificationType": "Email",
  "recipientType": "Admin",
  "notificationLevel": "All",
  "isDefaultRecipientsEnabled": true,
  "notificationRecipients": [ "$NotificationRecipients" ],
  "target": {
    "caller": "EndUser",
    "operations": [ "All" ],
    "level": "Assignment",
    "targetObjects": [],
    "inheritableSettings": [],
    "enforcedSettings": []
  }
}
"@

    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies/$RolePolicyID/rules/Notification_Admin_EndUser_Assignment" `
        -Method PATCH `
        -Headers $headers `
        -Body $notif_admin_enduser_assign_body
}
New-PIMGroupSettingsRule -RolePolicyID $pim_group_policy_id -NotificationRecipients "pim@test.com" -AccessToken $graph_token -verbose

                    }
                    
                    # Inline wait for PIM backend to finish provisioning the group
                    foreach ($member in $item.Members) {
                        $user_object_id = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users?`$filter=userprincipalname eq '$($member)'" -Method GET -AccessToken $graph_token).value.id
                    
                        #set eligible assignment for user to existing PIM Group
                        for ($i = 1; $i -le 5; $i++) {
                            try {
                                Write-Host "Assigning user $($member) as an eligible assignment to PIM Group $($new_entra_group.displayName)..." -ForegroundColor Green
                                New-PIMForGroupsEligibleAssignment `
                                    -EntraGroupID $new_entra_group.id `
                                    -PrincipalID $user_object_id `
                                    -AccessToken $graph_token `
                                    -ErrorAction Stop
                                break
                            }
                            catch {
                                Write-Warning "Eligible assignment failed (attempt $i). Retrying in 5s..."
                                Start-Sleep -Seconds 5
                            }
                        }
                    }
                }
            }
        } 
        $false {
            $group_name = "sec-" + $item.ResourceName + "-" + $item.RoleName.Replace(" ", "-").ToLower()
            $group_exists = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$($group_name)'" -Method GET -AccessToken $graph_token)

            #if group exists, add members to group
            if ($group_exists.id) {
              $existing_entra_group_id = ([string]$group_exists.id).Trim()
              $existing_user_object_id = ([string]$user_object_id).Trim()
              $user_object_id = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users?`$filter=userprincipalname eq '$($member)'" -Method GET -AccessToken $graph_token).value.id
              New-EntraGroupMember -EntraGroupID $existing_entra_group_id -EntraUserID $existing_user_object_id -AccessToken $graph_token
               
            }
            elseif (-not ($group_exists.id)) {
                #create PIM group
                $new_entra_group = New-EntraGroup -EntraGroupName $group_name.ToLower() -AccessToken $graph_token
                Start-Sleep -Seconds 15

                #assign the entra group as a direct assignment on the Azure Role
                if ($new_entra_group) {
                    foreach ($member in $item.Members) {
                        $user_object_id = (Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users?`$filter=userprincipalname eq '$($member)'" -Method GET -AccessToken $graph_token).value.id
                        New-EntraGroupMember -EntraGroupID $new_entra_group.id -EntraUserID $user_object_id -AccessToken $graph_token
                    }

                    $role_id = Get-AzureRoleGUID -RoleName $item.RoleName -AccessToken $azure_token

                    #assign the entra group as a direct assignment on the Azure Role
                    Start-Sleep -Seconds 15 #sleep added to mitigate potential timing issue with group creation and assignment
                    New-AzureRoleAssignment -EntraGroupID $new_entra_group.id -RoleID $role_id -ResourceScopeID $found_resource -AccessToken $azure_token
                    Write-Host "Assigning $($new_entra_group.displayName) as a direct assignment to Azure Role $($item.RoleName) on resource $($found_resource)..." -ForegroundColor Green

                }
            }
        }
    }
}
        

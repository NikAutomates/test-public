$token_response = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
$secure_token = $token_response.Token
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_token)
$azure_token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)

$graph_token = ""

function New-EntraGroup {
  param (
    [CmdletBinding()]

    [Parameter(Mandatory = $true)]
    [string]$EntraGroupName,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )
   
  begin {
 
    $new_entra_group = @" 
{
  "displayName": "$($EntraGroupName)",
  "mailEnabled": false,
  "mailNickname": "$($EntraGroupName)",
  "securityEnabled": true
}
"@
  }

  process {
    Invoke-GraphAPIRequest `
      -GraphURL "https://graph.microsoft.com/v1.0/groups" `
      -Method POST `
      -JsonBody $new_entra_group `
      -AccessToken $AccessToken
  }
}

function New-EntraGroupMember {
  param (
    [CmdletBinding()]
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [CmdletBinding()]
    [Parameter(Mandatory = $true)]
    [string]$EntraUserID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  begin {
   
    $new_entra_group_member = @"
{
  "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$($EntraUserID)"
}
"@
  }
  process {
    $member_of = Invoke-GraphAPIRequest -GraphURL "https://graph.microsoft.com/v1.0/users/$($EntraUserID)/memberOf" -Method 'GET' -AccessToken $AccessToken

    if ($member_of.id -contains $EntraGroupID) {
      Write-Warning "$($EntraUserID) is already in group $($EntraGroupID)"
      return
    }
    
    Invoke-GraphAPIRequest `
      -GraphURL "https://graph.microsoft.com/v1.0/groups/$($EntraGroupID)/members/`$ref" `
      -Method POST `
      -JsonBody $new_entra_group_member `
      -AccessToken $AccessToken
  }  
}

function Enable-EntraPIMGroup {
  param (
    [CmdletBinding()]
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [Parameter(Mandatory = $true)]
    [string]$PIMActivationGroupID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  $startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $enable_pim_for_groups = @"
{
  "accessId": "member",
  "principalId": "$($PIMActivationGroupID)",
  "groupId": "$($EntraGroupID)",
  "action": "adminAssign",
  "scheduleInfo": {
    "startDateTime": "$startTime",
    "expiration": {
      "type": "afterDuration",
      "duration": "PT5M"
    }
  },
  "justification": "Temporary 5-minute assignment of dummy group to enable PIM for Groups"
}
"@
  Invoke-GraphAPIRequest `
    -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests" `
    -Method POST `
    -JsonBody $enable_pim_for_groups `
    -AccessToken $AccessToken

}

function Get-EntraPIMGroup {
  param (
    [CmdletBinding()]
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [CmdletBinding()]
    [Parameter(Mandatory = $false)]
    [switch]$EligibleAssignment,
    [CmdletBinding()]
    [Parameter(Mandatory = $false)]
    [switch]$ActiveAssignment,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  ) 

  $pim_for_groups_assignment = (Invoke-GraphAPIRequest `
      -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$($EntraGroupID)'" `
      -Method GET `
      -AccessToken $AccessToken)


  $pim_for_groups_eligibility = (Invoke-GraphAPIRequest `
      -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$($EntraGroupID)'" `
      -Method GET `
      -AccessToken $AccessToken).value

  if ($ActiveAssignment -eq $true) {
    return $pim_for_groups_assignment
  }
  elseif ($EligibleAssignment -eq $true) {
    return $pim_for_groups_eligibility
  }
  else {
    return $pim_for_groups_assignment, $pim_for_groups_eligibility

  }
}


function Get-AzureRoleGUID {
  param (
    [Parameter(Mandatory = $false)]
    [string]$RoleName,
    [Parameter(Mandatory = $false)]
    [string]$AccessToken
  ) 

  $headers = @{
    Authorization  = "Bearer $($AccessToken)"
    "Content-Type" = "application/json"
  }

  $roles_and_guids_uri = "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
  return $((Invoke-RestMethod -Method 'GET' -Uri $roles_and_guids_uri -Headers $headers).value | Where-Object { $_.properties.RoleName -eq $($RoleName) }).name

}

function New-PIMAzureRoleActiveAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [Parameter(Mandatory = $true)]
    [string]$ResourceScopeID,
    [Parameter(Mandatory = $true)]
    [string]$RoleID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  $headers = @{
    Authorization  = "Bearer $($AccessToken)" 
    "Content-Type" = "application/json"
  }

 $azure_pim_role_active_assignment = @"
{
  "properties": {
    "principalId": "$($EntraGroupID)",
    "roleDefinitionId": "$($ResourceScopeID)/providers/Microsoft.Authorization/roleDefinitions/$($RoleID)",
    "requestType": "AdminAssign",
    "assignmentType": "Assigned",
    "justification": "Automated active assignment",
    "scheduleInfo": {
      "startDateTime": "$(Get-Date -Format o)",
      "expiration": {
        "type": "NoExpiration"
      }
    }
  }
}
"@

  $assignment_id = (New-Guid).Guid
  Start-Sleep -Seconds 10

  Invoke-RestMethod `
    -Uri "https://management.azure.com/$($ResourceScopeID)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$($assignment_id)?api-version=2020-10-01" `
    -Headers $headers `
    -Method PUT `
    -Body $azure_pim_role_active_assignment `
    -ContentType "application/json"
}

function New-AzureRoleAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [Parameter(Mandatory = $true)]
    [string]$ResourceScopeID,
    [Parameter(Mandatory = $true)]
    [string]$RoleID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  $headers = @{
    Authorization  = "Bearer $($AccessToken)"
    "Content-Type" = "application/json"
  }

  $body = @"
{
  "properties": {
    "principalId": "$($EntraGroupID)",
    "roleDefinitionId": "$($ResourceScopeID)/providers/Microsoft.Authorization/roleDefinitions/$($RoleID)"
  }
}
"@

  $assignment_id = (New-Guid).Guid

  Invoke-RestMethod `
    -Uri "https://management.azure.com/$($ResourceScopeID)/providers/Microsoft.Authorization/roleAssignments/$($assignment_id)?api-version=2022-04-01" `
    -Headers $headers `
    -Method PUT `
    -Body $body `
    -ContentType "application/json"
}

function New-PIMAzureRoleEligibleAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [Parameter(Mandatory = $true)]
    [string]$ResourceScopeID,
    [Parameter(Mandatory = $true)]
    [string]$RoleID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  $headers = @{
    Authorization  = "Bearer $($AccessToken)" 
    "Content-Type" = "application/json"
  }
  $azure_pim_role_eligible_assignment = @"
{
  "properties": {
    "principalId": "$($EntraGroupID)", 
    "roleDefinitionId": "$($ResourceScopeID)/providers/Microsoft.Authorization/roleDefinitions/$($RoleID)",
    "requestType": "AdminAssign",
    "scheduleInfo": {
      "startDateTime": "$(Get-Date -Format o)",
      "expiration": {
        "type": "NoExpiration"
      }
    }
  }
}
"@

  $assignment_id = (New-Guid).Guid
  Start-Sleep -Seconds 10
  Invoke-RestMethod `
    -Uri "https://management.azure.com/$($ResourceScopeID)/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$($assignment_id)?api-version=2020-10-01"`
    -Headers $headers `
    -Method PUT `
    -Body $azure_pim_role_eligible_assignment `
    -ContentType "application/json"
}


function New-PIMForGroupsEligibleAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,    
    [Parameter(Mandatory = $true)]
    [string]$PrincipalID,      
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )
  $pim_for_groups_group_eligible_member_assignment = @"
{
  "accessId": "member",
  "principalId": "$($PrincipalID)",
  "groupId": "$($EntraGroupID)",
  "action": "adminAssign",
  "scheduleInfo": {
    "startDateTime": "$(Get-Date -Format o)",
    "expiration": {
      "type": "NoExpiration"
    }
  },
  "justification": "Permanent eligible assignment"
}
"@
  Invoke-GraphAPIRequest `
    -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
    -Method POST `
    -JsonBody $pim_for_groups_group_eligible_member_assignment `
    -AccessToken $AccessToken
}

function Get-PIMAzureRoleEligibleAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,
    [Parameter(Mandatory = $false)]
    [string]$ResourceScopeID,
    [Parameter(Mandatory = $true)]
    [string]$RoleDefinitionID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )

  $headers = @{
    Authorization  = "Bearer $($AccessToken)" 
    "Content-Type" = "application/json"
  }


  (Invoke-RestMethod `
    -Uri "https://management.azure.com/$($ResourceScopeID)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01" `
    -Headers $headers `
    -Method GET).value.properties | Where-Object { $_.principalId -eq $EntraGroupID -and $_.roleDefinitionId.Split("roleDefinitions/")[1] -eq $RoleDefinitionID }

}

function New-PIMForGroupsEligibleAssignment {
  param (
    [Parameter(Mandatory = $true)]
    [string]$EntraGroupID,    
    [Parameter(Mandatory = $true)]
    [string]$PrincipalID,      
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )
  $pim_for_groups_group_eligible_member_assignment = @"
{
  "accessId": "member",
  "principalId": "$($PrincipalID)",
  "groupId": "$($EntraGroupID)",
  "action": "adminAssign",
  "scheduleInfo": {
    "startDateTime": "$(Get-Date -Format o)",
    "expiration": {
      "type": "NoExpiration"
    }
  },
  "justification": "Permanent eligible assignment"
}
"@
  Invoke-GraphAPIRequest `
    -GraphURL "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests" `
    -Method POST `
    -JsonBody $pim_for_groups_group_eligible_member_assignment `
    -AccessToken $AccessToken
}

$headers = @{
    Authorization  = "Bearer $($azure_token)"
    "Content-Type" = "application/json"
}

$lookup_table = @(
    @{
        ResourceName = "test-kv-001-az"
        RoleName     = "Contributor"
        UsePIM       = $true
        Members      = @("nik.chikersal@azurecloudsecurity.com", "eric.williams@automateyourpowershell.com")
    }
)
foreach ($item in $lookup_table) {
    $payload_exact = @"
{
    "query": "Resources | where name =~ '$($item.ResourceName)' | project name,id,type,subscriptionId,resourceGroup"
}
"@

    $resources_exact = (Invoke-RestMethod `
            -Uri "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" `
            -Method POST `
            -Headers $headers `
            -Body $payload_exact).data

    if ($resources_exact) {
        $found_resource = $resources_exact[0].id
    }

    if (-not $found_resource) {
        $payload_contains = @"
{
    "query": "Resources | where name contains '$($item.ResourceName)' | project name,id,type,subscriptionId,resourceGroup"
}
"@

        $resources_contains = (Invoke-RestMethod `
                -Uri "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01" `
                -Method POST `
                -Headers $headers `
                -Body $payload_contains).data

        if ($resources_contains) {
            $found_resource = $resources_contains[0].id
        }
    }

    # --- 3) SUBSCRIPTION NAME MATCH ---
    if (-not $found_resource) {
        $subscriptions = (Invoke-RestMethod `
                -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" `
                -Method GET `
                -Headers $headers).value

        foreach ($sub in $subscriptions) {
            if ($sub.displayName -match $item.ResourceName) {
                $subscription_found = $sub.id
            }
        }

        if ($subscription_found) {
            $found_resource = $subscription_found
        }
    }

    if ($found_resource -match "/subscriptions/([^/]+)") {
        $subscription_id = $Matches[1]
    }

    if (-not $found_resource -and $subscription_id) {
        try {
            $rg = (Invoke-RestMethod `
                    -Uri "https://management.azure.com/subscriptions/$subscription_id/resourcegroups/$($item.ResourceName)?api-version=2021-04-01" `
                    -Method GET `
                    -Headers $headers).id

            if ($rg) {
                $found_resource = $rg
            }
        }
        catch {}
    }

   
    
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

                    function New-PIMAzureRoleSettingsRule {
  param (
    [Parameter(Mandatory = $true)]
    [string]$NotificationRecipients,
    [Parameter(Mandatory = $true)]
    [string]$ResourceScopeID,
    [Parameter(Mandatory = $true)]
    [string]$RoleID,
    [Parameter(Mandatory = $true)]
    [string]$AccessToken
  )
  $headers = @{
    Authorization  = "Bearer $($AccessToken)"
    "Content-Type" = "application/json"
  }
  $pim_role_rule_settings = @"
{
  "properties": {
    "rules": [
      {
        "id": "Expiration_Admin_Eligibility",
        "ruleType": "RoleManagementPolicyExpirationRule",
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
      },
      {
        "enabledRules": [
          "MultiFactorAuthentication",
          "Justification"
        ],
        "id": "Enablement_EndUser_Assignment",
        "ruleType": "RoleManagementPolicyEnablementRule",
        "target": {
          "caller": "EndUser",
          "operations": [ "All" ],
          "level": "Assignment",
          "targetObjects": [],
          "inheritableSettings": [],
          "enforcedSettings": []
        }
      },
      {
        "notificationType": "Email",
        "recipientType": "Admin",
        "isDefaultRecipientsEnabled": true,
        "notificationLevel": "All",
        "notificationRecipients": [
          "$($NotificationRecipients)"
        ],
        "id": "Notification_Admin_Admin_Eligibility",
        "ruleType": "RoleManagementPolicyNotificationRule",
        "target": {
          "caller": "Admin",
          "operations": [ "All" ],
          "level": "Eligibility",
          "targetObjects": [],
          "inheritableSettings": [],
          "enforcedSettings": []
        }
      },
      {
        "notificationType": "Email",
        "recipientType": "Admin",
        "isDefaultRecipientsEnabled": true,
        "notificationLevel": "All",
        "notificationRecipients": [
          "$($NotificationRecipients)"
        ],
        "id": "Notification_Admin_Admin_Assignment",
        "ruleType": "RoleManagementPolicyNotificationRule",
        "target": {
          "caller": "Admin",
          "operations": [ "All" ],
          "level": "Assignment",
          "targetObjects": [],
          "inheritableSettings": [],
          "enforcedSettings": []
        }
      },
      {
        "notificationType": "Email",
        "recipientType": "Admin",
        "isDefaultRecipientsEnabled": true,
        "notificationLevel": "All",
        "notificationRecipients": [
          "$($NotificationRecipients)"
        ],
        "id": "Notification_Admin_EndUser_Assignment",
        "ruleType": "RoleManagementPolicyNotificationRule",
        "target": {
          "caller": "EndUser",
          "operations": [ "All" ],
          "level": "Assignment",
          "targetObjects": [],
          "inheritableSettings": [],
          "enforcedSettings": []
        }
      }
    ]
  }
}
"@
  Invoke-RestMethod -Uri "https://management.azure.com/$($ResourceScopeID)/providers/Microsoft.Authorization/roleManagementPolicies/$($RoleID)?api-version=2020-10-01" `
    -Headers $headers `
    -Method 'PATCH' `
    -Body $pim_role_rule_settings
}
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
        

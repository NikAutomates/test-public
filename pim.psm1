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
  $pim_role_rule_settings = $pim_role_rule_settings = @"
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
          "level": "Eligibility"
        }
      },
      {
        "id": "Expiration_Admin_Assignment",
        "ruleType": "RoleManagementPolicyExpirationRule",
        "isExpirationRequired": false,
        "maximumDuration": "P0D",
        "target": {
          "caller": "Admin",
          "operations": [ "All" ],
          "level": "Assignment"
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
          "level": "Assignment"
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
          "level": "Assignment"
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

Export-ModuleMember -Function `
    New-PIMAzureRoleSettingsRule,
    New-EntraGroup,
    New-EntraGroupMember,
    Enable-EntraPIMGroup,
    Get-EntraPIMGroup,
    Get-AzureRoleGUID,
    New-PIMAzureRoleActiveAssignment,
    New-AzureRoleAssignment,
    New-PIMAzureRoleEligibleAssignment,
    New-PIMForGroupsEligibleAssignment,
    Get-PIMAzureRoleEligibleAssignment

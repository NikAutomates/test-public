# -------------------------------
# CONFIG
# -------------------------------
$token = $graph_token
$vp_id = "<VP-USER-ID-HERE>"
$graph_url = "https://graph.microsoft.com/v1.0"

# storage lists
$all_reports = New-Object System.Collections.Generic.List[string]
$queue = New-Object System.Collections.Generic.Queue[object]

# seed the queue with the VP
$queue.Enqueue($vp_id)

# -------------------------------
# PROCESS LOOP (BFS traversal)
# -------------------------------
while ($queue.Count -gt 0) {

    $current = $queue.Dequeue()

    # Get direct reports for the current user
    $uri = "$graph_url/users/$current/directReports?`$select=id,displayName,jobTitle,userPrincipalName&`$top=999"
    $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{Authorization="Bearer $token"}

    if ($result.value.Count -gt 0) {
        foreach ($r in $result.value) {

            # add to full list
            $all_reports.Add($r.id)

            # queue this person so we pull THEIR reports too
            $queue.Enqueue($r.id)
        }

        # paging if needed
        while ($result.'@odata.nextLink') {
            $result = Invoke-RestMethod -Method GET -Uri $result.'@odata.nextLink' -Headers @{Authorization="Bearer $token"}
            foreach ($r in $result.value) {
                $all_reports.Add($r.id)
                $queue.Enqueue($r.id)
            }
        }
    }
}

# -------------------------------
# OUTPUT RESULTS
# -------------------------------
Write-Host "TOTAL REPORTS FOUND BELOW VP:" $all_reports.Count

# OPTIONAL: Dump objects with details
$full_output = foreach ($id in $all_reports) {
    Invoke-RestMethod -Method GET `
        -Uri "$graph_url/users/$id?`$select=id,displayName,userPrincipalName,jobTitle" `
        -Headers @{Authorization="Bearer $token"}
}

$full_output

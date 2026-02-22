$vp_id = "<PUT-ACTUAL-USER-ID-GUID-HERE>"   # << NOT UPN, NOT NAME
$graph_url = "https://graph.microsoft.com/v1.0"

$all_reports = New-Object System.Collections.Generic.List[string]
$queue = New-Object System.Collections.Generic.Queue[object]

$queue.Enqueue($vp_id)

while ($queue.Count -gt 0) {

    $current = $queue.Dequeue()

    $uri = "$graph_url/users/$current/directReports?`$top=999"
    $result = Invoke-RestMethod -Method GET -Uri $uri -Headers @{Authorization="Bearer $token"}

    if ($result.value.Count -gt 0) {
        foreach ($r in $result.value) {
            $all_reports.Add($r.id)
            $queue.Enqueue($r.id)
        }

        while ($result.'@odata.nextLink') {
            $result = Invoke-RestMethod -Method GET -Uri $result.'@odata.nextLink' -Headers @{Authorization="Bearer $token"}
            foreach ($r in $result.value) {
                $all_reports.Add($r.id)
                $queue.Enqueue($r.id)
            }
        }
    }
}

Write-Host "TOTAL FOUND: $($all_reports.Count)"

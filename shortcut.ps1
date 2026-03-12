#Variables used for the Title and Content on the Prompt Box
$Title = "Kace Service Desk"
$Prompt = "Select an Option Below"
$EdgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
          
$Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&org name IT Home", "&My Tickets", "&My Devices", "&New Access Request", "&Exit")
$Default = 4
 
#Prompt for choice based off variables and output
$Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
 
#Powershell Action with switch statement based off choice selected
switch($Choice) {

0 { [system.Diagnostics.Process]::Start("$($EdgePath)","https://sma.org/userui/") | Out-Null }

1 { [system.Diagnostics.Process]::Start("$($EdgePath)","https://sma.org.com/userui/ticket_list.php?") | Out-Null }

2 { [system.Diagnostics.Process]::Start("$($EdgePath)","https://sma.org.com/userui/device_list.php") | Out-Null }

3 { [system.Diagnostics.Process]::Start("$($EdgePath)","https://sma.org.com/userui/ticket_service_intermediate.php?QUEUE_ID=0&SERVICE_ID=2") | Out-Null }

4 {Exit}}

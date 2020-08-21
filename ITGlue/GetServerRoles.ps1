# Login to domain controller. copy/paste into powershell (running as admin). Open the server_roles.txt on desktop.

function IsInteractive { 
    $non_interactive = '-command', '-c', '-encodedcommand', '-e', '-ec', '-file', '-f'
     -not ([Environment]::GetCommandLineArgs() | Where-Object -FilterScript {$PSItem -in $non_interactive})
}
function getroles {
    try {
import-module ActiveDirectory
} catch {
    write-error "[ERR] Unable to load Active Directory powershell module"
    if ((IsInteractive))  { Read-Host  "      Press ANY key to continue..." }
    exit
}

if (test-path -path "$env:userprofile\desktop\") {
$output = "$env:userprofile\desktop\server_roles.txt"
} else {
$output = "$env:temp\server_roles.txt"
}

if (test-path "$output") {
	remove-item "$output"
} 
$servers = (Get-ADComputer -Filter {OperatingSystem -like "*windows*server*"}  | where Enabled | select DNSHostName).DNSHostName

foreach ($srv in $servers) { 
if (! (test-connection -computername $srv -quiet -count 1)) {
write-host "`r`n- Skipping: $srv - not online "
continue
}

$test=(Get-WindowsFeature -computer $srv -ErrorAction SilentlyContinue  | Where Installed).Name 
if ($test) {
$test2=(Get-WindowsFeature -computer $srv -ErrorAction SilentlyContinue | Where Installed).DisplayName
"`r`n-----------------`r`n* Server: $srv`r`n`r`n" |Tee-Object -append -file "$output"
 "_ Roles: _`r`n" |Tee-Object -append -file "$output"

if ($test -contains "AD-Domain-Services") { 
    "Domain Controller" |Tee-Object -append -file "$output"
    "Active Directory " |Tee-Object -append -file "$output"
} 
if ($test -contains "FS-FileServer") {   "File server" |Tee-Object -append -file "$output" }
if ($test -contains "Print-Server") { "Print Server" |Tee-Object -append -file  "$output"  }
if ($test -contains "GPMC") {  "Group Policy Management" |Tee-Object  -append -file "$output" }
if ($test -contains "DNS") {  "DNS Server" |Tee-Object  -append -file "$output" }
if ($test -contains "DHCP") {  "DHCP Server" |Tee-Object -append  -file "$output" }
if ($test -contains "web-server") {  "Web Server (IIS)" |Tee-Object -append  -file "$output" }
if ($test -contains "smtp-server") {  "SMTP Server" |Tee-Object -append  -file "$output" }
if ($test -contains "Remote-Desktop-Services") {  "Remote Desktop Sharing" |Tee-Object -append  -file "$output" }
if ($test -contains "RDS-Web-Access") {  "Remote Desktop Sharing: RemoteApps" |Tee-Object -append  -file "$output" } 

 "`r`n_ Installed Server Features: _`r`n" |Tee-Object -append -file "$output"
  foreach ($a in $test2) { 
    "$a" | Tee-Object -append -file "$output"
  }
 }
 }
 write-host "Done. Open file: $output"
}


getroles


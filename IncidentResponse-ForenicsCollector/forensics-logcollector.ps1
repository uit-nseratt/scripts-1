###################################################
#
# Collect Indications of Compromise (IoC) forensics data on a computer 
#
# Author: Nick Seratt <nseratt@focustsi.com>
# 
###################################################





$ErrorActionPreference = "SilentlyContinue"


function Get-TimeStamp { return "[{0:MM/dd/yy} {0:HH:mm:ss tt}]" -f (Get-Date) }
function Get-FileDateFormat {  return "{0:MM-dd-yy_hh:mmtt}" -f (Get-Date) }
function output-finding {
	$string = $args[0]
	write-host "$(Get-Timestamp) ---`n$string`n"
}
function Test-Administrator  
{ 
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

$outdir = "$env:temp\sec_collector"
$outzip = "$env:temp\sysinfo-$env:computername-$(Get-FileDateFormat).zip"

 #Check user is running the script is member of Administrator Group
if(-not (Test-Administrator)) {
        write-host "You need to run this script as administrator privileges"
		
	   #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess) | out-null
 
       #Exit from the current, unelevated, process
       Exit 1
	 
     }



if (! (test-path -path "$outdir")) { new-item -Force -Path "$outdir" -ItemType "directory" }

output-finding "Collecting windows event viewer files (Application, Security, System, etc.):"
output-finding "Executing Export Application Event Log"
& wevtutil epl Application "$outdir\Application.evtx"
output-finding "Executing Export Hardware Events Log:"
& wevtutil epl HardwareEvents "$outdir\HardwareEvents.evtx"
output-finding "Executing Export Security Event Log:"
& wevtutil epl Security "$outdir\Security.evtx"
output-finding "Executing Export System Event Log:"
& wevtutil epl System "$outdir\System.evtx" 

output-finding "Executing Suspicious AppData Files"
 $dir1=(Get-ChildItem -Path $env:systemdrive\ -Force -ErrorAction SilentlyContinue   )
 $dir2=(Get-ChildItem -Path $env:appdata,$env:localappdata,"C:\Users\Public\appdata\","C:\Users\default\appdata\" -Recurse -Force  -ErrorAction SilentlyContinue )
 $files = $dir1 + $dir2 ; $files | where {! $_.PSIsContainer -and $_.Extension -Match '^\.(exe|bat|com|cmd|vbs|vbe|vbscript|jar|jse|wsh|wsf|ws|scr|ps1|au3|sct|shs)$'}  | Select DirectoryName,Name,Extension,@{N='Version';E={$_.VersionInfo.ProductVersion}},@{N='Product';E={$_.VersionInfo.Product}},CreationTime,LastWriteTime,Length,@{N='FileHash';E={(Get-FileHash -Path $_.FullName).Hash}},@{N='VirusTotal';E={"https://virustotal.com/#/file/"+(Get-FileHash -Path $_.FullName).Hash}} | Sort-Object -Property DirectoryName,Name | Export-Csv -Path "$outdir\Suspicious_AppData_Files.csv" -Encoding ascii -NoTypeInformation

output-finding "Executing net config workstation"
 & net config workstation  > "$outdir\netconfig-workstation.txt"

output-finding "Executing net config server"
 & net config server  > "$outdir\netconfig-server.txt"

output-finding "Executing route print:"
 & route print  > "$outdir\routes.txt"

output-finding "Executing Get Local Users"
 Get-LocalUser | Select * |  Out-file "$outdir\localusers.txt"

output-finding "Executing Get Domain Trusts"
& nltest /domain_trusts /all_trusts  >  "$outdir\domaintrust.txt"

output-finding "Executing Get Network Shares"
& net view \\$env:computername >  "$outdir\networkshares.txt"
get-smbshare >>  "$outdir\networkshares.txt"

 output-finding "Executing Get Antivirus Products"

Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select * | Out-file "$outdir\SecurityCenter-Antiviruses.txt"


 output-finding "Executing Retrieve hosts file"
get-content "$env:windir\system32\drivers\etc\hosts" | select-string -Pattern "^[^#].*" | out-file "$outdir\hosts.txt"

output-finding "Executing netsh winhttp show proxy"
 & netsh winhttp show proxy  > "$outdir\netsh-proxy.txt"

output-finding "Executing ipconfig /all"
 & ipconfig /all  > "$outdir\ipconfig-all.txt"

output-finding "Executing  ipconfig /displaydns"
 &  ipconfig /displaydns  > "$outdir\dnscache.txt"

output-finding "Executing net statistics workstations"
 &  net statistics workstation  > "$outdir\netstats-workstation.txt"

output-finding "Executing netsh dump"
 &   netsh dump  > "$outdir\netsh-dump.txt"


output-finding "Executing List Active User Sessions"
 &   quser  > "$outdir\activesessions.txt"
 &   qwinsta  >> "$outdir\activesessions.txt"



output-finding "Executing netstat -ao, this might take some time, please hold..."
& netstat -ao > "$outdir\netstat-all.txt"

output-finding "Executing netsh advfirewall export"
& netsh advfirewall export "$outdir\advfirewallpolicy.txt"
 
output-finding "Executing netsh firewall rule show rule name=all"
&  netsh advfirewall firewall show rule name=all > "$outdir\firewall-all.txt"

  
output-finding "Executing List Processes and loaded Modules"
& tasklist /M > "$outdir\ProcessesAndModules.txt"

output-finding "Executing List Processes and their Hashes"
 Get-Process | Select ProcessName,Id,Path,Product,Company,Description,StartTime,@{N='FileHash';E={(Get-FileHash -Path $_.Path).Hash}},@{N='VirusTotal';E={"https://virustotal.com/#/file/"+(Get-FileHash -Path $_.Path).Hash}} |   Export-Csv -Path "$outdir\ProcessesandHashes.csv" -Encoding ascii -NoTypeInformation


output-finding "Executing List Services"
Get-WmiObject win32_service | select PSComputerName,Name,DisplayName,State,StartMode,PathName | export-csv  -Encoding ascii -NoTypeInformation -Path "$outdir\services.csv"

output-finding "Executing List Scheduled Tasks"
Get-ScheduledTask | Where-object {$_.TaskPath -notlike "\Microsoft*"} | ForEach-Object { [pscustomobject]@{
     Name = $_.TaskName
     Path = $_.TaskPath
     LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
     LastRun = $(($_ | Get-ScheduledTaskInfo).LastRunTime)
     NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
     Status = $_.State
     Command = $_.Actions.execute
     Arguments = $_.Actions.Arguments }} | Export-Csv -Path "$outdir\scheduledtasks.csv" -NoTypeInformation  -Encoding ascii

 
output-finding "Executing Windows Updates Report"
"= CMD: wmic qfe list`n`n" | out-file "$outdir\WindowsUpdates.txt"
wmic qfe list | out-file -append "$outdir\WindowsUpdates.txt"   
" = CMD: Get-HotFix`n`n" |  Out-file  -append "$outdir\WindowsUpdates.txt"
Get-HotFix | sort installedon | out-file -append  "$outdir\WindowsUpdates.txt"

output-finding "Executing vssadmin list providers:"
"# CMD : vssadmin list providers:`n`n" | Out-file "$outdir\vssadmin.txt"
& vssadmin list providers  >> "$outdir\vssadmin.txt"

output-finding "Executing vssadmin list shadows:"
"# CMD : vssadmin list shadows:`n`n" | Out-file -Append "$outdir\vssadmin.txt"
& vssadmin list shadows >> "$outdir\vssadmin.txt"

output-finding "Executing vssadmin list shadowstorage:"
"# CMD : vssadmin list shadowstorage:`n`n" | Out-file -Append "$outdir\vssadmin.txt"
& vssadmin list shadowstorage >> "$outdir\vssadmin.txt"

output-finding "Executing vssadmin list volumes:"
"# CMD :  vssadmin list volumes:`n`n" | Out-file -Append "$outdir\vssadmin.txt"
& vssadmin list volumes >> "$outdir\vssadmin.txt"

output-finding "Executing vssadmin list writers:"
"# CMD : vssadmin list writers:`n`n" | Out-file -Append "$outdir\vssadmin.txt"
& vssadmin list writers >> "$outdir\vssadmin.txt"

output-finding "Executing fltmc"
 & fltmc  > "$outdir\fltmc.txt"
 
output-finding "Executing local certificate store collection"
& Get-ChildItem -Recurse Cert:  > "$outdir\localcerts.txt"
& certutil -store My >> "$outdir\localcerts.txt"
& certutil -store -user Root  >> "$outdir\localcerts.txt"

output-finding "Listing all installed apps, please hold..."
& wmic product get /format:csv > "$outdir\allApps.csv"

if (! (Test-path -Path "$env:temp\autoruns.zip")) {
  output-finding "Downloading Microsoft AutoRuns."
  $webdlurl = "https://download.sysinternals.com/files/Autoruns.zip"
  $autoruns_outfile = "$env:temp\autoruns.zip"
    try {
       $autoruns_dl=(Invoke-WebRequest -Uri "$webdlurl" -OutFile "$autoruns_outfile"  -ErrorAction Stop)
       $StatusCode = $Response.StatusCode
    } catch {
       $StatusCode = $_.Exception.Response.StatusCode.value__
    }
} else { $StatusCode = "0" }

 if ($StatusCode -eq "0" -and ! (Test-Path -Path "$env:temp\autoruns\autorunsc.exe")) {
    output-finding "Extracting Microsoft AutoRuns."
    Expand-Archive -LiteralPath "$autoruns_outfile" -DestinationPath "$env:temp\autoruns\"

}   
output-finding "Executing Microsoft AutoRuns Report.   `n`n Cross referencing startup executables to VirusTotal - this can take a while (~5m). `n Review virustotal browser popups for any suspicious files."
&  "$env:temp\autoruns\autorunsc.exe" -a * -c -m -s -h -vt -vr > "$outdir\autoruns.csv"
(Get-Content "$outdir\autoruns.csv" | Select-Object -Skip 5) | Set-Content  "$outdir\autoruns.csv"

output-finding "Executing msinfo32, please hold.."
get-computerinfo > "$outdir\computerinfo.txt"
Start-process -FilePath "msinfo32" -NoNewWindow -ArgumentList "/nfo", "$outdir\msinfo32.nfo" -Wait 

output-finding "Finalizing and collecting logs...."

compress-archive  -Path "$outdir" -CompressionLevel Fastest -DestinationPath "$outzip"

output-finding "Saved results to archive: $outzip"

#cleanup folder after its archived
if (Test-Path -Path "$outdir") { Remove-Item -path "$outdir" -recurse -Force }
if (Test-Path -Path "$env:temp\autoruns\") { Remove-Item -path "$env:temp\autoruns\" -recurse -Force }

output-finding "Collection completed. Press any key to exit"
$HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | out-null
exit 0










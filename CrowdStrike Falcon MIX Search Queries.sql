Malware detection:
process_name:"powershell.exe" AND command_line:"-ep bypass"
filemod:(".exe" OR ".dll") AND "C:\ProgramData*.dll"
process_name:"mshta.exe" AND command_line:"javascript:"

Suspicious network traffic:
destination_address:192.168.1.100 AND destination_port:443 AND (protocol:tcp OR protocol:udp)
(source_address:10.0.0.0/8 OR source_address:172.16.0.0/12 OR source_address:192.168.0.0/16) AND destination_port:3389 AND (protocol:tcp OR protocol:udp)
destination_address:8.8.8.8 AND (destination_port:53 OR destination_port:5353)

Credential theft:
(process_name:"lsass.exe" OR process_name:"lsaiso.exe") AND command_line:"lsadump::sam"
process_name:"cmdkey.exe" OR process_name:"mimikatz.exe"
process_name:"netsh.exe" AND command_line:"wlan show profile"

Beaconing:
netconn_count:<10 AND netconn_duration:>5m AND netconn_count_sent:<5 AND user_name:"SYSTEM"
destination_port:53 AND (protocol:tcp OR protocol:udp) AND (NOT query:"ciscopxe" OR NOT query:"vqmon")
process_name:"svchost.exe" AND command_line:"-k netsvcs" AND (netconn_count:>30 OR netconn_count_sent:>30)

Command and control:
process_name:"iexplore.exe" AND command_line:"dns.pw"
process_name:"rundll32.exe" AND command_line:"DLLName: PowerShellHttp.dll, EntryPoint: Invoke-Mimikatz"
process_name:"powershell.exe" AND command_line:"dns.pw" AND user_name:(NOT "SYSTEM")

Lateral movement:
process_name:"net.exe" AND command_line:"use \*" AND (user_name:(NOT "SYSTEM") OR (user_name:"SYSTEM" AND parent_process_name:"services.exe"))
filemod:(".exe" OR ".dll") AND (user_name:(NOT "SYSTEM") OR (user_name:"SYSTEM" AND parent_process_name:"services.exe")) AND (destination_address:192.168.0.0/16 OR destination_address:172.16.0.0/12 OR destination_address:10.0.0.0/8)

PowerShell:
process_name:"powershell.exe" AND (command_line:"scriptblock" OR command_line:"encodedcommand") AND (netconn_count:>0 OR filemod_count:>0 OR registrymod_count:>0)
process_name:"powershell.exe" AND (command_line:"invoke-webrequest" OR command_line:"invoke-restmethod") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"new-object" OR command_line:"add-type" OR command_line:"reflection.assemblyname") AND filemod_count:>0

Phishing:
process_name:"outlook.exe" AND command_line:"/c IPM.note" AND filemod_count:>0 AND netconn_count:>0
process_name:"chrome.exe" AND command_line:"--profile-directory=Default" AND netconn_count:>0 AND (query:"google.com" OR query:"mail.google.com")
process_name:"firefox.exe" AND (command_line:"-new-window" OR command_line:"-new-tab") AND netconn_count:>0 AND query:"microsoft.com"

Data exfiltration:
process_name:"svchost.exe" AND command_line:"/t 60000" AND (netconn_count_sent:>1000 OR filemod_count_sent:>1000 OR registrymod_count_sent:>1000)
process_name:"powershell.exe" AND (command_line:"convertto-securestring" OR command_line:"export-clixml") AND netconn_count_sent:>0
process_name:"cmd.exe" AND command_line:"/c certutil -encode" AND filemod_count_sent:>0

Suspicious activity:
process_name:"wscript.exe" AND (command_line:"/e:VBScript.Encode" OR command_line:"/b /e:vbscript") AND filemod_count:>0
process_name:"regsvr32.exe" AND command_line:"/s /u /i:http://*" AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"powershell" OR command_line:"certutil" OR command_line:"bitsadmin" OR command_line:"wevtutil" OR command_line:"wmic") AND netconn_count:>0

Ransomware:
process_name:"taskdl.exe" AND command_line:"-url" AND netconn_count:>0
process_name:"lsass.exe" AND command_line:"-start" AND (filemod_count:>50 OR filemod_count_sent:>50 OR registrymod_count:>50 OR registrymod_count_sent:>50)
process_name:"cmd.exe" AND (command_line:"/c chcp 65001 && echo " OR command_line:"/c powershell -enc") AND (filemod_count:>10 OR filemod_count_sent:>10 OR registrymod_count:>10 OR registrymod_count_sent:>10)

DNS tunneling:
query:(".-idc." OR "-cdn." OR "-data." OR "-image." OR "-mov." OR "-picture." OR "-stream." OR "-video." OR "-voice." OR "-web.") AND (destination_port:53 OR destination_port:5353) AND netconn_count:>0
query:"google.com" AND netconn_count:>1000 AND netconn_duration:<1s
query:"bing.com" AND netconn_count:>1000 AND netconn_duration:<1s

Advanced persistent threats:
process_name:"wscript.exe" AND (command_line:"/b /e:vbscript.encode" OR command_line:"/b /e:jscript.encode") AND (filemod_count:>0 OR netconn_count:>0)
process_name:"mshta.exe" AND (command_line:"javascript:" OR command_line:"file://") AND (filemod_count:>0 OR netconn_count:>0)
process_name:"regsvr32.exe" AND command_line:"/u /i:http://" AND netconn_count:>0

Webshell:
process_name:"aspnet_compiler.exe" AND (command_line:"-v" OR command_line:"-u") AND filemod_count:>0
process_name:"cmd.exe" AND (command_line:"/c echo ^<?php eval(base64_decode(" OR command_line:"/c echo ^<?php $") AND (filemod_count:>0 OR netconn_count:>0)
process_name:"powershell.exe" AND (command_line:"iex(new-object net.webclient).downloadstring" OR command_line:"invoke-expression(new-object net.webclient).downloadstring") AND (filemod_count:>0 OR netconn_count:>0)

Remote access:
process_name:"mstsc.exe" AND (command_line:"/admin" OR command_line:"/restrictedadmin") AND netconn_count:>0
process_name:"psexec.exe" AND (command_line:"/accepteula" OR command_line:"/accepteula \\*") AND netconn_count:>0
process_name:"wmic.exe" AND (command_line:"/node:" OR command_line:"/node:^" OR command_line:"/node:@") AND netconn_count:>0

Insider threat:
process_name:"powershell.exe" AND (command_line:"get-content" OR command_line:"select-string") AND filemod_count:>0 AND user_name:(NOT "SYSTEM")
process_name:"net.exe" AND command_line:"user" AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0) AND user_name:(NOT "SYSTEM")
process_name:"wmiprvse.exe" AND command_line:"" AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0) AND user_name:(NOT "SYSTEM")

Exploit kits:
process_name:"iexplore.exe" AND (command_line:"mshtml:" OR command_line:"javascript:") AND netconn_count:>0
process_name:"chrome.exe" AND (command_line:"--profile-directory=" OR command_line:"--disable-extensions") AND netconn_count:>0 AND (query:"http://" OR query:"https://")
process_name:"firefox.exe" AND (command_line:"-new-tab" OR command_line:"-new-window") AND netconn_count:>0 AND (query:"http://" OR query:"https://")

Cryptojacking:
process_name:"powershell.exe" AND command_line:"iex (new-object net.webclient).downloadstring" AND netconn_count:>0
process_name:"taskmgr.exe" AND command_line:"/c netstat -nao" AND netconn_count:>0
process_name:"chrome.exe" AND command_line:"--disable-infobars --disable-background-networking" AND (filemod_count:>0 OR netconn_count:>0)

Malicious insiders:
process_name:"cmd.exe" AND command_line:"/c net user" AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0) AND user_name:(NOT "SYSTEM")
process_name:"explorer.exe" AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0) AND user_name:(NOT "SYSTEM")
process_name:"powershell.exe" AND (command_line:"get-process" OR command_line:"stop-process") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0) AND user_name:(NOT "SYSTEM")

Password spraying:
process_name:"cmd.exe" AND (command_line:"/c net user" OR command_line:"/c ping") AND netconn_count:>0
process_name:"powershell.exe" AND command_line:"new-aduser" AND netconn_count:>0
process_name:"ssh" AND query:"login:" AND netconn_count:>0

Reconnaissance:
process_name:"powershell.exe" AND (command_line:"test-connection" OR command_line:"nslookup" OR command_line:"resolve-dnsname") AND netconn_count:>0
process_name:"ping.exe" AND (command_line:"-n" OR command_line:"-l") AND netconn_count:>0
process_name:"tracert.exe" AND netconn_count:>0

Command and control:
process_name:"mshta.exe" AND (command_line:"javascript:" OR command_line:"file://") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"iex (new-object net.webclient).downloadstring" OR command_line:"invoke-expression (new-object net.webclient).downloadstring") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"certutil -urlcache -split -f" OR command_line:"bitsadmin /transfer") AND netconn_count:>0

Malware:
process_name:"winword.exe" AND (command_line:"/mFileSaveAsWebPage" OR command_line:"/mFilePrintDefault") AND netconn_count:>0
process_name:"chrome.exe" AND (command_line:"--disable-extensions --disable-web-security" OR command_line:"--disable-web-security") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"iex (new-object net.webclient).downloadstring" OR command_line:"invoke-expression (new-object net.webclient).downloadstring") AND netconn_count:>0

Data manipulation:
process_name:"powershell.exe" AND (command_line:"add-content" OR command_line:"set-content" OR command_line:"get-content") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)
process_name:"cmd.exe" AND (command_line:"certutil -decode" OR command_line:"certutil -encode") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)
process_name:"reg.exe" AND (command_line:"add" OR command_line:"delete") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)

Password stealing:
process_name:"mimikatz.exe" AND (command_line:"privilege::debug" OR command_line:"sekurlsa::logonpasswords" OR command_line:"lsadump::sam") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"get-winevent" OR command_line:"get-eventlog") AND netconn_count:>0
process_name:"cmdkey.exe" AND (command_line:"/list" OR command_line:"/add") AND netconn_count:>0

Network scanning:
process_name:"nmap.exe" AND netconn_count:>0
process_name:"ping.exe" AND netconn_count:>0 AND (query:"ping" OR query:"-n" OR query:"-c")
process_name:"net.exe" AND (command_line:"/user" OR command_line:"/view" OR command_line:"/domain") AND netconn_count:>0

Web application attacks:
process_name:"python.exe" AND (command_line:"manage.py runserver" OR command_line:"./manage.py runserver") AND netconn_count:>0
process_name:"iexplore.exe" AND (command_line:"/s" OR command_line:"/n") AND netconn_count:>0
process_name:"chrome.exe" AND (command_line:"--disable-infobars --disable-background-networking" OR command_line:"--disable-web-security --user-data-dir") AND netconn_count:>0

Ransomware:
process_name:"vssadmin.exe" AND (command_line:"delete shadows" OR command_line:"delete shadows /all" OR command_line:"resize shadowstorage") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"get-childitem -recurse" OR command_line:"get-content -path") AND netconn_count:>0
process_name:"taskmgr.exe" AND command_line:"/c netstat -nao" AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"invoke-expression" OR command_line:"new-object system.net.webclient; $client.DownloadString") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"vssadmin delete shadows /all /quiet" OR command_line:"wmic shadowcopy delete") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"kernel32.dll" OR command_line:"msvcrt.dll") AND netconn_count:>0

Exploits:
process_name:"cmd.exe" AND (command_line:"mshta http://" OR command_line:"wmic process call create") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"iex (new-object net.webclient).downloadstring" OR command_line:"invoke-expression (new-object net.webclient).downloadstring") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"javascript:" OR command_line:"data:") AND netconn_count:>0

Brute force attacks:
process_name:"powershell.exe" AND (command_line:"get-aduser" OR command_line:"test-connection") AND netconn_count:>0
process_name:"ssh" AND query:"login:" AND netconn_count:>0
process_name:"sqlcmd.exe" AND (command_line:"-S" OR command_line:"-U" OR command_line:"-P") AND netconn_count:>0

Endpoint attacks:
process_name:"svchost.exe" AND (command_line:"netsvcs" OR command_line:"wscsvc") AND netconn_count:>0
process_name:"mshta.exe" AND (command_line:"mhtml:" OR command_line:"about:") AND netconn_count:>0
process_name:"reg.exe" AND (command_line:"add" OR command_line:"delete") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)

Webshell:
process_name:"iexplore.exe" AND command_line:"-k" AND netconn_count:>0
process_name:"cmd.exe" AND command_line:"powershell -nop -c "$client = New-Object Net.WebClient; $client.DownloadString('http://" AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"iex (new-object net.webclient).downloadstring" OR command_line:"invoke-expression (new-object net.webclient).downloadstring") AND netconn_count:>0

File integrity monitoring:
process_name:"powershell.exe" AND (command_line:"new-item -type file" OR command_line:"copy-item" OR command_line:"move-item" OR command_line:"remove-item") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)
process_name:"cmd.exe" AND (command_line:"expand" OR command_line:"comp") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)
process_name:"reg.exe" AND (command_line:"add" OR command_line:"delete") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)

Advanced persistent threats:
process_name:"powershell.exe" AND (command_line:"invoke-expression" OR command_line:"new-object System.Net.WebClient") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"xcopy" OR command_line:"bitsadmin") AND netconn_count:>0
process_name:"wmic.exe" AND (command_line:"process call create" OR command_line:"os get") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)

Phishing:
process_name:"powershell.exe" AND (command_line:"invoke-expression (New-Object Net.WebClient).DownloadString" OR command_line:"iex (New-Object Net.WebClient).DownloadString") AND netconn_count:>0
process_name:"iexplore.exe" AND (command_line:"-noframemerging" OR command_line:"-noframemerging -extoff") AND netconn_count:>0
process_name:"winword.exe" AND command_line:"/mFileNewDefault" AND netconn_count:>0

Insider threats:
process_name:"powershell.exe" AND (command_line:"get-winevent" OR command_line:"get-eventlog") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"net user" OR command_line:"net localgroup administrators") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"C:\ProgramData\temp.dll" OR command_line:"C:\ProgramData\temp.dll,entry") AND netconn_count:>0

Privilege escalation:
process_name:"powershell.exe" AND (command_line:"start-process" OR command_line:"$s=New-Object" OR command_line:"Set-ItemProperty") AND netconn_count:>0
process_name:"net.exe" AND command_line:"use" AND netconn_count:>0
process_name:"reg.exe" AND (command_line:"add" OR command_line:"delete") AND (filemod_count:>0 OR registrymod_count:>0 OR netconn_count:>0)

Command and control:
process_name:"powershell.exe" AND (command_line:"new-object System.Net.Sockets.TcpClient" OR command_line:"new-object Net.Sockets.TcpClient" OR command_line:"new-object System.Net.WebClient") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"url.dll,OpenURL") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"nslookup" OR command_line:"tracert" OR command_line:"ping") AND netconn_count:>0

Data exfiltration:
process_name:"powershell.exe" AND (command_line:"$client.UploadFile" OR command_line:"$client.DownloadFile") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"bitsadmin" OR command_line:"certutil") AND netconn_count:>0
process_name:"outlook.exe" AND (command_line:"/a" OR command_line:"/f" OR command_line:"/attach") AND netconn_count:>0

Suspicious activity:
process_name:"powershell.exe" AND (command_line:"invoke-webrequest" OR command_line:"invoke-restmethod") AND netconn_count:>0
process_name:"mshta.exe" AND (command_line:"mhtml:" OR command_line:"about:") AND netconn_count:>0
process_name:"wmic.exe" AND (command_line:"os get" OR command_line:"process call create") AND netconn_count:>0

Malware:
process_name:"powershell.exe" AND (command_line:"invoke-expression (new-object system.net.webclient).downloadfile" OR command_line:"new-object system.net.webclient; $client.DownloadFile") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"dllname.dll, entrypoint") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"certutil" OR command_line:"bitsadmin") AND netconn_count:>0

Network scanning:
process_name:"nmap.exe" AND netconn_count:>0
process_name:"ping.exe" AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"test-netconnection" OR command_line:"test-connection") AND netconn_count:>0

Suspicious network activity:
netconn_count:>50
protocol:icmp AND netconn_count:>0
protocol:udp AND netconn_count:>0

Active directory reconnaissance:
process_name:"powershell.exe" AND (command_line:"get-adgroupmember" OR command_line:"get-adcomputer" OR command_line:"get-aduser") AND netconn_count:>0
process_name:"net.exe" AND (command_line:"group" OR command_line:"user") AND netconn_count:>0
process_name:"wmic.exe" AND (command_line:"useraccount" OR command_line:"computer") AND netconn_count:>0

Suspicious logins:
process_name:"powershell.exe" AND (command_line:"get-winevent -FilterHashTable" OR command_line:"get-eventlog -newest") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"net user" OR command_line:"net localgroup administrators") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"C:\ProgramData\temp.dll" OR command_line:"C:\ProgramData\temp.dll,entry") AND netconn_count:>0

Malicious activity:
process_name:"powershell.exe" AND (command_line:"new-object net.webclient" OR command_line:"(new-object net.webclient).downloadstring") AND netconn_count:>0
process_name:"rundll32.exe" AND (command_line:"msvcrt.dll" OR command_line:"kernel32.dll") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"bitsadmin" OR command_line:"certutil") AND netconn_count:>0

Data infiltration:
process_name:"powershell.exe" AND (command_line:"$client.UploadFile" OR command_line:"$client.DownloadFile") AND netconn_count:>0
process_name:"cmd.exe" AND (command_line:"bitsadmin" OR command_line:"certutil") AND netconn_count:>0
process_name:"outlook.exe" AND (command_line:"/a" OR command_line:"/f" OR command_line:"/attach") AND netconn_count:>0

Suspicious outgoing traffic:
process_name:"powershell.exe" AND (command_line:"invoke-webrequest" OR command_line:"invoke-restmethod") AND netconn_count:>0
process_name:"mshta.exe" AND (command_line:"mhtml:" OR command_line:"about:") AND netconn_count:>0
process_name:"wmic.exe" AND (command_line:"os get" OR command_line:"process call create") AND netconn_count:>0

Suspicious PowerShell usage:
process_name:"powershell.exe" AND (command_line:"-nop -exec bypass" OR command_line:"-w hidden -enc") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"Get-Content" OR command_line:"Add-Type") AND netconn_count:>0
process_name:"powershell.exe" AND (command_line:"set-executionpolicy unrestricted" OR command_line:"enable-psremoting -force") AND netconn_count:>0


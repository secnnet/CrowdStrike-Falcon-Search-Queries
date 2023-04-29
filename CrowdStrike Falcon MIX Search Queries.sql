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














































































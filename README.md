
# General Informations

## Installation
### Main installation
```
curl -L -s https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh | bash
```

### Dev installation
```
curl -L -s https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh | bash -s -- -b dev
```

### Correct wrong installation
```
curl -L -s https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh | bash -s -- -f
```

# Content

## Install (54/82)

### Penenv (3)
 - [X] install_penenv
 - [X] autoenum
 - [X] start

### Lang & downloaders (13)
 - [X] apt upgrade
 - [X] python 3
    - [X] 2to3
    - [X] pip & pip upgrade
    - [X] poetry
 - [X] go
 - [X] ruby
 - [X] java
 - [X] nodejs
    - [X] npm
    - [X] yarn
 - [X] make
 - [X] git
 - [X] krb5-user

### Commands (4)
 - [X] pyftpdlib
 - [X] dnsutils
 - [X] google-chrome
 - [X] jq

### Tools (26/47)
#### Web Scan
##### Subdomains & paths (8/13)
 - [X] sublist3r
 - [X] assetfinder
 - [X] amass
 - [X] gowitness
 - [X] subjack
 - [X] certspotter
 - [X] dnsrecon
 - [X] dnsenum
 - [X] waybackurls
 - [ ] arjun
 - [ ] brokenlinkchecker
 - [ ] dirscapper
 - [ ] haktrails
 - [ ] hakrawler
##### Fuzzers (2/4)
 - [X] gobuster
 - [X] whatweb
 - [ ] ffuf
 - [ ] x8
##### Others (5/6)
 - [X] wappalyzer
 - [X] testssl
 - [X] nikto
 - [X] wafw00f
 - [X] httprobe
 - [ ] secretfinder

#### Bruteforce (0/3)
 - [ ] hashcat
 - [ ] hydra
 - [ ] john

#### Network (5)
 - [X] nmap
 - [X] onesixtyone
 - [X] rpcbind
 - [X] snmpcheck
 - [X] snmpwalk

#### Exploits (0/5)
 - [ ] Metasploit
 - [ ] AutoHackBruteOS
 - [ ] sqlmap
 - [ ] commix
 - [ ] searchsploit

#### Other (6/12)
 - [X] impacket
 - [X] fierce
 - [X] oscanner
 - [X] odat
 - [X] crackmapexec
 - [X] cewl
 - [ ] cupp
 - [ ] DDexec
 - [ ] mitm6
 - [ ] proxychain
 - [ ] responder
 - [ ] Evil winrm

### Scripts (5/12)
 - [X] dnscat (server & client)
 - [X] LinPEAS
 - [X] WinPEAS
 - [X] miranda
 - [X] pspy
 - [ ] mimikatz
 - [ ] evilSSDP
 - [ ] linux-exploit-suggester-2
 - [ ] mimipenguin
 - [ ] powersploit
 - [ ] watson
 - [ ] rubeus

### Services (3)
 - [X] bloodhound
    - [X] neo4j
 - [X] nessus

## start

### Services
 - [X] neo4j
 - [X] nessus
 - [X] dnscat

### File transfer servers
 - [X] http server
 - [X] ftp server
 - [ ] smb server

### Other servers
 - [ ] Metasploit
 - [ ] Hashcat
 - [ ] responder



# Compatibilities

## Tested environnement
- Parrot
   - [X] hack the box
   - [ ] pentesting
   - [ ] architect
- Kali
   - [ ] 2023 64 bits
- Debian
   - [ ] 11
- Ubuntu Desktop
   - [ ] 20
   - [ ] 22
- Alpine
   - [ ] Standard
   - [ ] Extended
   - [ ] Raspery
   - [ ] VM


# Journey map

## OSINT

Name   | Tools
--------------------------------------------------
asn    | Amass
cdir   | Amass
domain | Amass, assetfinder, haktrails, waybackurl
IRL    | haktrails
pwd    | cewl, cupp


## Enumeration

Name    | Tools
------------------------------------------------------------------------------------------------------------------------
network | nmap
banner  | nmap, telnet
fuzz    | ffuf, gobuster
web     | arjun, brockenlinkchecker, dirscapper, gowitness, hakrawler, nikto, secretfinder, testssl, wappalyzer, whatweb
upnp    | miranda


## Authentication

### Creds
#### Bruteforce
 - nmap
 - hydra
 - crackmapexec
 - hashcat
 - john
#### Remote access
 - impacket
 - evil winrm

### Vulnerabilities
#### Scan
 - nmap
 - nessus
 - nikto
 - searchsploit
 - metasploit
 - google
#### Exploit
 - nmap
 - metasploit
 - sqlmap
 - commix

### Backdoor
 - reverse shells
 - add a user
 - metasploit
 - dnscat
 - impacket

## Infiltration

### Priviledge escalation
 - LinPEAS
 - WinPEAS
 - pspy
 - linux-exploit-suggestor-2
 - watson

### Dumping
 - impacket
 - bloodhound
 - crackmapexec
 - rubeus
 - mimikatz
 - mimipenguin

### Spying
 - proxychain
 - responder
 - mitm6
 - impacket

### Social Eng
 - evilSSDP
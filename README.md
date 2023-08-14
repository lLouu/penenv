
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

## Install (69/85)

### Penenv (3)
 - [X] install_penenv
 - [X] autoenum
 - [X] start

### Lang & downloaders (14)
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
 - [X] rust
 - [X] make
 - [X] git
 - [X] krb5-user

### Commands (5)
 - [X] pyftpdlib
 - [X] dnsutils
 - [X] google-chrome
 - [X] jq
 - [X] expect

### Tools (39/48)
#### Web Scan
##### Subdomains & paths (13)
 - [X] sublist3r
 - [X] assetfinder
 - [X] amass
 - [X] gowitness
 - [X] subjack
 - [X] certspotter
 - [X] dnsrecon
 - [X] dnsenum
 - [X] waybackurls
 - [X] arjun
 - [X] brokenlinkchecker
 - [X] dirscapper
 - [X] haktrails
 - [X] hakrawler
##### Fuzzers (3/4)
 - [X] gobuster
 - [X] whatweb
 - [X] ffuf
 - [ ] x8
##### Others (6)
 - [X] wappalyzer
 - [X] testssl
 - [X] nikto
 - [X] wafw00f
 - [X] httprobe
 - [X] secretfinder

#### Bruteforce (3)
 - [X] hashcat
 - [X] hydra
 - [X] john

#### Network (5)
 - [X] nmap
 - [X] onesixtyone
 - [X] rpcbind
 - [X] snmpcheck
 - [X] snmpwalk

#### Exploits (2/5)
 - [X] Metasploit
 - [X] searchsploit
 - [ ] AutoHackBruteOS
 - [ ] sqlmap
 - [ ] commix

#### Other (8/13)
 - [X] impacket
 - [X] fierce
 - [X] oscanner
 - [X] odat
 - [X] crackmapexec
 - [X] cewl
 - [X] cupp
 - [X] DDexec
 - [ ] mitm6
 - [ ] proxychain
 - [ ] responder
 - [ ] Evil winrm
 - [ ] openvpn

### Scripts (5/12)
 - [X] dnscat (server & client & shell)
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
 - [ ] openvpn

### File transfer servers
 - [X] http server
 - [X] ftp server
 - [X] smb server

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
-------|------------------------------------------
asn    | Amass
cdir   | Amass
domain | Amass, assetfinder, haktrails, waybackurl
IRL    | haktrails
pwd    | cewl, cupp


## Enumeration

Name    | Tools
--------|---------------------------------------------------------------------------------------------------------------
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
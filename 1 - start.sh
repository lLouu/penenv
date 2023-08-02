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
        echo -e "[-] Running as root. Please run in rootless mode... Exiting..."
        exit 1
fi
log=/home/$usr/logs
hotscript=/home/$usr/hot-script
if [[ ! -d $log ]];then
        mkdir $log
fi

# Check installations
if [[ ! -x "$(command -v install_penenv)" ]]; then
        echo -e "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh > installing;rm installing
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi
install_penenv

# Starting Neo4j
echo -e "[+] Starting neo4j"
sudo neo4j console & >> $log/neo4j.log
echo -e "[~] Log of neo4j are available in $log/neo4j"
echo -e "[*] Access to neo4j web interface through http://localhost:7474"
echo -e "[*] Launch bloodhound using 'bloodhound' command"


# Starting Nessus
echo -e "[+] Starting nessusd"
sudo systemctl start nessusd
echo -e "[*] Access to nessus web interface through http://localhost:8834"

# Starting dnscat server
echo -e "[+] Starting dnscat"
sudo dnscat
echo -e "[*] Access to dnscat tunnel through localhost:53"


# Start http server
echo -e "[+] Starting file transfer through http"
python3 -u -m http.server $hotscript 80 & >> $log/http.log
echo -e "[*] Access to file download through http://localhost:80/<path>"


# Start ftp server
echo -e "[+] Starting file transfer through ftp"
python3 -u -m pyftpdlib -d $hotscript & >> $log/ftp.log
echo -e "[*] Access to file transfer through ftp://localhost with your user credentials"


# Start smb server
echo -e "[+] Starting file transfer through smb"
python3 -u /usr/share/doc/python-impacket/examples/smbserver.py share $hotscript -smb2support & >> $log/smb.log
echo -e "[*] Access to file transfer through //<ip>/share/<path>"


# Start responder

echo -e ""
echo -e "[~] To check running servers, do 'jobs'"
echo -e "[~] To get to a process, do 'fg <job-id>'"


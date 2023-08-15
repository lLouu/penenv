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
echo "Suite version : V0.1.6"
echo "Script version : V1.2"
echo ""
echo ""

# Manage options
branch="main"
check="1"
force=""
no_upgrade=""
check_install="1"

POSITIONAL_ARGS=()
ORIGINAL_ARGS=$@

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--branch)
      branch="$2"
      shift # past argument
      shift # past value
      ;;
    -nc|--no-check)
      check=""
      shift
      ;;
    -f|--force)
      force="1"
      shift
      ;;
    -nu|--no-upgrade)
      no_upgrade="1"
      shift
      ;;
    -h|--help)
      echo "[~] Github options"
      echo "[*] -b | --branch <main|dev> (default: main) - Use this branch version of the github"
      echo "[*] -nc | --no-check - Disable the check of the branch on github"
      echo ""
      echo "[~] Misc options"
      echo "[*] -f | --force - Force the installation even when the detection says it is installed"
      echo "[*] -nu | --no-upgrade - Disable apt and pip upgrading"
      echo "[*] -h | --help - Get help"
      ;;
    -ni|--no-install)
      check_install=""
      shift
      ;;
    -*|--*)
      tput setaf 1;echo "[-] Unknown option $1... Exiting";tput sgr0
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

set -- "${POSITIONAL_ARGS[@]}" # restore positional parameters

# Set directory environement
usr=$(whoami)
if [[ $usr == "root" ]];then
        tput setaf 1;echo "[-] Running as root. Please run in rootless mode... Exiting...";tput sgr0
        exit 1
fi
log=/home/$usr/logs
hotscript=/home/$usr/hot-script
session=/home/$usr/session

# Check installations
if [[ $check_install ]];then
  if [[ ! -x "$(command -v install_penenv)" ]];then
          echo "[+] install_penenv not detected as a command...Setting up"
          wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh > installing;rm installing
          chmod +x 0\ -\ install.sh
          sudo mv 0\ -\ install.sh /bin/install_penenv
  fi
  install_penenv $ORIGINAL_ARGS
fi

if [[ ! -d $session ]];then
       mkdir $session
fi
sudo rm $session/*

# Starting Neo4j
echo "[+] Starting neo4j"
sudo neo4j console >> $log/neo4j.log &
tput setaf 4;echo "[*] Access to neo4j web interface through http://localhost:7474";tput sgr0
tput setaf 6;echo "[~] Log of neo4j are available in $log/neo4j";tput sgr0
tput setaf 6;echo "[~] Launch bloodhound using 'bloodhound' command";tput sgr0


# Starting Nessus
echo "[+] Starting nessusd"
sudo systemctl start nessusd
tput setaf 4;echo "[*] Access to nessus web interface through https://localhost:8834";tput sgr0

# Starting dnscat server
echo "[+] Starting dnscat"
read -p "Domain > " dom
read -p "Secret > " sec
if [[ ! "$sec" ]];then sec="hellowthere";fi
touch $session/dnscat.stdin
touch $session/dnscat.stdout
tail -f $session/dnscat.stdin | sudo unbuffer -p dnscat $dom --secret $sec --security=authenticated | tee $session/dnscat.stdout > /dev/null &
tput setaf 4;echo "[*] Access to dnscat tunnel through localhost:53 with secret $sec";tput sgr0
tput setaf 6;echo "[~] To connect while using domain request, make sure this server is an authoritative DNS";tput sgr0
tput setaf 6;echo "[~] To get your shell after executing client dnscat, execute dnscat-shell here";tput sgr0

# Start http server
echo "[+] Starting file transfer through http"
sudo python3 -u -m http.server --directory $hotscript 8080 >> $log/http.log &
tput setaf 4;echo "[*] Access to file download through http://localhost:8080/<path>";tput sgr0


# Start ftp server
echo "[+] Starting file transfer through ftp"
sudo python3 -u -m pyftpdlib -d $hotscript 2>> $log/ftp.log &
tput setaf 4;echo "[*] Access to file transfer through ftp://localhost:2121";tput sgr0


# Start smb server
echo "[+] Starting file transfer through smb"
sudo impacket-smbserver share $hotscript -smb2support >> $log/smb.log &
tput setaf 4;echo "[*] Access to file transfer through //<ip>/share/<path>";tput sgr0



# echo ""
# tput setaf 6;echo "[~] To check running servers, do 'jobs'";tput sgr0
# tput setaf 6;echo "[~] To get to a process, do 'fg <job-id>'";tput sgr0
# tput setaf 6;echo "[~] To put back a process to background, press CTRL+Z then do 'bg'";tput sgr0


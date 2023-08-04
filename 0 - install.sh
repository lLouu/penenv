#! /bin/bash
# TODO : add cold tools
# TODO : add networkers


echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.1.1"
echo "Script version : V1.1"
echo ""
echo ""



# Manage options
branch="main"

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--branch)
      branch="$2"
      shift # past argument
      shift # past value
      ;;
    -*|--*)
      echo "Unknown option $1"
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
hotscript=/home/$usr/hot-script
if [[ ! -d $hotscript ]];then
        mkdir $hotscript
fi

# colors !
if [ ! -x "$(command -v tput)" ];then
        echo "[+] tput not detected. installing..."
        sudo apt-get install tput -y > /dev/null
fi

# Set self command
if [[ ! -x "$(command -v install_penenv)" ]];then
        echo "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh -q
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi

# Install autoenum & its dependencies
if [[ ! -x "$(command -v autoenum)" ]];then
        echo "[+] autoenum not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh -q
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
fi

echo "[+] Checking autoenum dependencies"
echo ""
autoenum --first

# Install start
if [[ ! -x "$(command -v start)" ]];then
        echo "[+] start not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh -q
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
fi

# Install bloodhound
if [[ ! -x "$(command -v bloodhound)" ]];then
        echo "[+] Bloodhound not detected...Installing"
        sudo apt-get install bloodhound -y > /dev/null
        tput setaf 6;echo "[~] Go to http://localhost:7474 to set new neo4j password";tput sgr0
fi

if [[ ! -f "$hotscript/Invoke-Bloodhound.ps1" ]];then
        echo "[+] Invoke-Bloodhound not detected...Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 -q
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
fi

if [[ ! -x "$(command -v java)" ]];then
        echo "[+] Java not detected...Installing"
        sudo apt-get install default-jdk -y > /dev/null
fi

if [[ ! "$(java --version)" =~ "openjdk 11.0.18" ]];then
        echo "[+] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
fi

# Install Nessus
if [[ -f "/opt/nessus/sbin/nessusd" ]];then
        echo "[+] Nessus not detected...Installing"
        curl -s --request GET \
               --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.5.3-debian10_amd64.deb' \
               --output 'Nessus.deb' > /dev/null
        sudo apt-get install ./Nessus.deb -y > /dev/null
        rm Nessus.deb
        sudo systemctl start nessusd
        tput setaf 6;echo "[~] Go to http://localhost:8834 to complete nessus installation";tput sgr0
fi

# Install ftp module
if [[ ! -x "$(pip list | grep pyftpdlib)" ]];then
        echo "[+] Pyftplib not detected...Installing"
        sudo pip install pyftpdlib -q 2> /dev/null
fi

# Install impacket
if [[ ! -d "/usr/share/doc/python-impacket" ]];then
        echo "[+] Impacket not detected...Installing"
        sudo pip install impacket -q 2> /dev/null
        git clone https://github.com/fortra/impacket --quiet > /dev/null
        sudo cp impacket/exemples/* /bin
        sudo mv impacket /usr/share/doc/python-impacket
        printf "#! /bin/sh\nls /usr/share/doc/python-impacket/examples/" > impacket_script
        chmod +x impacket_script
        sudo mv impacket_script /bin/impacket_script
fi

# Install dns2cat & dependencies
if [[ ! -x "$(command -v make)" ]];then
        echo "[+] Make not detected...Installing"
        sudo apt-get install make -y > /dev/null
fi

if [[ ! -x "$(command -v gem)" ]];then
        echo "[+] Rubby not detected...Installing"
        sudo apt-get install ruby-dev -y > /dev/null
fi

if [[ ! -d "/lib/dnscat" ]];then
        echo "[+] Dnscat sourcecode not detected...Installing"
        git clone https://github.com/iagox86/dnscat2.git --quiet > /dev/null
        sudo mv dnscat2 /lib/dnscat
        # correct minor sourcecode error
        sudo sed -i 's/return a.value.ptr == a.value.ptr/return a.value.ptr == b.value.ptr/g' /lib/dnscat/client/libs/ll.c
fi

if [[ ! -f "$hotscript/dnscat" ]];then
        echo "[+] Dnscat client not detected...Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        make > /dev/null
        mv dnscat $hotscript/dnscat
        cd $workingdir
fi

if [[ ! -x "$(command -v dnscat)" ]];then
        echo "[+] Dnscat server not detected...Making"
        workingdir=$(pwd)
        cd /lib/dnscat/server
        sudo gem install bundler > /dev/null
        sudo bundler install > /dev/null
        cd $workingdir
        
        echo "[+] Creating command..."
        printf "#! /bin/sh\nsudo ruby /lib/dnscat/server/dnscat2.rb \$@" > dnscat
        chmod +x dnscat
        sudo mv dnscat /bin/dnscat
fi

# Install PEAS
if [[ ! -f "$hotscript/LinPEAS.sh" ]];then
        echo "[+] LinPEAS not detected...Installing"
        curl -L -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output $hotscript/LinPEAS.sh
fi

if [[ ! -f "$hotscript/WinPEAS.ps1" ]];then
        echo "[+] WinPEAS powershell not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -q
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
fi

if [[ ! -f "$hotscript/WinPEAS.bat" ]];then
        echo "[+] WinPEAS bat not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -q
        mv winPEAS.bat $hotscript/WinPEAS.bat
fi

# Install miranda
if [[ ! -f "$hotscript/miranda.py" ]];then
        echo "[+] Miranda not detected...Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
fi

# Install pspy
if [[ ! -f "$hotscript/pspy32" ]];then
        echo "[+] Pspy32 not detected...Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 --output $hotscript/pspy32
fi

if [[ ! -f "$hotscript/pspy64" ]];then
        echo "[+] Pspy64 not detected...Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 --output $hotscript/pspy64
fi

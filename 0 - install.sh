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
echo "Suite version : V0.1.2"
echo "Script version : V1.2"
echo ""
echo ""



# Manage options
branch="main"
check=true
force=false
no_upgrade=false

POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case $1 in
    -b|--branch)
      branch="$2"
      shift # past argument
      shift # past value
      ;;
    -nc|--no-check)
      check=false
      shift
      ;;
    -f|--force)
      force=true
      shift
      ;;
    -nu|--no-upgrade)
      no_upgrade=true
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

# Inform user
if [[ $branch != "main" && $check ]];then tput setaf 4;echo "[*] $branch will be the used github branch for installation";tput sgr0;
else
        if [[ $check ]];then tput setaf 1;echo "[-] using $branch cannot be done without github checking... Exiting";tput sgr0; exit 1; fi
fi
if [[ $force ]];then tput setaf 4;echo "[*] installation will be forced for every components";tput sgr0; fi
if [[ $no_upgrade ]];then tput setaf 4;echo "[*] apt and pip will not be upgraded";tput sgr0; fi
echo ""

# Set directory environement
usr=$(whoami)
if [[ $usr == "root" ]];then
        tput setaf 1;echo "[-] Running as root. Please run in rootless mode... Exiting...";tput sgr0
        exit 1
fi
hotscript=/home/$usr/hot-script
if [[ ! -d $hotscript ]];then
        echo "[+] Creating hotscript folder in $hotscript"
        mkdir $hotscript
fi

# colors !
if [[ ! -x "$(command -v tput)" || $force ]];then
        echo "[+] tput not detected. installing..."
        sudo apt-get install tput -y > /dev/null
fi

# Set self command
if [[ ! -x "$(command -v install_penenv)" || $check || $force ]];then
        echo "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh -q
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi

## Languages and downloaders
# Upgrade apt
if [[ ! $no_upgrade ]];then
        echo "[+] Updating apt-get and upgrading installed packages... This may take a while"
        sudo apt-get update > upgrade
        sudo apt-get upgrade -y > upgrade
        sudo apt-get autoremove -y > upgrade; rm upgrade
        tput setaf 4;echo "[*] apt-get updated and upgraded";tput sgr0
fi

# Install python3
if [[ ! -x "$(command -v python3)" || $force ]];then
        echo "[+] python3 not detected...Installing"
        sudo apt-get install python3 -y > /dev/null
fi

# Install pip
if [[ ! -x "$(command -v pip)" || $force ]];then
        if [[ ! -x "$(command -v pip3)" || $force ]];then
                echo "[+] pip not detected...Installing"
                sudo apt-get install python3-pip -y > /dev/null
        fi
        # Check if an alias is needed
        if [[ ! -x "$(command -v pip)" ]];then
                echo "[+] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
        fi
fi

# Upgrade pip
if [[ ! $no_upgrade ]];then
        echo "[+] Upgrading pip and python packages... This may take a while"
        pip install --upgrade pip -q 2> /dev/null
        l=$(pip list --outdated | awk '{print($1, "==", $3)}' | tail -n +3)
        n=$(echo "$l" | wc -l | awk '{print($1)}')
        tput setaf 6;echo "[~] $n packages to upgrade";tput sgr0
        i=0
        for line in $l
        do
                pip install $line --upgrade -q 2> /dev/null
                (( i = i+1 ))
                echo -ne "$i/$n\r"
        done
        tput setaf 4;echo "[*] pip and python packages upgraded";tput sgr0
fi

# Install go
if [[ ! -x "$(command -v go)" || $force ]];then
        echo "[+] golang not detected...Installing"
        sudo apt-get install golang -y > /dev/null
fi

# Install Ruby
if [[ ! -x "$(command -v gem)" || $force ]];then
        echo "[+] Rubby not detected...Installing"
        sudo apt-get install ruby-dev -y > /dev/null
fi

# Install Java
if [[ ! -x "$(command -v java)" || $force ]];then
        echo "[+] Java not detected...Installing"
        sudo apt-get install default-jdk -y > /dev/null
fi

# Install make
if [[ ! -x "$(command -v make)" || $force ]];then
        echo "[+] Make not detected...Installing"
        sudo apt-get install make -y > /dev/null
fi

# Install git
if [[ ! -x "$(command -v git)" || $force ]];then
        echo "[+] git not detected...Installing"
        sudo apt-get install git -y > /dev/null
fi

## Commands
# Install autoenum
if [[ ! -x "$(command -v autoenum)" || $check || $force ]];then
        echo "[+] autoenum not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh -q
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
fi

# Install start
if [[ ! -x "$(command -v start)" || $check || $force ]];then
        echo "[+] start not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh -q
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
fi

# Install ftp module
if [[ ! -x "$(pip list | grep pyftpdlib)" || $force ]];then
        echo "[+] Pyftplib not detected...Installing"
        sudo pip install pyftpdlib -q 2> /dev/null
fi

# Install impacket
if [[ ! -d "/usr/share/doc/python-impacket" || $force ]];then
        echo "[+] Impacket not detected...Installing"
        sudo pip install impacket -q 2> /dev/null
        git clone https://github.com/fortra/impacket --quiet > /dev/null
        sudo cp impacket/exemples/* /bin
        sudo mv impacket /usr/share/doc/python-impacket
        printf "#! /bin/sh\nls /usr/share/doc/python-impacket/examples/" > impacket_script
        chmod +x impacket_script
        sudo mv impacket_script /bin/impacket_script
fi

# Install dnsutils
if [[ ! -x "$(command -v dig)" || $force ]];then
        echo "[+] dig not detected...Installing"
        sudo apt-get install dnsutils > /dev/null
fi

# Install sublist3r
if [[ ! -x "$(command -v sublist3r)" || $force ]];then
        echo "[+] sublist3r not detected...Installing"
        sudo git clone https://github.com/aboul3la/Sublist3r.git --quiet > /dev/null
        pip install -r Sublist3r/requirements.txt -q 2> /dev/null
        sudo mv Sublist3r/sublist3r.py /bin/sublist3r
        sudo mv Sublist3r/subbrute /lib/python3/dist-packages/subbrute
        sudo rm Sublist3r/*
        sudo rm -R Sublist3r
fi

# Install assetfinder
if [[ ! -x "$(command -v assetfinder)" || $force ]];then
        echo "[+] assetfinder not detected...Installing"
        go install github.com/tomnomnom/assetfinder@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/assetfinder /bin/assetfinder
fi

# Install amass
if [[ ! -x "$(command -v amass)" || $force ]];then
        echo "[+] amass not detected...Installing"
        go install github.com/owasp-amass/amass/v4/...@master 2> /dev/null
        sudo cp /home/$usr/go/bin/amass /bin/amass
fi

# Install gowitness
if [[ ! -x "$(command -v gowitness)" || $force ]];then
        echo "[+] Gowitness not detected...Installing"
        go install github.com/sensepost/gowitness@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/gowitness /bin/gowitness
fi

# Install subjack
if [[ ! -x "$(command -v subjack)" || $force ]];then
        echo "[+] Subjack not detected...Installing"
        go install github.com/haccer/subjack@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/subjack /bin/subjack
fi

# Install certspotter
if [[ ! -x "$(command -v certspotter)" || $force ]];then
        echo "[+] certspotter not detected...Installing"
        go install software.sslmate.com/src/certspotter/cmd/certspotter@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/certspotter /bin/certspotter
fi

# Install httprobe
if [[ ! -x "$(command -v httprobe)" || $force ]];then
        echo "[+] httprobe not detected...Installing"
        go install github.com/tomnomnom/httprobe@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/httprobe /bin/httprobe
fi

# Install waybackurls
if [[ ! -x "$(command -v waybackurls)" || $force ]];then
        echo "[+] waybackurls not detected...Installing"
        go install github.com/tomnomnom/waybackurls@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/waybackurls /bin/waybackurls
fi

# Install testssl
if [[ ! -x "$(command -v testssl)" || $force ]];then
        echo -e "[+] Testssl not detected...Installing"
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git --quiet > /dev/null
        sudo mv testssl.sh /lib32/testssl
        printf "#! /bin/sh\nsudo /lib32/testssl/testssl.sh \$@" > testssl
        chmod +x testssl
        sudo mv testssl /bin/testssl
fi

# Install nmap
if [[ ! -x "$(command -v nmap)" || $force ]];then
        echo "[+] nmap not detected...Installing"
        sudo apt-get install nmap -y > /dev/null
fi

# Install nikto
if [[ ! -x "$(command -v nikto)" || $force ]];then
        echo "[+] nikto not detected. Installing..."
        sudo apt-get install nikto -y > /dev/null
fi

# Install gobuster
if [[ ! -x "$(command -v gobuster)" || $force ]];then
        echo "[+] gobuster not detected. Installing..."
        sudo apt-get install gobuster -y > /dev/null
fi

# Install whatweb
if [[ ! -x "$(command -v whatweb)" || $force ]];then
       echo "[+] whatweb not detected. installing..."
        sudo apt-get install whatweb -y > /dev/null
fi

# Install onewistyone
if [[ ! -x "$(command -v onesixtyone)" || $force ]];then
        echo "[+] onesixtyone not detected. Installing..."
        sudo apt-get install onesixtyone -y > /dev/null
fi

# Install rpcbind
if [[ ! -x "$(command -v rpcbind)" || $force ]];then
        echo "[+] rpcbind not detected. Installing..."
        sudo apt-get install rpcbind -y > /dev/null
fi

# Install snmpcheck
if [[ ! -x "$(command -v snmp-check)" || $force ]];then
        echo "[+] snmp-check not detected. Installing..."
        sudo apt-get install snmpcheck -y > /dev/null
fi

# Install snmpwalk
if [[ ! -x "$(command -v snmpwalk)" || $force ]];then
        echo "[+] snmpwalk not detected. Installing..."
        sudo apt-get install snmp -y > /dev/null
fi

# Install fierce
if [[ ! -x "$(command -v fierce)" || $force ]];then
        echo "[+] fierce not detected. Installing..."
        sudo apt-get install fierce -y > /dev/null
fi

# Install dnsrecon
if [[ ! -x "$(command -v dnsrecon)" || $force ]];then
        echo "[+] dnsrecon not detected. Installing..."
        sudo apt-get install dnsrecon -y > /dev/null
fi

# Install dnsenum
if [[ ! -x "$(command -v dnsenum)" || $force ]];then
        echo "[+] dnsenum not detected. Installing..."
        sudo apt-get install dnsenum -y > /dev/null
fi

# Install oscanner
if [[ ! -x "$(command -v oscanner)" || $force ]];then
        echo "[+] oscanner not detected. Installing..."
        sudo apt-get install oscanner -y > /dev/null
fi

# Install wafw00f
if [[ ! -x "$(command -v wafw00f)" || $force ]];then
        echo "[+] wafw00f not detected. Installing..."
        sudo apt-get install wafw00f -y > /dev/null
fi

# Install odat
if [[ ! -x "$(command -v odat)" || $force ]];then
        echo "[+] odat not detected. installing..."
        sudo wget https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz -q
        sudo tar xzf odat-linux-libc2.17-x86_64.tar.gz
        sudo mv odat-libc2.17-x86_64 /lib32/odat_lib
        printf "#! /bin/sh\nsudo /lib32/odat_lib/odat-libc2.17-x86_64 \$@" > odat
        chmod +x odat
        sudo mv odat /bin/odat
fi

# Install jq
if [[ ! -x "$(command -v jq)" || $force ]];then
        echo "[+] jq not detected. installing..."
        sudo apt-get install jq -y > /dev/null
fi


## Services
# Install bloodhound
if [[ ! -x "$(command -v bloodhound)" || $force ]];then
        echo "[+] Bloodhound not detected...Installing"
        sudo apt-get install bloodhound -y > /dev/null
        tput setaf 6;echo "[~] Go to http://localhost:7474 to set new neo4j password";tput sgr0
fi

if [[ ! -f "$hotscript/Invoke-Bloodhound.ps1" || $force ]];then
        echo "[+] Invoke-Bloodhound not detected...Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 -q
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
fi

if [[ ! "$(java --version)" =~ "openjdk 11.0.18" || $force ]];then
        echo "[+] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
fi

# Install Nessus
if [[ -f "/opt/nessus/sbin/nessusd" || $force ]];then
        echo "[+] Nessus not detected...Installing"
        curl -s --request GET \
               --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.5.3-debian10_amd64.deb' \
               --output 'Nessus.deb' > /dev/null
        sudo apt-get install ./Nessus.deb -y > /dev/null
        rm Nessus.deb
        sudo systemctl start nessusd
        tput setaf 6;echo "[~] Go to http://localhost:8834 to complete nessus installation";tput sgr0
fi


## Hot scripts
# Install dns2cat & dependencies
if [[ ! -d "/lib/dnscat" || $force ]];then
        echo "[+] Dnscat sourcecode not detected...Installing"
        git clone https://github.com/iagox86/dnscat2.git --quiet > /dev/null
        sudo mv dnscat2 /lib/dnscat
        # correct minor sourcecode error
        sudo sed -i 's/return a.value.ptr == a.value.ptr/return a.value.ptr == b.value.ptr/g' /lib/dnscat/client/libs/ll.c
fi

if [[ ! -f "$hotscript/dnscat" || $force ]];then
        echo "[+] Dnscat client not detected...Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        make > /dev/null
        mv dnscat $hotscript/dnscat
        cd $workingdir
fi

if [[ ! -x "$(command -v dnscat)" || $force ]];then
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
if [[ ! -f "$hotscript/LinPEAS.sh" || $force ]];then
        echo "[+] LinPEAS not detected...Installing"
        curl -L -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output $hotscript/LinPEAS.sh
fi

if [[ ! -f "$hotscript/WinPEAS.ps1" || $force ]];then
        echo "[+] WinPEAS powershell not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -q
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
fi

if [[ ! -f "$hotscript/WinPEAS.bat" || $force ]];then
        echo "[+] WinPEAS bat not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -q
        mv winPEAS.bat $hotscript/WinPEAS.bat
fi

# Install miranda
if [[ ! -f "$hotscript/miranda.py" || $force ]];then
        echo "[+] Miranda not detected...Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
fi

# Install pspy
if [[ ! -f "$hotscript/pspy32" || $force ]];then
        echo "[+] Pspy32 not detected...Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 --output $hotscript/pspy32
fi

if [[ ! -f "$hotscript/pspy64" || $force ]];then
        echo "[+] Pspy64 not detected...Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 --output $hotscript/pspy64
fi

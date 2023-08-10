#! /bin/bash$


echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.1.3"
echo "Script version : V1.3"
echo ""
echo ""

apt_installation () {
        if [[ $# -eq 0 || $# -gt 3 ]];then tput setaf 1;echo "[!] DEBUG : $# argument given for apt installation, when only 1, 2 or 3 are accepted... ($@)";tput sgr0; return; fi 
        if [[ $# -eq 1 ]];then name=$1; pkg=$1; fi
        if [[ $# -eq 2 ]];then name=$2; pkg=$2; fi
        if [[ $# -eq 3 ]];then =$2; pkg=$3; fi
        if [[ ! -x "$(command -v $1)" || $force ]];then
                echo "[+] $name not detected... Installing"
                sudo apt-get install $pkg -y > /dev/null
        fi
}

# Manage options
branch="main"
check="1"
force=""
no_upgrade=""

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
      exit 1
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
if [[ $branch != "main" && $check ]];then tput setaf 4;echo "[*] $branch will be the used github branch for installation";tput sgr0;fi
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

# colors
apt_installation "tput" "tput" "ncurses-bin"

# PenEnv
###### Install install_penenv
if [[ ! -x "$(command -v install_penenv)" || $check || $force ]];then
        echo "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh -q
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi

###### Install autoenum
if [[ ! -x "$(command -v autoenum)" || $check || $force ]];then
        echo "[+] autoenum not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh -q
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
fi

###### Install start
if [[ ! -x "$(command -v start)" || $check || $force ]];then
        echo "[+] start not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh -q
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
fi

if [[ $check ]];then
        tput setaf 6;echo "[~] Checking done... Reloading command";tput sgr0
        echo "";
        install_penenv $ORIGINAL_ARGS -nc
        exit 1
fi

## Languages and downloaders
###### Upgrade apt
if [[ ! $no_upgrade ]];then
        echo "[+] Updating apt-get and upgrading installed packages... This may take a while"
        sudo apt-get update > upgrade
        sudo apt-get upgrade -y > upgrade
        sudo apt-get autoremove -y > upgrade; rm upgrade
        tput setaf 4;echo "[*] apt-get updated and upgraded";tput sgr0
fi

###### Install python3
apt_installation "python3"

###### Install 2to3
apt_installation "2to3"

###### Install pip
if [[ ! -x "$(command -v pip)" || $force ]];then
        if [[ ! -x "$(command -v pip3)" || $force ]];then
                echo "[+] pip not detected... Installing"
                sudo apt-get install python3-pip -y > /dev/null
        fi
        # Check if an alias is needed
        if [[ ! -x "$(command -v pip)" ]];then
                echo "[+] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
        fi
fi

###### Upgrade pip
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

###### Install poetry
if [[ ! -x "$(command -v poetry)" || $force ]];then
        echo "[+] poetry not detected... Installing"
        curl -sSL https://install.python-poetry.org | python3 > /dev/null
fi

###### Install go
apt_installation "go" "golang"

###### Install Ruby
apt_installation "gem" "Ruby" "ruby-dev"

###### Install Java
apt_installation "java" "Java" "default-jdk"

###### Install Nodejs
apt_installation "node" "NodeJS" "nodejs"

###### Install npm
apt_installation "npm"

###### Install yarn
if [[ ! -x "$(command -v yarn)" || $force ]];then
        echo "[+] Yarn not detected... Installing"
        sudo npm install --silent --global yarn 2> /dev/null
fi

###### Install make
apt_installation "make"

###### Install git
apt_installation "git"

###### Install krb5
apt_installation "kinit" "Kerberos" "krb5-user"

# Commands
###### Install ftp module
if [[ ! "$(pip list | grep pyftpdlib)" || $force ]];then
        echo "[+] Pyftplib not detected... Installing"
        sudo pip install pyftpdlib -q 2> /dev/null
fi

###### Install dnsutils
apt_installation "dig" "dig" "dnsutils"

###### Install google-chrome
if [[ ! -x "$(command -v google-chrome)" || $force ]];then
        echo "[+] google-chrome not detected... Installing"
        wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -q
        sudo apt-get install ./google-chrome-stable_current_amd64.deb -y > /dev/null
        rm google-chrome-stable_current_amd64.deb
fi

###### Install jq
apt_installation "jq"

# Tools
## Web scan
### Subdomain & paths
###### Install sublist3r
if [[ ! -x "$(command -v sublist3r)" || $force ]];then
        echo "[+] sublist3r not detected... Installing"
        if [[ -d "/lib/python3/dist-packages/subbrute" ]];then
                sudo mv /lib/python3/dist-packages/subbrute /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/python3/dist-packages/subbrute to /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        sudo git clone https://github.com/aboul3la/Sublist3r.git --quiet > /dev/null
        pip install -r Sublist3r/requirements.txt -q 2> /dev/null
        sudo mv Sublist3r/sublist3r.py /bin/sublist3r
        sudo mv Sublist3r/subbrute /lib/python3/dist-packages/subbrute
        sudo rm Sublist3r/*
        sudo rm -R Sublist3r
fi

###### Install assetfinder
if [[ ! -x "$(command -v assetfinder)" || $force ]];then
        echo "[+] assetfinder not detected... Installing"
        go install github.com/tomnomnom/assetfinder@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/assetfinder /bin/assetfinder
fi

###### Install amass
if [[ ! -x "$(command -v amass)" || $force ]];then
        echo "[+] amass not detected... Installing"
        go install github.com/owasp-amass/amass/v4/...@master 2> /dev/null
        sudo cp /home/$usr/go/bin/amass /bin/amass
fi

###### Install gowitness
if [[ ! -x "$(command -v gowitness)" || $force ]];then
        echo "[+] Gowitness not detected... Installing"
        go install github.com/sensepost/gowitness@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/gowitness /bin/gowitness
fi

###### Install subjack
if [[ ! -x "$(command -v subjack)" || $force ]];then
        echo "[+] Subjack not detected... Installing"
        go install github.com/haccer/subjack@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/subjack /bin/subjack
fi

###### Install certspotter
if [[ ! -x "$(command -v certspotter)" || $force ]];then
        echo "[+] certspotter not detected... Installing"
        go install software.sslmate.com/src/certspotter/cmd/certspotter@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/certspotter /bin/certspotter
fi

###### Install dnsrecon
apt_installation "dnsrecon"

###### Install dnsenum
apt_installation "dnsenum"

###### Install waybackurls
if [[ ! -x "$(command -v waybackurls)" || $force ]];then
        echo "[+] waybackurls not detected... Installing"
        go install github.com/tomnomnom/waybackurls@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/waybackurls /bin/waybackurls
fi

### Fuzzers
###### Install gobuster
apt_installation "gobuster"

###### Install whatweb
apt_installation "whatweb"

### Others
###### Install wappalyzer
if [[ ! -x "$(command -v wappalyzer)" || $force ]];then
        echo "[+] wappalyzer not detected... Installing"
        if [[ -d "/lib/wappalyzer" ]];then
                sudo mv /lib/wappalyzer /lib/wappalyzer-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/wappalyzer to /lib/wappalyzer-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone https://github.com/wappalyzer/wappalyzer.git --quiet > /dev/null
        sudo mv wappalyzer /lib/wappalyzer
        workingdir=$(pwd)
        cd /lib/wappalyzer
        # correct minor sourcecode error
        sudo sed -i 's/this.analyzedURLS[url.href]?.status/this.analyzedURLS[url.href].status/g' /lib/wappalyzer/src/drivers/npm/drivers.js
        yarn install --silent 2>/dev/null >/dev/null
        yarn run link --silent 2>/dev/null >/dev/null
        cd $workingdir
        printf "#! /bin/sh\nsudo node /lib/wappalyzer/src/drivers/npm/cli.js \$@" > wappalyzer
        chmod +x wappalyzer
        sudo mv wappalyzer /bin/wappalyzer
fi

###### Install testssl
if [[ ! -x "$(command -v testssl)" || $force ]];then
        echo -e "[+] Testssl not detected... Installing"
        if [[ -d "/lib32/testssl" ]];then
                sudo mv /lib32/testssl /lib32/testssl-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib32/testssl to /lib32/testssl-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git --quiet > /dev/null
        sudo mv testssl.sh /lib32/testssl
        printf "#! /bin/sh\nsudo /lib32/testssl/testssl.sh \$@" > testssl
        chmod +x testssl
        sudo mv testssl /bin/testssl
fi

###### Install nikto
apt_installation "nikto"

###### Install wafw00f
apt_installation "wafw00f"

###### Install httprobe
if [[ ! -x "$(command -v httprobe)" || $force ]];then
        echo "[+] httprobe not detected... Installing"
        go install github.com/tomnomnom/httprobe@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/httprobe /bin/httprobe
fi

### Bruteforce


### Network
###### Install nmap
apt_installation "nmap"

###### Install onewistyone
apt_installation "onesixtyone"

###### Install rpcbind
apt_installation "rpcbind"

###### Install snmpcheck
apt_installation "snmp-check" "snmp-check" "snmpcheck"

###### Install snmpwalk
apt_installation "snmpwalk" "snmpwalk" "snmp"

### Exploits


### Others
###### Install impacket
apt_installation "impacket-ntlmrelayx" "impacket" "impacket-scripts"

###### Install fierce
apt_installation "fierce"

###### Install oscanner
apt_installation "oscanner"

###### Install odat
if [[ ! -x "$(command -v odat)" || $force ]];then
        echo "[+] odat not detected... Installing"
        if [[ -d "/lib32/odat_lib" ]];then
                sudo mv /lib32/odat_lib /lib32/odat_lib-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib32/odat_lib to /lib32/odat_lib-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        wget https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz -q
        sudo tar xzf odat-linux-libc2.17-x86_64.tar.gz
        sudo rm odat-linux-libc2.17-x86_64.tar.gz
        sudo mv odat-libc2.17-x86_64 /lib32/odat_lib
        printf "#! /bin/sh\nsudo /lib32/odat_lib/odat-libc2.17-x86_64 \$@" > odat
        chmod +x odat
        sudo mv odat /bin/odat
fi

###### Install crackmapexec
if [[ ! -x "$(command -v crackmapexec)" || $force ]];then
        echo "[+] crackmapexec not detected... Installing"
        if [[ -d "/lib/crackmapexec" ]];then
                sudo mv /lib/crackmapexec /lib/crackmapexec-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/crackmapexec to /lib/crackmapexec-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential > /dev/null
        git clone https://github.com/mpgn/CrackMapExec --quiet > /dev/null
        sudo mv CrackMapExec /lib/crackmapexec
        workingdir=$(pwd)
        cd /lib/crackmapexec
        poetry install >/dev/null
        poetry run crackmapexec >/dev/null
        cd $workingdir
        printf "#! /bin/sh\ncd /lib/crackmapexec\nsudo poetry run crackmapexec \$@" > crackmapexec
        chmod +x crackmapexec
        sudo mv crackmapexec /bin/crackmapexec
        printf "#! /bin/sh\ncd /lib/crackmapexec\nsudo poetry run crackmapexec \$@" > cme
        chmod +x cme
        sudo mv cme /bin/cme
        printf "#! /bin/sh\ncd /lib/crackmapexec\nsudo poetry run cmedb \$@" > cmedb
        chmod +x cmedb
        sudo mv cmedb /bin/cmedb
fi

###### Install cewl
apt_installation "cewl"



## Hot scripts
###### Install dnscat2 & dependencies
if [[ ! -d "/lib/dnscat" || $force ]];then
        echo "[+] Dnscat sourcecode not detected... Installing"
        if [[ -d "/lib/dnscat" ]];then
                sudo mv /lib/dnscat /lib/dnscat-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/dnscat to /lib/dnscat-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
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
        sudo bundler install 2>/dev/null >/dev/null
        cd $workingdir
        
        echo "[+] Creating command..."
        printf "#! /bin/sh\nsudo ruby /lib/dnscat/server/dnscat2.rb \$@" > dnscat
        chmod +x dnscat
        sudo mv dnscat /bin/dnscat
fi

###### Install PEAS
if [[ ! -f "$hotscript/LinPEAS.sh" || $force ]];then
        echo "[+] LinPEAS not detected... Installing"
        curl -L -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output $hotscript/LinPEAS.sh
        chmod +x $hotscript/LinPEAS.sh
fi

if [[ ! -f "$hotscript/WinPEAS.ps1" || $force ]];then
        echo "[+] WinPEAS powershell not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -q
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
        chmod +x $hotscript/WinPEAS.ps1
fi

if [[ ! -f "$hotscript/WinPEAS_internet.ps1" || $force ]];then
        echo "[+] WinPEAS internet not detected... Installing"
        printf "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')" > $hotscript/WinPEAS_internet.ps1
        chmod +x $hotscript/WinPEAS_internet.ps1
fi

if [[ ! -f "$hotscript/WinPEAS.bat" || $force ]];then
        echo "[+] WinPEAS bat not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -q
        mv winPEAS.bat $hotscript/WinPEAS.bat
        chmod +x $hotscript/WinPEAS.bat
fi

###### Install miranda
if [[ ! -f "$hotscript/miranda.py" || $force ]];then
        echo "[+] Miranda not detected... Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
        chmod +x $hotscript/miranda.py
        2to3 $hotscript/miranda.py -w $hotscript/miranda.py 2> /dev/null
        sed -i 's/        /\t/g' $hotscript/miranda.py
        sed -i 's/import IN/# import IN/g' $hotscript/miranda.py
        sed -i 's/socket.sendto(data/socket.sendto(data.encode()/g' $hotscript/miranda.py
fi

###### Install pspy
if [[ ! -f "$hotscript/pspy32" || $force ]];then
        echo "[+] Pspy32 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 --output $hotscript/pspy32
        chmod +x $hotscript/pspy32
fi

if [[ ! -f "$hotscript/pspy64" || $force ]];then
        echo "[+] Pspy64 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 --output $hotscript/pspy64
        chmod +x $hotscript/pspy64
fi


## Services
###### Install bloodhound
apt_installation "bloodhound"

if [[ ! -f "$hotscript/Invoke-Bloodhound.ps1" || $force ]];then
        echo "[+] Invoke-Bloodhound not detected... Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 -q
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
fi

if [[ ! "$(java --version)" =~ "openjdk 11.0.18" || $force ]];then
        echo "[+] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
fi

###### Install Nessus
if [[ -f "/opt/nessus/sbin/nessusd" || $force ]];then
        echo "[+] Nessus not detected... Installing"
        file=$(curl -s --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus' | grep -o -P "Nessus-\d+\.\d+\.\d+-debian10_amd64.deb" | head -n 1)
        curl -s --request GET \
               --url "https://www.tenable.com/downloads/api/v2/pages/nessus/files/$file" \
               --output 'Nessus.deb'
        sudo apt-get install ./Nessus.deb -y > /dev/null
        rm Nessus.deb
        sudo systemctl start nessusd
        tput setaf 6;echo "[~] Go to https://localhost:8834 to complete nessus installation";tput sgr0
fi


#! /bin/bash
# TODO : sudo ticket BEFORE creating artifact folder
#        and such as sudo is asked only once
# TODO : do logging and state functions

start=$(date +%s)

echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.2.3"
echo "Script version : V1.8"
echo ""
echo ""



wait_pid() {
        if [[ $# -eq 0 ]];then return; fi
        while [[ -e "/proc/$1" ]];do sleep 1;done
}


apt_installation () {
        if [[ $# -eq 0 || $# -gt 3 ]];then tput setaf 1;echo "[!] DEBUG : $# argument given for apt installation, when only 1, 2 or 3 are accepted... ($@)";tput sgr0; return; fi 
        if [[ $# -eq 1 ]];then name=$1; pkg=$1; fi
        if [[ $# -eq 2 ]];then name=$2; pkg=$2; fi
        if [[ $# -eq 3 ]];then name=$2; pkg=$3; fi
        if [[ ! -x "$(command -v $1)" || $force ]];then
                echo "[+] $name not detected... Installing"
                wait_apt
                sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install $pkg -yq 2>>$log/install-errors.log >>$log/install-infos.log
        fi
}

go_installation () {
        if [[ $# -ne 2 ]];then tput setaf 1;echo "[!] DEBUG : $# argument given for go installation, when 2 are required... ($@)";tput sgr0; return; fi 
        if [[ ! -x "$(command -v $1)" || $force ]];then
                echo "[+] $1 not detected... Installing"
                go install $2 2>> $log/install-warnings.log
                sudo cp /home/$usr/go/bin/$1 /bin/$1
        fi
}



bg_proc=()
apt_proc=()
pip_proc=()

installation () {
        if [[ $# -eq 0 ]];then tput setaf 1;echo "[!] DEBUG : No arguments but need at least 1... Cannot procceed to installation";tput sgr0;return;fi
        if [[ "$(type $1 | grep 'not found')" ]];then tput setaf 1;echo "[!] DEBUG : $1 is not a defined function... Cannot procceed to installation";tput sgr0;return;fi
        ($@) &
        p=$!
}
bg_install () {
        p=-1
        installation $@
        if [[ $p -ne -1 ]];then bg_proc+=( $p );fi
}
apt_install () {
        p=-1
        installation $@
        if [[ $p -ne -1 ]];then apt_proc+=( $p );fi
}
pip_install () {
        p=-1
        installation $@
        if [[ $p -ne -1 ]];then pip_proc+=( $p );fi
}

wait_bg () {
        for job in "${bg_proc[@]}"
        do
                wait_pid $job
        done
}

wait_apt () {
        for job in "${apt_proc[@]}"
        do
                wait_pid $job
        done
}

wait_pip () {
        for job in "${pip_proc[@]}"
        do
                wait_pid $job
        done
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
if [[ $no_upgrade ]];then tput setaf 4;echo "[*] apt, pip and metasploit will not be upgraded";tput sgr0; fi
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
if [[ ! -d $hotscript ]];then
        echo "[+] Creating hotscript folder in $hotscript"
        mkdir $hotscript
fi

# Trap ctrl+Z to remove artifacts before exiting
artifacts="/home/$usr/artifacts-$(date +%s)"
mkdir $artifacts
cd $artifacts
stop () {
        tput setaf 4;echo "[*] Waiting the installation to end...";tput sgr0
        wait_bg
        wait_apt
        wait_pip
        cd /home/$usr
        if [[ -d $artifacts ]];then
                sudo rm -R $artifacts
                tput setaf 6;echo "[~] Artifacts removed";tput sgr0
                echo ""
        fi
        exit 1
}
trap stop INT


# colors
bg_install apt_installation "tput" "tput" "ncurses-bin"

# PenEnv
###### Install install-penenv
task-ipenenv() {
if [[ ! -x "$(command -v install-penenv)" || $check || $force ]];then
        echo "[+] install-penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh -q
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install-penenv
fi
}
bg_install task-ipenenv

###### Install autoenum
task-autoenum() {
if [[ ! -x "$(command -v autoenum)" || $check || $force ]];then
        echo "[+] autoenum not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh -q
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
fi
}
bg_install task-autoenum

###### Install start
task-start() {
if [[ ! -x "$(command -v start)" || $check || $force ]];then
        echo "[+] start not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh -q
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
fi
}
bg_install task-start

if [[ $check ]];then
        wait_bg
        tput setaf 6;echo "[~] Checking done... Reloading command";tput sgr0
        cd /home/$usr
        sudo rm -R $artifacts
        tput setaf 6;echo "[~] Chekings Artifacts removed";tput sgr0
        echo ""
        install-penenv $ORIGINAL_ARGS -nc
        exit 1
fi

## Languages and downloaders
###### Upgrade apt
if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        echo "[+] Updating apt-get and upgrading installed packages... This may take a while"
        apt-task() {
        sudo apt-get -o DPkg::Lock::Timeout=600 update > /dev/null
        sudo apt-get -o DPkg::Lock::Timeout=600 upgrade -y > /dev/null
        sudo apt-get -o DPkg::Lock::Timeout=600 autoremove -y > /dev/null
        tput setaf 4;echo "[*] apt-get updated and upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)";tput sgr0
        }
        apt_install apt-task
fi

###### Install python3
bg_install apt_installation "python3"

###### Install 2to3
bg_install apt_installation "2to3"

###### Install pip
(if [[ ! -x "$(command -v pip)" || $force ]];then
        if [[ ! -x "$(command -v pip3)" || $force ]];then
                echo "[+] pip not detected... Installing"
                sudo apt-get -o DPkg::Lock::Timeout=600 install python3-pip -y >> $log/install-infos.log
        fi
        # Check if an alias is needed
        if [[ ! -x "$(command -v pip)" ]];then
                echo "[+] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
        fi
fi

###### Upgrade pip
if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        echo "[+] Upgrading pip and python packages... This may take a while"
        pip install --upgrade pip -q 2>> $log/install-warnings.log
        l=$(pip list --outdated | awk '{print($1)}' | tail -n +3)
        n=$(echo "$l" | wc -l | awk '{print($1)}')
        tput setaf 6;echo "[~] $n packages to upgrade";tput sgr0
        # i=0
        for line in $l
        do
                pip_install pip install $line --upgrade -q 2>> $log/install-warnings.log
                # (( i = i+1 ))
                # str="$i/$n  | currently upgrading $line"
                # cols=$(tput cols)
                # pad=$(printf ' %.0s' $(seq 1 $(($cols - ${#str}%$cols))))
                # ret=$(printf '\r%.0s' $(seq 1 $((${#str}/$cols + 1))))
                # echo -ne "$str$pad$ret"
        done
        tput setaf 4;echo "[*] pip and python packages upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)";tput sgr0
fi

###### Install poetry
if [[ ! -x "$(command -v poetry)" || $force ]];then
        echo "[+] poetry not detected... Installing"
        curl -sSL https://install.python-poetry.org | python3 >> $log/install-infos.log
fi) &

###### Install go
(if [[ ! -x "$(command -v go)" || ! "$(go version)" =~ "1.20" || $force ]];then
        echo "[+] go 1.20 not detected... Installing"
        wget  https://go.dev/dl/go1.20.2.linux-amd64.tar.gz -q
        sudo tar xzf go1.20.2.linux-amd64.tar.gz 
        if [[ -d "/usr/local/go" ]];then
                sudo mv /usr/local/go /usr/local/go-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /usr/local/go to /usr/local/go-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        sudo mv go /usr/local
        export GOROOT=/usr/local/go 
        export GOPATH=$HOME/Projects/Proj1 
        export PATH=$GOPATH/bin:$GOROOT/bin:$PATH 
fi) &

###### Install Ruby
bg_install apt_installation "gem" "Ruby" "ruby-dev"

###### Install Java
bg_install apt_installation "java" "Java" "default-jdk"

###### Install Nodejs
task-js() {
apt_installation "node" "NodeJS" "nodejs"

###### Install npm
apt_installation "npm"

###### Install yarn
if [[ ! -x "$(command -v yarn)" || $force ]];then
        echo "[+] Yarn not detected... Installing"
        sudo npm install --silent --global yarn 2>> $log/install-warnings.log
fi
}
bg_install task-js

###### Install rust
task-rust() {
if [[ ! -x "$(command -v cargo)" || $force ]];then
        echo "[+] Rust not detected... Installing"
        curl -s https://sh.rustup.rs -sSf | sh -s >>$log/install-infos.log 2>>$log/install-errors.log -- -y
fi
}
bg_install task-rust

###### Install make
bg_install apt_installation "make"

###### Install mono
task-mono() {
if [[ ! -x "$(command -v mozroots)" || $force ]];then
        echo "[+] Mono not detected... Installing"
        sudo apt-get -o DPkg::Lock::Timeout=600 install -yq dirmngr ca-certificates gnupg >>$log/install-infos.log 2>>$log/install-errors.log 
        sudo gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF 2>>$log/install-warnings.log >>$log/install-infos.log
        echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list >/dev/null
        sudo apt-get -o DPkg::Lock::Timeout=600 install -yq mono-devel >>$log/install-infos.log 2>>$log/install-errors.log 
fi
}
bg_install task-mono

###### Install dotnet
task-dotnet() {
if [[ ! -x "$(command -v dotnet)" || $force ]];then
        wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh -q
        chmod +x ./dotnet-install.sh
        ./dotnet-install.sh --version latest 2>>$log/install-errors.log >>$log/install-infos.log
fi
}
bg_install task-dotnet

###### Install git
bg_install apt_installation "git"

###### Install krb5
bg_install apt_installation "kinit" "Kerberos" "krb5-user"


wait_bg



# Commands
###### Install ftp module
task-ftp() {
if [[ ! "$(pip list | grep pyftpdlib)" || $force ]];then
        echo "[+] Pyftplib not detected... Installing"
        wait_pip
        sudo pip install pyftpdlib -q 2>> $log/install-warnings.log
fi
}
bg_install task-ftp

###### Install dnsutils
bg_install apt_installation "dig" "dig" "dnsutils"

###### Install google-chrome
task-chrome() {
if [[ ! -x "$(command -v google-chrome)" || $force ]];then
        echo "[+] google-chrome not detected... Installing"
        wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -q
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./google-chrome-stable_current_amd64.deb -y >> $log/install-infos.log
        rm google-chrome-stable_current_amd64.deb
fi
}
bg_install task-chrome

###### Install jq
bg_install apt_installation "jq"

###### Install expect
bg_install apt_installation "unbuffer" "expect"

# Tools
## Web scan
### Subdomain & paths
###### Install sublist3r
task-sublister() {
if [[ ! -x "$(command -v sublist3r)" || $force ]];then
        echo "[+] sublist3r not detected... Installing"
        if [[ -d "/lib/python3/dist-packages/subbrute" ]];then
                sudo mv /lib/python3/dist-packages/subbrute /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/python3/dist-packages/subbrute to /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        sudo git clone https://github.com/aboul3la/Sublist3r.git --quiet >> $log/install-infos.log
        wait_pip
        pip install -r Sublist3r/requirements.txt -q 2>> $log/install-warnings.log
        sudo mv Sublist3r/sublist3r.py /bin/sublist3r
        sudo mv Sublist3r/subbrute /lib/python3/dist-packages/subbrute
        sudo rm Sublist3r/*
        sudo rm -R Sublist3r
fi
}
bg_install task-sublister

###### Install assetfinder
bg_install go_installation "assetfinder" "github.com/tomnomnom/assetfinder@latest" 

###### Install amass
bg_install go_installation "amass" "github.com/owasp-amass/amass/v4/...@master" 

###### Install gowitness
bg_install go_installation "gowitness" "github.com/sensepost/gowitness@latest" 

###### Install subjack
bg_install go_installation "subjack" "github.com/haccer/subjack@latest" 

###### Install certspotter
bg_install go_installation "certspotter" "software.sslmate.com/src/certspotter/cmd/certspotter@latest" 

###### Install dnsrecon
bg_install apt_installation "dnsrecon" 

###### Install dnsenum
bg_install apt_installation "dnsenum" 

###### Install waybackurls
bg_install go_installation "waybackurls" "github.com/tomnomnom/waybackurls@latest" 

###### Install Arjun
task-arjun() {
if [[ ! "$(pip list | grep arjun)" || $force ]];then
        echo "[+] Arjun not detected... Installing"
        wait_pip
        sudo pip install arjun -q 2>> $log/install-warnings.log
fi
}
bg_install task-arjun

###### Install BrokenLinkChecker
task-blc() {
if [[ ! -x "$(command -v blc)" || $force ]];then
        echo "[+] BrokenLinkChecker not detected... Installing"
        sudo npm install --silent --global broken-link-checker 2>> $log/install-warnings.log
fi
}
bg_install task-blc

###### Install dirscraper
task-dirscraper() {
if [[ ! -x "$(command -v dirscraper)" || $force ]];then
        echo "[+] Dirscapper not detected... Installing"
        git clone https://github.com/Cillian-Collins/dirscraper.git --quiet >> $log/install-infos.log
        chmod +x ./dirscraper/dirscraper.py
        sudo mv dirscraper/dirscraper.py /bin/dirscraper
        wait_pip
        pip install -r ./dirscraper/requirements.txt -q 2>> $log/install-warnings.log
        sudo rm -R ./dirscraper
fi
}
bg_install task-dirscraper

###### Install Haktrails
bg_install go_installation "haktrails" "github.com/hakluke/haktrails@latest" 

###### Install Hakrawler
bg_install go_installation "hakrawler" "github.com/hakluke/hakrawler@latest" 

### Fuzzers
###### Install gobuster
bg_install apt_installation "gobuster" 

###### Install whatweb
bg_install apt_installation "whatweb" 

###### Install ffuf
bg_install go_installation "ffuf" "github.com/ffuf/ffuf/v2@latest" 

###### Install x8
task-xeight() {
if [[ ! -x "$(command -v x8)" || $force ]];then
        echo "[+] x8 not detected... Installing"
        cargo install x8 >>$log/install-infos.log 2>>$log/install-errors.log
fi
}
bg_install task-xeight

### Others
###### Install wappalyzer
task-wappalyzer() {
if [[ ! -x "$(command -v wappalyzer)" || $force ]];then
        echo "[+] wappalyzer not detected... Installing"
        if [[ -d "/lib/wappalyzer" ]];then
                sudo mv /lib/wappalyzer /lib/wappalyzer-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/wappalyzer to /lib/wappalyzer-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone https://github.com/wappalyzer/wappalyzer.git --quiet >> $log/install-infos.log
        sudo mv wappalyzer /lib/wappalyzer
        workingdir=$(pwd)
        cd /lib/wappalyzer
        # correct minor sourcecode error
        sudo sed -i 's/?././g' /lib/wappalyzer/src/drivers/npm/driver.js
        sudo sed -i 's/?././g' /lib/wappalyzer/src/drivers/npm/wappalyzer.js
        yarn install --silent 2>>$log/install-errors.log >>$log/install-infos.log
        yarn run link --silent 2>>$log/install-errors.log >>$log/install-infos.log
        cd $workingdir
        printf "#! /bin/sh\nsudo node /lib/wappalyzer/src/drivers/npm/cli.js \$@" > wappalyzer
        chmod +x wappalyzer
        sudo mv wappalyzer /bin/wappalyzer
fi
}
bg_install task-wappalyzer

###### Install testssl
task-testssl() {
if [[ ! -x "$(command -v testssl)" || $force ]];then
        echo -e "[+] Testssl not detected... Installing"
        if [[ -d "/lib32/testssl" ]];then
                sudo mv /lib32/testssl /lib32/testssl-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib32/testssl to /lib32/testssl-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git --quiet >> $log/install-infos.log
        sudo mv testssl.sh /lib32/testssl
        printf "#! /bin/sh\nsudo /lib32/testssl/testssl.sh \$@" > testssl
        chmod +x testssl
        sudo mv testssl /bin/testssl
fi
}
bg_install task-testssl

###### Install nikto
bg_install apt_installation "nikto" 

###### Install wafw00f
bg_install apt_installation "wafw00f" 

###### Install httprobe
bg_install go_installation "httprobe" "github.com/tomnomnom/httprobe@latest" 

###### Install Secretfinder
task-secretfinder() {
if [[ ! -x "$(command -v secretfinder)" || $force ]];then
        echo "[+] Secretfinder not detected... Installing"
        git clone https://github.com/m4ll0k/SecretFinder.git --quiet >> $log/install-infos.log
        chmod +x ./SecretFinder/SecretFinder.py
        sudo mv SecretFinder/SecretFinder.py /bin/secretfinder
        wait_pip
        pip install -r ./SecretFinder/requirements.txt -q 2>> $log/install-warnings.log
        sudo rm -R ./SecretFinder
fi
}
bg_install task-secretfinder

### Bruteforce
###### Install hashcat
bg_install apt_installation "hashcat"

###### Install hydra
task-hydra() {
if [[ ! -x "$(command -v hydra)" || $force ]];then
        echo "[+] Hydra not detected... Installing"
        git clone https://github.com/vanhauser-thc/thc-hydra --quiet >> $log/install-infos.log
        cd thc-hydra
        ./configure >>$log/install-infos.log 2>>$log/install-errors.log
        make >> $log/install-infos.log
        sudo make install >>$log/install-infos.log 2>>$log/install-errors.log
        sudo mv hydra /bin/hydra
        cd ..
        sudo rm -R thc-hydra
fi
}
bg_install task-hydra

###### Install john
bg_install apt_installation "john"

### Network
###### Install nmap
bg_install apt_installation "nmap"

###### Install onewistyone
bg_install apt_installation "onesixtyone"

###### Install rpcbind
bg_install apt_installation "rpcbind"

###### Install snmpcheck
bg_install apt_installation "snmp-check" "snmp-check" "snmpcheck"

###### Install snmpwalk
bg_install apt_installation "snmpwalk" "snmpwalk" "snmp"

### Exploits
###### Install Metasploit
task-metasploit() {
if [[ ! -x "$(command -v msfconsole)" || $force ]];then
        echo "[+] Metasploit not detected... Installing"
        curl -s -L https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb --output msfinstall
        chmod +x msfinstall
        sudo ./msfinstall 2>>$log/install-warnings.log >> $log/install-infos.log
        rm msfinstall
fi

if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        echo "[+] Upgrading metasploit... This may take a while"
        sudo msfupdate >>$log/install-infos.log 2>>$log/install-warnings.log
        tput setaf 4;echo "[*] Metasploit data upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)";tput sgr0
fi
}
bg_install task-metasploit

###### Install searchsploit
task-searchsploit() {
if [[ ! -x "$(command -v searchsploit)" || $force ]];then
        echo "[+] Searchsploit not detected... Installing"
        wget https://raw.githubusercontent.com/rad10/SearchSploit.py/master/searchsploit.py -q
        chmod +x searchsploit.py
        sudo mv searchsploit.py /bin/searchsploit
fi
}
bg_install task-searchsploit

###### Install AutoHackBruteOS
task-autohackbruteos() {
if [[ ! -x "$(command -v AutoHackBruteOS)" || $force ]];then
        echo "[+] AutoHackBruteOS not detected... Installing"
        (echo "#! /usr/bin/env ruby" && curl -L -s https://raw.githubusercontent.com/carlospolop/AutoHackBruteOs/master/AutoHackBruteOs.rc) > AutoHackBruteOs.rc
        chmod +x AutoHackBruteOs.rc
        sudo mv AutoHackBruteOs.rc /bin/AutoHackBruteOs
fi
}
bg_install task-autohackbruteos

###### Install sqlmap
task-sqlmap() {
if [[ ! -x "$(command -v sqlmap)" || $force ]];then
        echo "[+] sqlmap not detected... Installing"
        if [[ -d "/lib/sqlmap" ]];then
                sudo mv /lib/sqlmap /lib/sqlmap-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/sqlmap to /lib/sqlmap-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git --quiet >> $log/install-infos.log
        wait_pip
        pip install -r sqlmap/requirements.txt -q 2>> $log/install-warnings.log
        sudo mv sqlmap /lib/sqlmap
        printf "#! /bin/sh\nsudo python3 /lib/sqlmap/sqlmap.py \$@" > sqlmap
        chmod +x sqlmap
        sudo mv sqlmap /bin/sqlmap
fi
}
bg_install task-sqlmap

###### Install commix
task-commix() {
if [[ ! -x "$(command -v commix)" || $force ]];then
        echo "[+] commix not detected... Installing"
        if [[ -d "/lib/commix" ]];then
                sudo mv /lib/commix /lib/commix-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/commix to /lib/commix-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone https://github.com/commixproject/commix.git --quiet >> $log/install-infos.log
        sudo mv commix /lib/commix
        printf "#! /bin/sh\nsudo python3 /lib/commix/commix.py \$@" > commix
        chmod +x commix
        sudo mv commix /bin/commix
fi
}
bg_install task-commix

###### Install pixload
task-pixload() {
if [[ ! -x "$(command -v pixload-png)" || $force ]];then
        echo "[+] Pixload not detected... Installing"
        sudo git clone https://github.com/sighook/pixload.git --quiet >> $log/install-infos.log
        cd pixload
        make >> $log/install-infos.log 2>>$log/install-warnings.log
        sudo rm pixload-*\.*
        chmod +x pixload-*
        sudo mv pixload-* /bin
        cd ..
        sudo rm -R pixload
fi
}
bg_install task-pixload

### Others
###### Install impacket
bg_install apt_installation "impacket-ntlmrelayx" "impacket" "impacket-scripts"

###### Install fierce
bg_install apt_installation "fierce"

###### Install oscanner
bg_install apt_installation "oscanner"

###### Install odat
task-odat() {
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
}
bg_install task-odat

###### Install crackmapexec
task-crackmapexec() {
if [[ ! -x "$(command -v crackmapexec)" || $force ]];then
        echo "[+] crackmapexec not detected... Installing"
        if [[ -d "/lib/crackmapexec" ]];then
                sudo mv /lib/crackmapexec /lib/crackmapexec-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/crackmapexec to /lib/crackmapexec-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y libssl-dev libffi-dev python-dev-is-python3 build-essential >> $log/install-infos.log
        git clone https://github.com/mpgn/CrackMapExec --quiet >> $log/install-infos.log
        sudo mv CrackMapExec /lib/crackmapexec
        workingdir=$(pwd)
        cd /lib/crackmapexec
        poetry lock >>$log/install-infos.log 2>>$log/install-errors.log
        poetry install >>$log/install-infos.log 2>>$log/install-errors.log
        poetry run crackmapexec >>$log/install-infos.log 2>>$log/install-errors.log
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
}
bg_install task-crackmapexec

###### Install cewl
bg_install apt_installation "cewl"

###### Install cupp
task-cupp() {
if [[ ! -x "$(command -v cupp)" || $force ]];then
        echo "[+] Cupp not detected... Installing"
        wget https://raw.githubusercontent.com/Mebus/cupp/master/cupp.py -q
        chmod +x cupp.py
        sudo mv cupp.py /bin/cupp
fi
}
bg_install task-cupp

###### Install DDexec
task-ddexec() {
if [[ ! -x "$(command -v ddexec)" || $force ]];then
        echo "[+] DDexec not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/DDexec/main/DDexec.sh -q
        chmod +x DDexec.sh
        sudo mv DDexec.sh /bin/ddexec
fi
}
bg_install task-ddexec

###### Install openvpn
bg_install apt_installation "openvpn"

###### Install mitm6
task-mitmsix() {
if [[ ! -x "$(command -v mitm6)" || $force ]];then
        echo "[+] mitm6 not detected... Installing"
        sudo git clone https://github.com/dirkjanm/mitm6.git --quiet >> $log/install-infos.log
        wait_pip
        pip install -r mitm6/requirements.txt -q 2>> $log/install-warnings.log
        sudo chmod +x mitm6/mitm6/mitm6.py
        sudo mv mitm6/mitm6/mitm6.py /bin/mitm6
        sudo rm -R mitm6
fi
}
bg_install task-mitmsix

###### Install proxychain
task-proxychain() {
if [[ ! -x "$(command -v proxychains)" || $force ]];then
        echo "[+] Proxychain not detected... Installing"
        git clone https://github.com/haad/proxychains.git --quiet >> $log/install-infos.log
        cd proxychains
        ./configure >>$log/install-infos.log 2>>$log/install-errors.log
        make >> $log/install-infos.log
        sudo make install >>$log/install-infos.log 2>>$log/install-errors.log
        sudo mv proxychains4 /bin/proxychains
        cd ..
        sudo rm -R proxychains
fi
}
bg_install task-proxychain

###### Install responder
task-responder() {
if [[ ! -x "$(command -v responder)" || $force ]];then
        echo "[+] responder not detected... Installing"
        if [[ -d "/lib/responder" ]];then
                sudo mv /lib/responder /lib/responder-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/responder to /lib/responder-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone https://github.com/lgandx/Responder.git --quiet >> $log/install-infos.log
        sudo mv Responder /lib/responder
        printf "#! /bin/sh\nsudo python3 /lib/responder/Responder.py \$@" > responder
        chmod +x responder
        sudo mv responder /bin/responder
fi
}
bg_install task-responder

###### Install Evil winrm



## Hot scripts
###### Install dnscat2 & dependencies
task-dnscat() {
if [[ ! -d "/lib/dnscat" || $force ]];then
        echo "[+] Dnscat sourcecode not detected... Installing"
        if [[ -d "/lib/dnscat" ]];then
                sudo mv /lib/dnscat /lib/dnscat-$(date +%y-%m-%d--%T).old
                tput setaf 6;echo "[~] Moved /lib/dnscat to /lib/dnscat-$(date +%y-%m-%d--%T).old due to forced reinstallation";tput sgr0
        fi
        git clone https://github.com/iagox86/dnscat2.git --quiet >> $log/install-infos.log
        sudo mv dnscat2 /lib/dnscat
        # correct minor sourcecode error
        sudo sed -i 's/return a.value.ptr == a.value.ptr/return a.value.ptr == b.value.ptr/g' /lib/dnscat/client/libs/ll.c
fi

if [[ ! -f "$hotscript/dnscat" || $force ]];then
        echo "[+] Dnscat client not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        make >> $log/install-infos.log
        mv dnscat $hotscript/dnscat
        cd $workingdir
fi

if [[ ! -x "$(command -v dnscat)" || $force ]];then
        echo "[+] Dnscat server not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/server
        sudo gem install bundler >> $log/install-infos.log
        sudo bundler install 2>>$log/install-errors.log >>$log/install-infos.log
        cd $workingdir
        printf "#! /bin/sh\nsudo ruby /lib/dnscat/server/dnscat2.rb \$@" > dnscat
        chmod +x dnscat
        sudo mv dnscat /bin/dnscat
fi

if [[ ! -x "$(command -v dnscat-shell)" || $force ]];then
        echo "[+] dnscat shell not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/misc/dnscat-shell.sh -q
        chmod +x dnscat-shell.sh
        sudo mv dnscat-shell.sh /bin/dnscat-shell
fi}
bg_install task-dnscat

###### Install Chisel
task-chisel() {
go_installation "chisel" "github.com/jpillora/chisel@latest"
if [[ -f "$hotscript/chisel" || $force ]];then
        sudo cp $(command -v chisel) $hotscript/chisel
fi
}
bg_install task-chisel

###### Install frp
task-frp() {
if [[ ! -d "$hotscript/frp" || $force ]];then
        sudo git clone https://github.com/fatedier/frp.git --quiet >> $log/install-infos.log
        cd frp
        ./package.sh >>$log/install-infos.log 2>>$log/install-warnings.log
        mv bin $hotscript/frp
        cd ..
        rm -R frp
fi
}
bg_install task-frp

###### Install PEAS
task-lpeas() {
if [[ ! -f "$hotscript/LinPEAS.sh" || $force ]];then
        echo "[+] LinPEAS not detected... Installing"
        curl -L -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output $hotscript/LinPEAS.sh
        chmod +x $hotscript/LinPEAS.sh
fi
}
bg_install task-lpeas

task-wpeasps() {
if [[ ! -f "$hotscript/WinPEAS.ps1" || $force ]];then
        echo "[+] WinPEAS powershell not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -q
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
        chmod +x $hotscript/WinPEAS.ps1
fi
}
bg_install task-wpeasps

task-wpeasi() {
if [[ ! -f "$hotscript/WinPEAS_internet.ps1" || $force ]];then
        echo "[+] WinPEAS internet not detected... Installing"
        printf "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')" > $hotscript/WinPEAS_internet.ps1
        chmod +x $hotscript/WinPEAS_internet.ps1
fi
}
bg_install task-wpeasi

task-wpeasbat() {
if [[ ! -f "$hotscript/WinPEAS.bat" || $force ]];then
        echo "[+] WinPEAS bat not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -q
        mv winPEAS.bat $hotscript/WinPEAS.bat
        chmod +x $hotscript/WinPEAS.bat
fi
}
bg_install task-wpeasbat

###### Install miranda
task-miranda() {
if [[ ! -f "$hotscript/miranda.py" || $force ]];then
        echo "[+] Miranda not detected... Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
        chmod +x $hotscript/miranda.py
        2to3 $hotscript/miranda.py -w $hotscript/miranda.py >/dev/null 2>>$log/install-warnings.log
        sed -i 's/        /\t/g' $hotscript/miranda.py
        sed -i 's/import IN/# import IN/g' $hotscript/miranda.py
        sed -i 's/socket.sendto(data/socket.sendto(data.encode()/g' $hotscript/miranda.py
fi
}
bg_install task-miranda

###### Install pspy
task-pspy32() {
if [[ ! -f "$hotscript/pspy32" || $force ]];then
        echo "[+] Pspy32 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 --output $hotscript/pspy32
        chmod +x $hotscript/pspy32
fi
}
bg_install task-pspy32

task-pspy64() {
if [[ ! -f "$hotscript/pspy64" || $force ]];then
        echo "[+] Pspy64 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 --output $hotscript/pspy64
        chmod +x $hotscript/pspy64
fi
}
bg_install task-pspy64

###### Install rubeus

###### Install mimikatz

###### Install mimipenguin
task-mimipenguin() {
if [[ ! -f "$hotscript/mimipenguin" || $force ]];then
        echo "[+] Mimipenguin not detected... Installing"
        sudo git clone https://github.com/huntergregal/mimipenguin.git --quiet >> $log/install-infos.log
        cd mimipenguin
        sudo make >> $log/install-infos.log 2>>$log/install-warnings.log
        sudo mv mimipenguin $hotscript/mimipenguin
        sudo mv mimipenguin.py $hotscript/mimipenguin.py
        sudo mv mimipenguin.sh $hotscript/mimipenguin.sh
        cd ..
        sudo rm -R mimipenguin
fi
}
bg_install task-mimipenguin

###### Install linux-exploit-suggester-2
task-les() {
if [[ ! -f "$hotscript/linux-exploit-suggester-2.pl" || $force ]];then
        echo "[+] Linux exploit suggester 2 not detected... Installing"
        wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -q
        mv linux-exploit-suggester-2.pl $hotscript/linux-exploit-suggester-2.pl
fi
}
bg_install task-les

###### Install wesng
task-wesng() {
if [[ ! "$(command -v wes)" || $force ]];then
        echo "[+] Wesng not detected... Installing"
        wait_pip
        sudo pip install wesng -q 2>> $log/install-warnings.log
        wes --update >> $log/install-infos.log
fi
}
bg_install task-wesng

###### Install watson

###### Install powersploit

###### Install evilSSDP


## Services
###### Install bloodhound
bg_install apt_installation "bloodhound"

task-invoke-bloodhound() {
if [[ ! -f "$hotscript/Invoke-Bloodhound.ps1" || $force ]];then
        echo "[+] Invoke-Bloodhound not detected... Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 -q
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
fi
}
bg_install task-invoke-bloodhound

###### Install Nessus
task-nessus() {
if [[ ! "$(java --version)" =~ "openjdk 11.0.18" || $force ]];then
        echo "[+] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
fi

if [[ ! "$(systemctl status nessusd 2>/dev/null)" || $force ]];then
        echo "[+] Nessus not detected... Installing"
        file=$(curl -s --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus' | grep -o -P "Nessus-\d+\.\d+\.\d+-debian10_amd64.deb" | head -n 1)
        curl -s --request GET \
               --url "https://www.tenable.com/downloads/api/v2/pages/nessus/files/$file" \
               --output 'Nessus.deb'
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./Nessus.deb -y >> $log/install-infos.log
        rm Nessus.deb
        sudo systemctl start nessusd
        tput setaf 6;echo "[~] Go to https://localhost:8834 to complete nessus installation";tput sgr0
fi}
bg_install task-nessus

wait_bg

tput setaf 6;echo "[~] Installation done... Took $(date -d@$(($(date +%s)-$start)) -u +%H:%M:%S)";tput sgr0

stop

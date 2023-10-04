#! /bin/bash
# TODO : review GUI
# TODO : add task viewer, either using threds, either using logs

start=$(date +%s)

banner (){
        echo "    ____             ______          ";
        echo "   / __ \___  ____  / ____/___ _   __";
        echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
        echo " / ____/  __/ / / / /___/ / / / |/ / ";
        echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
        echo "                                     ";
        echo ""
        echo "Author : lLou_"
        echo "Suite version : V0.2.6 beta"
        echo "Script version : V2.2 beta"
        echo ""
        echo ""
}

# Get current user
usr=$(whoami)
if [[ $usr == "root" ]];then
        echo "[-] Running as root. Please run in rootless mode... Exiting..."
        exit 1
fi

# Trap ctrl+Z to remove artifacts and restore shell before exiting
artifacts="/home/$usr/artifacts-$(date +%s)"
mkdir $artifacts
cd $artifacts

# Set gui pipes
gui="$artifacts/pipe"
mkdir $gui
touch $gui/updates
echo -ne "-1" > $gui/position

# Set threading management
thread_dir="$artifacts/threads"
waiting_dir="$thread_dir/waiting"
mkdir $thread_dir
mkdir $waiting_dir

stop () {
        # wait proccesses
        add_log_entry; update_log $ret "[*] Killing remaining background process..."
        kill_bg
        kill_apt
        kill_pip
        update_log $ret "[+] All launched installation process has ended"
        # kill gui proc
        kill_pc $guiproc_id
        tput cnorm
        tput rmcup
        # report states in shell and in transcript
        transcript=$log/transcript
        echo "=========================" >> $transcript
        if [[ -d $gui ]];then
                u=$(cat $gui/updates)
                for i in $(seq 1 ${#u});do
                        if [[ -f $gui/$i ]];then cat $gui/$i; cat $gui/$i >> $transcript;fi
                done
        fi
        # restore directories
        cd /home/$usr
        if [[ -d $artifacts ]];then
                sudo rm -R $artifacts
                tput setaf 6;echo "[~] Artifacts removed";tput sgr0
                echo ""
        fi
        # remove sudoer ticket
        if [[ -f "/etc/sudoers.d/tmp" ]];then sudo rm /etc/sudoers.d/tmp; fi
        if [[ $# -eq 0 ]];then exit 1; fi
}
trap stop INT

# Common installation protocols
apt_installation () {
        if [[ $# -eq 0 || $# -gt 3 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for apt installation, when only 1, 2 or 3 are accepted... ($@)"; return; fi 
        if [[ $# -eq 1 ]];then name=$1; pkg=$1; fi
        if [[ $# -eq 2 ]];then name=$2; pkg=$2; fi
        if [[ $# -eq 3 ]];then name=$2; pkg=$3; fi
        if [[ ! -x "$(command -v $1)" || $force ]];then
                redirect_output $(get_log_file $name)
                add_log_entry; update_log $ret "[*] $name not detected... Waiting for apt upgrade"
                wait_apt
                update_log $ret "[~] $name not detected... Installing"
                # non interactive apt install, and wait 10 minutes for dpkg lock to be unlocked if needed (thanks to parrallelization)
                sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install $pkg -y
                update_log $ret "[+] $name Installed"
        fi
}

go_installation () {
        if [[ $# -ne 2 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for go installation, when 2 are required... ($@)"; return; fi 
        if [[ ! -x "$(command -v $1)" || $force ]];then
                redirect_output $(get_log_file $1)
                add_log_entry; update_log $ret "[*] $1 not detected... Waiting go to be installed"
                wait_command "go"
                update_log $ret "[~] $1 not detected... Installing"
                go install $2
                sudo cp /home/$usr/go/bin/$1 /bin/$1
                update_log $ret "[+] $1 Installed"
        fi
}


# Parrallelization function
bg_proc=() # array of process to wait for complete installation
apt_proc=() # process for apt upgrade
pip_proc=() # process for pip upgrade

# // functions
installation () {
        if [[ $# -eq 0 ]];then add_log_entry; update_log $ret "[!] DEBUG : No arguments but need at least 1... Cannot procceed to installation";return;fi
        if [[ "$(type $1 | grep 'not found')" ]];then add_log_entry; update_log $ret "[!] DEBUG : $1 is not a defined function... Cannot procceed to installation";return;fi
        while [[ $(ls $thread_dir | wc -l) -gt $thread ]];do sleep .2; done
        (file=$(date +%s%N); echo "$@" > $thread_dir/$file; $@; rm $thread_dir/$file) &
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

# wait for process to end
wait_pid() {
        if [[ $# -eq 0 ]];then return; fi
        while [[ -e "/proc/$1" ]];do sleep .2;done
}
wait_bg () {
        for job in "${bg_proc[@]}"
        do
                wait_pid $job
        done
}
wait_procs () {
        if [[ $# -ne 0 ]];then
                if [[ -f "$thread_dir/$file" ]];then mv $thread_dir/$file $waiting_dir/$file;fi # Put the thread in waiting mode if not the main thread
                for job in "$@"
                do
                        wait_pid $job
                done
                while [[ $(ls $waiting_dir | head -n1) -ne $file || $(ls $thread_dir | wc -l) -ge $thread ]];do sleep .2; done # Wait a working thread to be available again
                if [[ -f "$waiting_dir/$file" ]];then mv $waiting_dir/$file $thread_dir/$file;fi
        fi
}
wait_apt () { wait_procs ${apt_proc[@]}; }
wait_pip () { wait_procs ${pip_proc[@]}; }
wait_command() {
        (for cmd in $@;do
                while [[ ! "$(command -v $cmd)" ]];do sleep .2;done
        done) &
        wait_procs $!
}

# killing process
kill_pc () {
        for p in $@;do
                if [[ $(ps aux | awk '{print($2)}' | grep $p) ]];then sudo kill $p 2>/dev/null;fi
        done
}
kill_bg () { kill_pc ${bg_proc[@]}; }
kill_apt () { kill_pc ${apt_proc[@]}; }
kill_pip () { kill_pc ${pip_proc[@]}; }

# GUI management
# => works with pipe in artifacts
# => .update gives a char for each log entry, it is by default 0, putting it to 1 means the log entry has been updated
# => the log entry content is in $gui/$log_entry_id
# => scrolling is managed by interaction process, that gives position throught position file
# => if $gui/getting exists, wait, to avoid two entries getting the same id
add_log_entry() {
        lname=getting-$(date +%s%N)
        if [[ ! -d $gui ]];then return;fi
        touch $gui/$lname
        while [[ -d $gui && $(ls $gui | grep getting | head -n 1) -ne $lname ]];do sleep .1; done
        if [[ ! -d $gui ]];then return;fi
        printf '0' >> $gui/updates
        ret=$(wc -c $gui/updates | awk '{print($1)}')
        rm $gui/$lname
        touch $gui/$ret
        return $ret
}
update_log() {
        if [[ ! -d $gui ]]; then return; fi
        if [[ ! -f "$gui/$1" ]];then add_log_entry; update_log $ret "[!] DEBUG : $1 is not a log entry";return; fi
        echo "${@:2}" > $gui/$1
        sed -i "s/./1/$1" $gui/updates
}

gui_proc () {
        add_log_entry
        tput smcup
        tput civis

        while [[ true ]];do
                # Observe updating to reduce gui needs ?
                # And maybe sort such that Installing process are all the way down
                echo "$(tput cup 0 0)$(tput ed)$(for log in $(ls $gui | sort -g | tail -n+3);do  cat $gui/$log;done)"
                sleep 0.2
        done
}

# Manage log
get_log_file () {
        if [[ $# -ne 1 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for get_log_file, when only 1 is accepted... ($@)"; return; fi 
        if [[ $nologs ]];then echo "/dev/null";return;fi
        echo "$log/$1.log"
}
redirect_output () {
        if [[ $# -eq 0 || $# -gt 2 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# arguments but need 1 or 2... Cannot procceed to output redirection";return;fi
        if [[ $# -eq 1 ]];then err=$1;else err=$2; fi
        touch $1
        touch $err
        if [[ ! -f $1 || ! -f $err ]];then add_log_entry; update_log $ret "[!] DEBUG : error while handeling $1 and $err";return;fi
        exec >> $1
        exec 2>> $err
}

# Manage options
branch="main"
check="1"
force=""
no_upgrade=""
nologs=""
thread=5

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
    -t|--thread)
      thread=$2
      shift # past argument
      shift # past value
      ;;
    -f|--force)
      force="1"
      shift
      ;;
    -nu|--no-upgrade)
      no_upgrade="1"
      shift
      ;;
    -nl|--no-log)
      nologs="1"
      shift
      ;;
    -h|--help)
      echo "[~] Github options"
      echo "[*] -b | --branch <main|dev> (default: main) - Use this branch version of the github"
      echo "[*] -nc | --no-check - Disable the check of the branch on github"
      echo ""
      echo "[~] Misc options"
      echo "[*] -t | --thread <int> (default: 5) - Concurent threads to use"
      echo "[*] -f | --force - Force the installation even when the detection says it is installed"
      echo "[*] -nu | --no-upgrade - Disable apt and pip upgrading"
      echo "[*] -nl | --no-log - Disable logging"
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

# launch gui & get sudo ticket
printf "Defaults\ttimestamp_timeout=-1\n" | sudo tee /etc/sudoers.d/tmp > /dev/null
gui_proc &
guiproc_id=$!

# Set directory environement
log=/home/$usr/logs
hotscript=/home/$usr/hot-script
if [[ ! -d $log && ! $nologs ]];then
        add_log_entry; update_log $ret "[+] Creating log folder in $log"
        mkdir $log
fi
if [[ ! -d $hotscript ]];then
        add_log_entry; update_log $ret "[+] Creating hotscript folder in $hotscript"
        mkdir $hotscript
fi

# Inform user
add_log_entry; update_log $ret "$(banner)"
if [[ $branch != "main" && $check ]];then add_log_entry; update_log $ret "[*] $branch will be the used github branch for installation";fi
if [[ $thread != 5 ]];then add_log_entry; update_log $ret "[*] $thread additional active processes wil be used for parallel tasks";fi
if [[ $force ]];then add_log_entry; update_log $ret "[*] installation will be forced for every components"; fi
if [[ $nologs ]];then add_log_entry; update_log $ret "[*] logging is disabled"; fi
if [[ $no_upgrade ]];then add_log_entry; update_log $ret "[*] apt, pip and metasploit will not be upgraded"; fi
add_log_entry; update_log $ret ""

# colors
bg_install apt_installation "tput" "tput" "ncurses-bin"

# PenEnv
###### Install install-penenv
task-ipenenv() {
if [[ ! -x "$(command -v install-penenv)" || $check || $force ]];then
        redirect_output $(get_log_file install-penenv)
        add_log_entry; update_log $ret "[~] install-penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install-penenv
        update_log $ret "[+] install-penenv Setted up as command"
fi
}
bg_install task-ipenenv

###### Install autoenum
task-autoenum() {
if [[ ! -x "$(command -v autoenum)" || $check || $force ]];then
        redirect_output $(get_log_file autoenum)
        add_log_entry; update_log $ret "[~] autoenum not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
        update_log $ret "[+] autoenum Installed"
fi
}
bg_install task-autoenum

###### Install start
task-start() {
if [[ ! -x "$(command -v start)" || $check || $force ]];then
        redirect_output $(get_log_file start)
        add_log_entry; update_log $ret "[~] start not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
        update_log $ret "[+] start Installed"
fi
}
bg_install task-start

if [[ $check ]];then
        stop --no-exit
        install-penenv $ORIGINAL_ARGS -nc
        exit 1
fi

## Languages and downloaders
add_log_entry; update_log $ret "[*] Getting languages and downloaders..."
###### Upgrade apt
if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        add_log_entry; update_log $ret "[~] Updating apt-get and upgrading installed packages..."
        apt-task() {
        redirect_output $(get_log_file apt)
        sudo apt-get -o DPkg::Lock::Timeout=600 update
        update_log $ret "[~] Upgrading installed packages... Updating apt-get done..."
        sudo apt-get -o DPkg::Lock::Timeout=600 upgrade -y
        update_log $ret "[~] Update and upgrade done... Removing unused packages..."
        sudo apt-get -o DPkg::Lock::Timeout=600 autoremove -y
        update_log $ret "[+] apt-get updated and upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
        }
        apt_install apt-task
fi

###### Install python3
bg_install apt_installation "python3"

###### Install 2to3
bg_install apt_installation "2to3"

###### Install pip
pip-install () {
if [[ ! -x "$(command -v pip)" || $force ]];then
        redirect_output $(get_log_file pip)
        if [[ ! -x "$(command -v pip3)" || $force ]];then
                add_log_entry; update_log $ret "[~] pip not detected... Installing"
                sudo apt-get -o DPkg::Lock::Timeout=600 install python3-pip -y
                update_log $ret "[+] pip Installed"
        fi
        # Check if an alias is needed
        if [[ ! -x "$(command -v pip)" ]];then
                add_log_entry; update_log $ret "[~] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
                update_log $ret "[*] pip is now an alias of pip3"
        fi
fi
}
pip_install pip-install

pip-update () {
###### Upgrade pip
if [[ ! $no_upgrade ]];then
        redirect_output $(get_log_file pip)
        add_log_entry; update_log $ret "[*] Waiting pip installation..."
        wait_command "pip"
        start_update=$(date +%s)
        update_log $ret "[~] Upgrading pip and python packages..."
        pip install --upgrade pip
        l=$(pip list --outdated | awk '{print($1)}' | tail -n +3)
        n=$(echo "$l" | wc -l | awk '{print($1)}')
        i=0
        for line in $l
        do
                update_log $ret "[~] Upgrading pip and python packages... $i/$n packages upgraded  | currently upgrading $line"
                pip_install pip install $line --upgrade
                (( i = i+1 ))
        done
        update_log $ret "[+] pip and python packages upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
fi
}
pip_install pip-update

poetry-task () {
###### Install poetry
if [[ ! -x "$(command -v poetry)" || $force ]];then
        redirect_output $(get_log_file poetry)
        add_log_entry; update_log $ret "[~] poetry not detected... Installing"
        curl -sSL https://install.python-poetry.org | python3
        update_log $ret "[+] poetry Installed"
fi
}
bg_install poetry-task

###### Install go
go-task () {
if [[ ! -x "$(command -v go)" || ! "$(go version)" =~ "1.20" || $force ]];then
        redirect_output $(get_log_file go)
        add_log_entry; update_log $ret "[~] go 1.20 not detected... Installing"
        wget https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
        sudo tar xzf go1.20.2.linux-amd64.tar.gz 
        if [[ -d "/usr/local/go" ]];then
                sudo mv /usr/local/go /usr/local/go-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /usr/local/go to /usr/local/go-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        sudo mv go /usr/lib/go-1.20
        if [[ -f "/bin/go" ]];then sudo rm /bin/go;fi
        if [[ -f "/bin/gofmt" ]];then sudo rm /bin/gofmt;fi
        sudo ln -s /usr/lib/go-1.20/bin/go /bin/go
        sudo ln -s /usr/lib/go-1.20/bin/gofmt /bin/gofmt
        export GOROOT=/usr/local/go
        export PATH=$GOROOT/bin:$PATH 
        update_log $ret "[+] go 1.20 Installed"
fi
}
bg_install go-task

###### Install Ruby
bg_install apt_installation "gem" "Ruby" "ruby-dev"

###### Install Java
bg_install apt_installation "java" "Java" "default-jdk"

###### Install Nodejs
apt_installation "node" "NodeJS" "nodejs"

###### Install npm
apt_installation "npm"

###### Install yarn
task-yarn() {
if [[ ! -x "$(command -v yarn)" || $force ]];then
        redirect_output $(get_log_file yarn)
        add_log_entry; update_log $ret "[*] Yarn not detected... Waiting for npm"
        wait_command "npm"
        update_log $ret "[~] Yarn not detected... Installing"
        sudo npm install --global yarn
        update_log $ret "[+] Yarn Installed"
fi
}
bg_install task-yarn

###### Install rust
task-rust() {
if [[ ! -x "$(command -v cargo)" || $force ]];then
        redirect_output $(get_log_file rust)
        add_log_entry; update_log $ret "[~] Rust not detected... Installing"
        curl -s https://sh.rustup.rs -sSf | sh -s -- -y
        sudo cp /home/$usr/.cargo/bin/* /bin
        export PATH=/home/$usr/.cargo/bin:$PATH
        update_log $ret "[+] Rust Installed"
fi
}
bg_install task-rust

###### Install make
bg_install apt_installation "make"

###### Install mono
task-mono() {
if [[ ! -x "$(command -v mozroots)" || $force ]];then
        redirect_output $(get_log_file mono)
        add_log_entry; update_log $ret "[*] Mono not detected... Waiting for apt upgrade"
        wait_apt
        update_log $ret "[~] Mono not detected... Installing"
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y dirmngr ca-certificates gnupg
        sudo gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
        echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list >/dev/null
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y mono-devel
        update_log $ret "[+] Mono Installed"
fi
}
bg_install task-mono

###### Install dotnet
task-dotnet() {
if [[ ! -x "$(command -v dotnet)" || $force ]];then
        redirect_output $(get_log_file dotnet)
        add_log_entry; update_log $ret "[~] Dotnet not detected... Installing"
        wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh -q
        chmod +x ./dotnet-install.sh
        ./dotnet-install.sh --version latest
        rm dotnet-install.sh
        export DOTNET_ROOT=$HOME/.dotnet
        export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools
        update_log $ret "[+] Dotnet Installed"
fi
}
bg_install task-dotnet

###### Install git
bg_install apt_installation "git"

###### Install krb5
bg_install apt_installation "kinit" "Kerberos" "krb5-user"



# Commands
add_log_entry; update_log $ret "[*] Getting commands..."
###### Install ftp module
task-ftp() {
if [[ ! "$(pip list | grep pyftpdlib)" || $force ]];then
        redirect_output $(get_log_file pyftplib)
        add_log_entry; update_log $ret "[*] Pyftplib not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Pyftplib not detected... Installing"
        sudo pip install pyftpdlib
        update_log $ret "[+] Pyftplib Installed"
fi
}
bg_install task-ftp

###### Install dnsutils
bg_install apt_installation "dig" "dig" "dnsutils"

###### Install google-chrome
task-chrome() {
if [[ ! -x "$(command -v google-chrome)" || $force ]];then
        redirect_output $(get_log_file chrome)
        add_log_entry; update_log $ret "[~] google-chrome not detected... Installing"
        wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -q
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./google-chrome-stable_current_amd64.deb -y
        rm google-chrome-stable_current_amd64.deb
        update_log $ret "[+] google-chrome Installed"
fi
}
bg_install task-chrome

###### Install jq
bg_install apt_installation "jq"

###### Install expect
bg_install apt_installation "unbuffer" "expect"

# Tools
## Web scan
add_log_entry; update_log $ret "[*] Getting web scan tools..."
### Subdomain & paths
###### Install sublist3r
task-sublister() {
if [[ ! -x "$(command -v sublist3r)" || $force ]];then
        redirect_output $(get_log_file sublister)
        add_log_entry; update_log $ret "[*] sublist3r not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] sublist3r not detected... Installing"
        if [[ -d "/lib/python3/dist-packages/subbrute" ]];then
                sudo mv /lib/python3/dist-packages/subbrute /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/python3/dist-packages/subbrute to /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        sudo git clone https://github.com/aboul3la/Sublist3r.git
        update_log $ret "[~] sublist3r not detected... Waiting for pip"
        wait_pip
        update_log $ret "[~] sublist3r not detected... Installing requirements"
        pip install -r Sublist3r/requirements.txt
        sudo mv Sublist3r/sublist3r.py /bin/sublist3r
        sudo mv Sublist3r/subbrute /lib/python3/dist-packages/subbrute
        sudo rm Sublist3r/*
        sudo rm -R Sublist3r
        update_log $ret "[+] sublist3r Installed"
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
        redirect_output $(get_log_file arjun)
        add_log_entry; update_log $ret "[*] Arjun not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Arjun not detected... Installing"
        sudo pip install arjun
        update_log $ret "[+] Arjun Installed"
fi
}
bg_install task-arjun

###### Install BrokenLinkChecker
task-blc() {
if [[ ! -x "$(command -v blc)" || $force ]];then
        redirect_output $(get_log_file brikenlinkchecker)
        add_log_entry; update_log $ret "[*] BrokenLinkChecker not detected... Waiting for npm"
        wait_command "npm"
        update_log $ret "[~] BrokenLinkChecker not detected... Installing"
        sudo npm install --global broken-link-checker
        update_log $ret "[+] BrokenLinkChecker Installed"
fi
}
bg_install task-blc

###### Install dirscraper
task-dirscraper() {
if [[ ! -x "$(command -v dirscraper)" || $force ]];then
        redirect_output $(get_log_file dirscraper)
        add_log_entry; update_log $ret "[*] Dirscapper not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Dirscapper not detected... Installing"
        git clone https://github.com/Cillian-Collins/dirscraper.git
        chmod +x ./dirscraper/dirscraper.py
        sudo mv dirscraper/dirscraper.py /bin/dirscraper
        update_log $ret "[*] Dirscapper not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Dirscapper not detected... Installing requirements"
        pip install -r ./dirscraper/requirements.txt
        sudo rm -R ./dirscraper
        update_log $ret "[+] Dirscapper Installed"
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
        redirect_output $(get_log_file x8)
        add_log_entry; update_log $ret "[*] x8 not detected... Waiting for rust"
        wait_command "cargo"
        update_log $ret "[~] x8 not detected... Installing"
        cargo install x8
        update_log $ret "[+] x8 Installed"
fi
}
bg_install task-xeight

### Others
###### Install wappalyzer
task-wappalyzer() {
if [[ ! -x "$(command -v wappalyzer)" || $force ]];then
        redirect_output $(get_log_file wappalyzer)
        add_log_entry; update_log $ret "[*] wappalyzer not detected... Waiting for yarn and git"
        wait_command "yarn" "git"
        update_log $ret "[~] wappalyzer not detected... Installing"
        if [[ -d "/lib/wappalyzer" ]];then
                sudo mv /lib/wappalyzer /lib/wappalyzer-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/wappalyzer to /lib/wappalyzer-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone https://github.com/wappalyzer/wappalyzer.git
        sudo mv wappalyzer /lib/wappalyzer
        workingdir=$(pwd)
        cd /lib/wappalyzer
        # correct minor sourcecode error
        sudo sed -i 's/?././g' /lib/wappalyzer/src/drivers/npm/driver.js
        sudo sed -i 's/?././g' /lib/wappalyzer/src/drivers/npm/wappalyzer.js
        cd /lib/wappalyzer && yarn install
        cd /lib/wappalyzer && yarn run link
        cd $workingdir
        printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo node /lib/wappalyzer/src/drivers/npm/cli.js\$args" > wappalyzer
        chmod +x wappalyzer
        sudo mv wappalyzer /bin/wappalyzer
        update_log $ret "[+] wappalyzer Installed"
fi
}
bg_install task-wappalyzer

###### Install testssl
task-testssl() {
if [[ ! -x "$(command -v testssl)" || $force ]];then
        redirect_output $(get_log_file testssl)
        add_log_entry; update_log $ret "[*] Testssl not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Testssl not detected... Installing"
        if [[ -d "/lib32/testssl" ]];then
                sudo mv /lib32/testssl /lib32/testssl-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib32/testssl to /lib32/testssl-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git
        sudo mv testssl.sh /lib32/testssl
        # printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo /lib32/testssl/testssl.sh \$args" > testssl
        # chmod +x testssl
        # sudo mv testssl /bin/testssl
        sudo ln -s /lib32/testssl/testssl.sh /bin/testssl
        update_log $ret "[+] Testssl Installed"
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
        redirect_output $(get_log_file secretfinder)
        add_log_entry; update_log $ret "[*] Secretfinder not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Secretfinder not detected... Installing"
        git clone https://github.com/m4ll0k/SecretFinder.git
        chmod +x ./SecretFinder/SecretFinder.py
        sudo mv SecretFinder/SecretFinder.py /bin/secretfinder
        update_log $ret "[*] Secretfinder not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Secretfinder not detected... Installing requirements"
        pip install -r ./SecretFinder/requirements.txt
        sudo rm -R ./SecretFinder
        update_log $ret "[+] Secretfinder Installed"
fi
}
bg_install task-secretfinder

### Bruteforce
add_log_entry; update_log $ret "[*] Getting bruteforce tools..."
###### Install hashcat
bg_install apt_installation "hashcat"

###### Install hydra
task-hydra() {
if [[ ! -x "$(command -v hydra)" || $force ]];then
        redirect_output $(get_log_file hydra)
        add_log_entry; update_log $ret "[*] Hydra not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Hydra not detected... Installing"
        git clone https://github.com/vanhauser-thc/thc-hydra
        cd thc-hydra
        ./configure
        make
        sudo make install
        sudo mv hydra /bin/hydra
        cd ..
        sudo rm -R thc-hydra
        update_log $ret "[+] Hydra Installed"
fi
}
bg_install task-hydra

###### Install john
bg_install apt_installation "john"

### Network
add_log_entry; update_log $ret "[*] Getting network tools..."
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
add_log_entry; update_log $ret "[*] Getting exploit tools..."
###### Install Metasploit & Armitage
task-metasploit() {
if [[ ! -x "$(command -v msfconsole)" || ! -x "$(command -v armitage)" || $force ]];then
        redirect_output $(get_log_file armitage)
        add_log_entry; update_log $ret "[*] Metasploit and Armitage not detected... Waiting for apt update"
        wait_apt
        update_log $ret "[*] Metasploit and Armitage not detected... Waiting for java"
        wait_command "java"
        update_log $ret "[~] Metasploit and Armitage not detected... Installing"
        if [[ ! "$(java --version)" =~ "openjdk 11.0.18" || $force ]];then
                tmp=$ret
                add_log_entry; update_log $ret "[~] Java != 11 is used... Setting it to 11.0.18"
                sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
                update_log $ret "[*] Java version setted to 11.0.18"
                ret=$tmp
        fi
        curl -s -L https://raw.githubusercontent.com/Matt-London/Install-Armitage-on-Linux/master/ArmitageInstaller --output ArmitageInstaller
        chmod +x ArmitageInstaller
        sudo ./ArmitageInstaller
        rm ArmitageInstaller
        curl -s -L https://raw.githubusercontent.com/BlackArch/msfdb/master/msfdb --output msfdb
        chmod +x msfdb
        sudo mv msfdb /bin
        update_log $ret "[+] Metasploit & Armitage Installed"
fi
}
bg_install task-metasploit

update-metasploit() {
if [[ ! $no_upgrade ]];then
        redirect_output $(get_log_file metasploit)
        add_log_entry; update_log $ret "[*] Waiting for metasploit..."
        wait_command "msfupdate"
        start_update=$(date +%s)
        update_log $ret "[~] Upgrading metasploit..."
        sudo msfupdate
        update_log $ret "[*] Metasploit data upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
fi
}
bg_install update-metasploit

###### Install searchsploit
task-searchsploit() {
if [[ ! -x "$(command -v searchsploit)" || $force ]];then
        add_log_entry; update_log $ret "[~] Searchsploit not detected... Installing"
        wget https://raw.githubusercontent.com/rad10/SearchSploit.py/master/searchsploit.py -q
        chmod +x searchsploit.py
        sudo mv searchsploit.py /bin/searchsploit
        update_log $ret "[+] Searchsploit Installed"
fi
}
bg_install task-searchsploit

###### Install AutoHackBruteOS
task-autohackbruteos() {
if [[ ! -x "$(command -v AutoHackBruteOS)" || $force ]];then
        add_log_entry; update_log $ret "[~] AutoHackBruteOS not detected... Installing"
        (echo "#! /usr/bin/env ruby" && curl -L -s https://raw.githubusercontent.com/carlospolop/AutoHackBruteOs/master/AutoHackBruteOs.rc) > AutoHackBruteOs.rc
        chmod +x AutoHackBruteOs.rc
        sudo mv AutoHackBruteOs.rc /bin/AutoHackBruteOs
        update_log $ret "[+] AutoHackBruteOS Installed"
fi
}
bg_install task-autohackbruteos

###### Install sqlmap
task-sqlmap() {
if [[ ! -x "$(command -v sqlmap)" || $force ]];then
        redirect_output $(get_log_file sqlmap)
        add_log_entry; update_log $ret "[*] sqlmap not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] sqlmap not detected... Installing"
        if [[ -d "/lib/sqlmap" ]];then
                sudo mv /lib/sqlmap /lib/sqlmap-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/sqlmap to /lib/sqlmap-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
        update_log $ret "[*] sqlmap not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] sqlmap not detected... Installing" requirements
        pip install -r sqlmap/requirements.txt
        sudo mv sqlmap /lib/sqlmap
        printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo python3 /lib/sqlmap/sqlmap.py \$args" > sqlmap
        chmod +x sqlmap
        sudo mv sqlmap /bin/sqlmap
        update_log $ret "[+] sqlmap Installed"
fi
}
bg_install task-sqlmap

###### Install commix
task-commix() {
if [[ ! -x "$(command -v commix)" || $force ]];then
        redirect_output $(get_log_file commix)
        add_log_entry; update_log $ret "[*] commix not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] commix not detected... Installing"
        if [[ -d "/lib/commix" ]];then
                sudo mv /lib/commix /lib/commix-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/commix to /lib/commix-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone https://github.com/commixproject/commix.git
        sudo mv commix /lib/commix
        printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo python3 /lib/commix/commix.py \$args" > commix
        chmod +x commix
        sudo mv commix /bin/commix
        update_log $ret "[+] commix Installed"
fi
}
bg_install task-commix

###### Install pixload
task-pixload() {
if [[ ! -x "$(command -v pixload-png)" || $force ]];then
        redirect_output $(get_log_file pixload)
        add_log_entry; update_log $ret "[*] Pixload not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Pixload not detected... Installing"
        sudo git clone https://github.com/sighook/pixload.git
        cd pixload
        make
        sudo rm *pod
        sudo rm *in
        chmod +x pixload-*
        sudo mv pixload-* /bin
        cd ..
        sudo rm -R pixload
        update_log $ret "[+] Pixload Installed"
fi
}
bg_install task-pixload

### Others
add_log_entry; update_log $ret "[*] Getting other tools..."
###### Install impacket
bg_install apt_installation "impacket-ntlmrelayx" "impacket" "impacket-scripts"

###### Install fierce
bg_install apt_installation "fierce"

###### Install oscanner
bg_install apt_installation "oscanner"

###### Install odat
task-odat() {
if [[ ! -x "$(command -v odat)" || $force ]];then
        redirect_output $(get_log_file odat)
        add_log_entry; update_log $ret "[~] odat not detected... Installing"
        if [[ -d "/lib32/odat_lib" ]];then
                sudo mv /lib32/odat_lib /lib32/odat_lib-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib32/odat_lib to /lib32/odat_lib-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        wget https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz -q
        sudo tar xzf odat-linux-libc2.17-x86_64.tar.gz
        sudo rm odat-linux-libc2.17-x86_64.tar.gz
        sudo mv odat-libc2.17-x86_64 /lib32/odat_lib
        sudo ln -s /lib32/odat_lib/odat-libc2.17-x86_64 /bin/odat
        update_log $ret "[+] odat Installed"
fi
}
bg_install task-odat

###### Install crackmapexec
task-crackmapexec() {
if [[ ! -x "$(command -v crackmapexec)" || $force ]];then
        redirect_output $(get_log_file crackmapexec)
        add_log_entry; update_log $ret "[*] crackmapexec not detected... Waiting for apt upgrade"
        wait_apt
        update_log $ret "[~] crackmapexec not detected... Getting Dependencies"
        if [[ -d "/lib/crackmapexec" ]];then
                sudo mv /lib/crackmapexec /lib/crackmapexec-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/crackmapexec to /lib/crackmapexec-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
        update_log $ret "[*] crackmapexec not detected... Waiting for poetry and git"
        wait_command "poetry" "git"
        update_log $ret "[~] crackmapexec not detected... Installing"
        git clone https://github.com/mpgn/CrackMapExec
        sudo mv CrackMapExec /lib/crackmapexec
        workingdir=$(pwd)
        cd /lib/crackmapexec
        cd /lib/crackmapexec && poetry lock
        cd /lib/crackmapexec && poetry install
        update_log $ret "[~] crackmapexec not detected... Initialize"
        cd /lib/crackmapexec && poetry run crackmapexec
        cd $workingdir
        printf "#! /bin/sh\ncd /lib/crackmapexec\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo poetry run crackmapexec \$args" > crackmapexec
        chmod +x crackmapexec
        sudo mv crackmapexec /bin/crackmapexec
        printf "#! /bin/sh\ncd /lib/crackmapexec\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo poetry run crackmapexec \$args" > cme
        chmod +x cme
        sudo mv cme /bin/cme
        printf "#! /bin/sh\ncd /lib/crackmapexec\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo poetry run cmedb \$args" > cmedb
        chmod +x cmedb
        sudo mv cmedb /bin/cmedb
        update_log $ret "[+] crackmapexec Installed"
fi
}
bg_install task-crackmapexec

###### Install cewl
bg_install apt_installation "cewl"

###### Install cupp
task-cupp() {
if [[ ! -x "$(command -v cupp)" || $force ]];then
        add_log_entry; update_log $ret "[~] Cupp not detected... Installing"
        wget https://raw.githubusercontent.com/Mebus/cupp/master/cupp.py -q
        chmod +x cupp.py
        sudo mv cupp.py /bin/cupp
        update_log $ret "[+] Cupp Installed"
fi
}
bg_install task-cupp

###### Install DDexec
task-ddexec() {
if [[ ! -x "$(command -v ddexec)" || $force ]];then
        add_log_entry; update_log $ret "[~] DDexec not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/DDexec/main/DDexec.sh -q
        chmod +x DDexec.sh
        sudo mv DDexec.sh /bin/ddexec
        update_log $ret "[+] DDexec Installed"
fi
}
bg_install task-ddexec

###### Install openvpn
bg_install apt_installation "openvpn"

###### Install mitm6
task-mitmsix() {
if [[ ! -x "$(command -v mitm6)" || $force ]];then
        redirect_output $(get_log_file mitm6)
        add_log_entry; update_log $ret "[*] mitm6 not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] mitm6 not detected... Installing"
        sudo git clone https://github.com/dirkjanm/mitm6.git
        update_log $ret "[*] mitm6 not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] mitm6 not detected... Installing requirements"
        pip install -r mitm6/requirements.txt
        sudo chmod +x mitm6/mitm6/mitm6.py
        sudo mv mitm6/mitm6/mitm6.py /bin/mitm6
        sudo rm -R mitm6
        update_log $ret "[+] mitm6 Installed"
fi
}
bg_install task-mitmsix

###### Install proxychain
task-proxychain() {
if [[ ! -x "$(command -v proxychains)" || $force ]];then
        redirect_output $(get_log_file proxychains)
        add_log_entry; update_log $ret "[*] Proxychain not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Proxychain not detected... Installing"
        git clone https://github.com/haad/proxychains.git
        cd proxychains
        ./configure
        make
        sudo make install
        sudo mv proxychains4 /bin/proxychains
        cd ..
        sudo rm -R proxychains
        update_log $ret "[+] Proxychain Installed"
fi
}
bg_install task-proxychain

###### Install responder
task-responder() {
if [[ ! -x "$(command -v responder)" || $force ]];then
        redirect_output $(get_log_file responder)
        add_log_entry; update_log $ret "[*] responder not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] responder not detected... Installing"
        if [[ -d "/lib/responder" ]];then
                sudo mv /lib/responder /lib/responder-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/responder to /lib/responder-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone https://github.com/lgandx/Responder.git
        sudo mv Responder /lib/responder
        printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo python3 /lib/responder/Responder.py \$args" > responder
        chmod +x responder
        sudo mv responder /bin/responder
        update_log $ret "[+] responder Installed"
fi
}
bg_install task-responder

###### Install Evil winrm



## Hot scripts
add_log_entry; update_log $ret "[*] Getting scripts..."
###### Install dnscat2 & dependencies
lib-dnscat() {
if [[ ! -d "/lib/dnscat" || $force ]];then
        redirect_output $(get_log_file dnscat-lib)
        add_log_entry; update_log $ret "[*] Dnscat sourcecode not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Dnscat sourcecode not detected... Installing"
        if [[ -d "/lib/dnscat" ]];then
                sudo mv /lib/dnscat /lib/dnscat-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/dnscat to /lib/dnscat-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        git clone https://github.com/iagox86/dnscat2.git
        sudo mv dnscat2 /lib/dnscat
        # correct minor sourcecode error
        sudo sed -i 's/return a.value.ptr == a.value.ptr/return a.value.ptr == b.value.ptr/g' /lib/dnscat/client/libs/ll.c
        update_log $ret "[+] Dnscat sourcecode Installed"
fi
}
bg_install lib-dnscat

task-dnscat() {
if [[ ! -f "$hotscript/dnscat" || $force ]];then
        redirect_output $(get_log_file dnscqt-client)
        add_log_entry; update_log $ret "[*] Dnscat client not detected... Waiting for library"
        ( while [[ ! -d "/lib/dnscat/client" ]];do sleep .2;done ) &
        wait_procs $!
        update_log $ret "[*] Dnscat client not detected... Waiting for make"
        wait_command "make"
        update_log $ret "[~] Dnscat client not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        cd /lib/dnscat/client && make
        mv /lib/dnscat/client/dnscat $hotscript/dnscat
        cd $workingdir
        update_log $ret "[+] Dnscat client Made"
fi
}
bg_install task-dnscat

srv-dnscat() {
if [[ ! -x "$(command -v dnscat)" || $force ]];then
        redirect_output $(get_log_file dnscat-server)
        add_log_entry; update_log $ret "[*] Dnscat server not detected... Waiting for library"
        ( while [[ ! -d "/lib/dnscat/server" ]];do sleep .2;done ) &
        wait_procs $!
        update_log $ret "[*] Dnscat server not detected... Waiting for Ruby to be installed"
        wait_command "gem" "bundler"
        update_log $ret "[~] Dnscat server not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/server
        cd /lib/dnscat/server && sudo gem install bundler
        cd /lib/dnscat/server && sudo bundler install
        cd $workingdir
        printf "#! /bin/sh\nargs=''\nfor [[ arg in \$@ ]];do args=\"\$args '\$arg'\"\nsudo ruby /lib/dnscat/server/dnscat2.rb \$args" > dnscat
        chmod +x dnscat
        sudo mv dnscat /bin/dnscat
        update_log $ret "[+] Dnscat server Made"
fi
}
bg_install srv-dnscat

shell-dnscat() {
if [[ ! -x "$(command -v dnscat-shell)" || $force ]];then
        add_log_entry; update_log $ret "[~] dnscat shell not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/misc/dnscat-shell.sh -q
        chmod +x dnscat-shell.sh
        sudo mv dnscat-shell.sh /bin/dnscat-shell
        update_log $ret "[+] dnscat shell Installed"
fi
}
bg_install shell-dnscat

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
        redirect_output $(get_log_file frp)
        add_log_entry; update_log $ret "[*] frp not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] frp not detected... Installing"
        sudo git clone https://github.com/fatedier/frp.git
        cd frp
        ./package.sh
        mv bin $hotscript/frp
        cd ..
        rm -R frp
        update_log $ret "[+] frp Installed"
fi
}
bg_install task-frp

###### Install PEAS
task-lpeas() {
if [[ ! -f "$hotscript/LinPEAS.sh" || $force ]];then
        add_log_entry; update_log $ret "[~] LinPEAS not detected... Installing"
        curl -L -s https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh --output $hotscript/LinPEAS.sh
        chmod +x $hotscript/LinPEAS.sh
        update_log $ret "[+] LinPEAS Installed"
fi
}
bg_install task-lpeas

task-wpeasps() {
if [[ ! -f "$hotscript/WinPEAS.ps1" || $force ]];then
        add_log_entry; update_log $ret "[~] WinPEAS powershell not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1 -q
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
        chmod +x $hotscript/WinPEAS.ps1
        update_log $ret "[+] WinPEAS powershell Installed"
fi
}
bg_install task-wpeasps

task-wpeasi() {
if [[ ! -f "$hotscript/WinPEAS_internet.ps1" || $force ]];then
        add_log_entry; update_log $ret "[~] WinPEAS internet not detected... Installing"
        printf "IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1')" > $hotscript/WinPEAS_internet.ps1
        chmod +x $hotscript/WinPEAS_internet.ps1
        update_log $ret "[+] WinPEAS internet Installed"
fi
}
bg_install task-wpeasi

task-wpeasbat() {
if [[ ! -f "$hotscript/WinPEAS.bat" || $force ]];then
        add_log_entry; update_log $ret "[~] WinPEAS bat not detected... Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat -q
        mv winPEAS.bat $hotscript/WinPEAS.bat
        chmod +x $hotscript/WinPEAS.bat
        update_log $ret "[+] WinPEAS bat Installed"
fi
}
bg_install task-wpeasbat

###### Install miranda
task-miranda() {
if [[ ! -f "$hotscript/miranda.py" || $force ]];then
        redirect_output $(get_log_file miranda)
        add_log_entry; update_log $ret "[~] Miranda not detected... Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
        chmod +x $hotscript/miranda.py
        2to3 $hotscript/miranda.py -w $hotscript/miranda.py
        sed -i 's/        /\t/g' $hotscript/miranda.py
        sed -i 's/import IN/# import IN/g' $hotscript/miranda.py
        sed -i 's/socket.sendto(data/socket.sendto(data.encode()/g' $hotscript/miranda.py
        update_log $ret "[+] Miranda Installed"
fi
}
bg_install task-miranda

###### Install pspy
task-pspy32() {
if [[ ! -f "$hotscript/pspy32" || $force ]];then
        add_log_entry; update_log $ret "[~] Pspy32 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32 --output $hotscript/pspy32
        chmod +x $hotscript/pspy32
        update_log $ret "[+] Pspy32 Installed"
fi
}
bg_install task-pspy32

task-pspy64() {
if [[ ! -f "$hotscript/pspy64" || $force ]];then
        add_log_entry; update_log $ret "[~] Pspy64 not detected... Installing"
        curl -L -s https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 --output $hotscript/pspy64
        chmod +x $hotscript/pspy64
        update_log $ret "[+] Pspy64 Installed"
fi
}
bg_install task-pspy64

###### Install rubeus

###### Install mimikatz

###### Install mimipenguin
task-mimipenguin() {
if [[ ! -f "$hotscript/mimipenguin" || $force ]];then
        redirect_output $(get_log_file mimipenguin)
        add_log_entry; update_log $ret "[*] Mimipenguin not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Mimipenguin not detected... Installing"
        sudo git clone https://github.com/huntergregal/mimipenguin.git
        cd mimipenguin
        sudo make
        sudo mv mimipenguin $hotscript/mimipenguin
        sudo mv mimipenguin.py $hotscript/mimipenguin.py
        sudo mv mimipenguin.sh $hotscript/mimipenguin.sh
        cd ..
        sudo rm -R mimipenguin
        update_log $ret "[+] Mimipenguin Installed"
fi
}
bg_install task-mimipenguin

###### Install linux-exploit-suggester-2
task-les() {
if [[ ! -f "$hotscript/linux-exploit-suggester-2.pl" || $force ]];then
        add_log_entry; update_log $ret "[~] Linux exploit suggester 2 not detected... Installing"
        wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl -q
        mv linux-exploit-suggester-2.pl $hotscript/linux-exploit-suggester-2.pl
        update_log $ret "[+] Linux exploit suggester 2 Installed"
fi
}
bg_install task-les

###### Install wesng
task-wesng() {
if [[ ! "$(command -v wes)" || $force ]];then
        redirect_output $(get_log_file wesng)
        add_log_entry; update_log $ret "[*] Wesng not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Wesng not detected... Installing"
        sudo pip install wesng
        wes --update
        update_log $ret "[+] Wesng Installed"
fi
}
bg_install task-wesng

###### Install watson

###### Install powersploit

###### Install evilSSDP


## Services
add_log_entry; update_log $ret "[*] Getting Services..."
###### Install bloodhound
bg_install apt_installation "bloodhound"

task-invoke-bloodhound() {
if [[ ! -f "$hotscript/Invoke-Bloodhound.ps1" || $force ]];then
        add_log_entry; update_log $ret "[~] Invoke-Bloodhound not detected... Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 -q
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
        update_log $ret "[+] Invoke-Bloodhound Installed"
fi
}
bg_install task-invoke-bloodhound

###### Install Nessus
task-nessus() {
wait_command "java"
if [[ ! "$(java --version)" =~ "openjdk 11.0.18" || $force ]];then
        add_log_entry; update_log $ret "[~] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
        update_log $ret "[*] Java version setted to 11.0.18"
fi

if [[ ! "$(systemctl status nessusd 2>/dev/null)" || $force ]];then
        redirect_output $(get_log_file nessus)
        add_log_entry; update_log $ret "[~] Nessus not detected... Installing"
        file=$(curl -s --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus' | grep -o -P "Nessus-\d+\.\d+\.\d+-debian10_amd64.deb" | head -n 1)
        curl -s --request GET \
               --url "https://www.tenable.com/downloads/api/v2/pages/nessus/files/$file" \
               --output 'Nessus.deb'
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./Nessus.deb -y
        rm Nessus.deb
        sudo systemctl start nessusd
        update_log $ret "[~] Go to https://localhost:8834 to complete nessus installation"
fi
}
bg_install task-nessus

# add_log_entry; update_log $ret "[~] No more task, waiting apt... (${apt_proc[@]})"
wait_apt
# update_log $ret "[~] No more task, waiting pip... (${pip_proc[@]})"
wait_pip
# update_log $ret "[~] No more task, waiting bg... (${bg_proc[@]})"
wait_bg

add_log_entry; update_log $ret "[~] Installation done... Took $(date -d@$(($(date +%s)-$start)) -u +%H:%M:%S)"

stop

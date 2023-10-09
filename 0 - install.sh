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
        echo "Suite version : V0.2.7"
        echo "Script version : V2.3"
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
goback_dir="$waiting_dir/going_back"
mkdir $thread_dir
mkdir $waiting_dir
mkdir $goback_dir

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
        if [[ $# -eq 0 ]];then add_log_entry; update_log $ret "[!] DEBUG : 0 argument given for apt installation, when at least 1 is needed..."; return; fi 
        if [[ $# -eq 1 ]];then name=$1; pkg=$1; fi
        if [[ $# -eq 2 ]];then name=$2; pkg=$2; fi
        if [[ $# -gt 2 ]];then name=$2; fi
        if [[ ! -x "$(command -v $1)" || $force ]];then
                add_log_entry; update_log $ret "[*] $name not detected... Waiting for apt upgrade"
                wait_apt
                update_log $ret "[~] $name not detected... Installing"
                # non interactive apt install, and wait 10 minutes for dpkg lock to be unlocked if needed (thanks to parrallelization)
                if [[ $# -le 2 ]];then
                        sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install $pkg --allow-downgrades -yq 2>>$(get_log_file $name) >>$(get_log_file $name)
                else
                        for pkg in ${@:3};do
                                sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install $pkg --allow-downgrades -yq 2>>$(get_log_file $name) >>$(get_log_file $name)
                        done
                fi
                update_log $ret "[+] $name Installed"
        fi
}

pip_installation () {
        if [[ $# -ne 1 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for apt installation, when only 1 is accepted... ($@)"; return; fi 
        if [[ ! "$(pip list | grep $1)" || $force ]];then
                add_log_entry; update_log $ret "[*] $1 not detected... Waiting for pip upgrade"
                wait_pip
                update_log $ret "[~] $1 not detected... Installing"
                sudo pip install $1 >>$(get_log_file $1) 2>>$(get_log_file $1)
                update_log $ret "[+] $1 Installed"
        fi
}

go_installation () {
        if [[ $# -ne 2 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for go installation, when 2 are required... ($@)"; return; fi 
        if [[ ! -x "$(command -v $1)" || $force ]];then
                add_log_entry; update_log $ret "[*] $1 not detected... Waiting go to be installed"
                wait_command "go"
                update_log $ret "[~] $1 not detected... Installing"
                go install $2 2>> $(get_log_file $1)
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
        (file=$(date +%s%N); echo $@ > $thread_dir/$file; "$@"; rm $thread_dir/$file) &
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
                if [[ -f "$waiting_dir/$file" ]];then mv $waiting_dir/$file $goback_dir/$file;fi # Put the thread in want to activate again mode
                while [[ $(ls $goback_dir | head -n1) -ne $file || $(ls $thread_dir | wc -l) -gt $thread ]];do sleep .2; done # Wait a working thread to be available again while being the first in queue
                if [[ -f "$goback_dir/$file" ]];then mv $goback_dir/$file $thread_dir/$file;fi
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

                used=$((1 + $(ls $thread_dir | wc -l)))
                waiting=$(($(ls $waiting_dir | wc -l) + $(ls $goback_dir | wc -l) - 1))
                ended=$(cat $gui/* | grep "\[+\]" | wc -l)
                total=$(($ended + $waiting + $used - 1))

                echo -ne "$(tput cup 0 0)$(tput ed)$(for log in $(ls $gui | sort -g | tail -n+3);do  cat $gui/$log;done)\n  >  Used threads : $used  -  Waiting : $waiting - Progress : $ended / $total"
                sleep 0.2
        done
}

# Manage log
get_log_file () {
        if [[ $# -ne 1 ]];then add_log_entry; update_log $ret "[!] DEBUG : $# argument given for get_log_file, when only 1 is accepted... ($@)"; return; fi 
        if [[ $nologs ]];then echo "/dev/null";return;fi
        echo "$log/$1.log"
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
        add_log_entry; update_log $ret "[~] install-penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/0%20-%20install.sh -q
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install-penenv
        update_log $ret "[+] install-penenv Setted up as command"
fi
}
bg_install task-ipenenv

###### Install autoenum
task-autoenum() {
if [[ ! -x "$(command -v autoenum)" || $check || $force ]];then
        add_log_entry; update_log $ret "[~] autoenum not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/A%20-%20autoenum.sh -q
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
        update_log $ret "[+] autoenum Installed"
fi
}
bg_install task-autoenum

###### Install start
task-start() {
if [[ ! -x "$(command -v start)" || $check || $force ]];then
        add_log_entry; update_log $ret "[~] start not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/1%20-%20start.sh -q
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
        update_log $ret "[+] start Installed"
fi
}
bg_install task-start

if [[ $check ]];then
        wait_bg
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
        sudo apt-get -o DPkg::Lock::Timeout=600 update > /dev/null
        update_log $ret "[~] Upgrading installed packages... Updating apt-get done..."
        sudo apt-get -o DPkg::Lock::Timeout=600 upgrade -y > /dev/null
        update_log $ret "[~] Update and upgrade done... Removing unused packages..."
        sudo apt-get -o DPkg::Lock::Timeout=600 autoremove -y > /dev/null
        update_log $ret "[+] apt-get updated and upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
        }
        apt_install apt-task
fi

###### Install python3
bg_install apt_installation "python3"

###### Install 2to3
bg_install apt_installation "2to3"

###### Install pip
pip-task (){
if [[ ! -x "$(command -v pip)" || $force ]];then
        if [[ ! -x "$(command -v pip3)" || $force ]];then
                add_log_entry; update_log $ret "[~] pip not detected... Installing"
                sudo apt-get -o DPkg::Lock::Timeout=600 install python3-pip -y >>$(get_log_file pip) 2>>$(get_log_file pip)
                update_log $ret "[+] pip Installed"
        fi
        # Check if an alias is needed
        if [[ ! -x "$(command -v pip)" ]];then
                add_log_entry; update_log $ret "[~] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
                update_log $ret "[*] pip is now an alias of pip3"
        fi
fi

###### Upgrade pip
if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        add_log_entry; update_log $ret "[~] Upgrading pip and python packages..."
        pip install --upgrade pip -q 2>>$(get_log_file pip) >>$(get_log_file pip)
        l=$(pip list --outdated | awk '{print($1)}' | tail -n +3)
        n=$(echo "$l" | wc -l | awk '{print($1)}')
        i=0
        for line in $l
        do
                update_log $ret "[~] Upgrading pip and python packages... $i/$n packages upgraded  | currently upgrading $line"
                pip_install pip install $line --upgrade -q 2>>$(get_log_file pip) >>$(get_log_file pip)
                (( i = i+1 ))
        done
        update_log $ret "[+] pip and python packages upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
fi
}
pip_install pip-task

###### Install poetry
poetry-task (){
if [[ ! -x "$(command -v poetry)" || $force ]];then
        add_log_entry; update_log $ret "[*] poetry not detected... Waiting for pip update"
        wait_pip
        update_log $ret "[~] poetry not detected... Installing"
        curl -sSL https://install.python-poetry.org | python3 >>$(get_log_file poetry) 2>>$(get_log_file poetry)
        update_log $ret "[+] poetry Installed"
fi
}
bg_install poetry-task

###### Install go
go-task(){
if [[ ! -x "$(command -v go)" || ! "$(go version)" =~ "1.20" || $force ]];then
        add_log_entry; update_log $ret "[~] go 1.20 not detected... Installing"
        wget  https://go.dev/dl/go1.20.2.linux-amd64.tar.gz -q
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
bg_install apt_installation "java" "Java" "default-jdk" "openjdk-17-jdk"

###### Install Nodejs
task-js() {
apt_installation "node" "NodeJS" "nodejs"

###### Install npm
apt_installation "npm"

###### Install yarn
if [[ ! -x "$(command -v yarn)" || $force ]];then
        add_log_entry; update_log $ret "[~] Yarn not detected... Installing"
        sudo npm install --silent --global yarn 2>>$(get_log_file yarn) >>$(get_log_file yarn)
        update_log $ret "[+] Yarn Installed"
fi
}
bg_install task-js

###### Install rust
task-rust() {
if [[ ! -x "$(command -v cargo)" || $force ]];then
        add_log_entry; update_log $ret "[~] Rust not detected... Installing"
        curl -s https://sh.rustup.rs -sSf | sh -s >>$(get_log_file rust) 2>>$(get_log_file rust) -- -y
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
        add_log_entry; update_log $ret "[*] Mono not detected... Waiting for apt upgrade"
        wait_apt
        update_log $ret "[~] Mono not detected... Installing"
        sudo apt-get -o DPkg::Lock::Timeout=600 install -yq dirmngr ca-certificates gnupg >>$(get_log_file mono) 2>>$(get_log_file mono) 
        sudo gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF 2>>$(get_log_file mono) >>$(get_log_file mono)
        echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list >/dev/null
        sudo apt-get -o DPkg::Lock::Timeout=600 install -yq mono-devel >>$(get_log_file mono) 2>>$(get_log_file mono) 
        update_log $ret "[+] Mono Installed"
fi
}
bg_install task-mono

###### Install dotnet
task-dotnet() {
if [[ ! -x "$(command -v dotnet)" || $force ]];then
        add_log_entry; update_log $ret "[~] Dotnet not detected... Installing"
        wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh -q
        chmod +x ./dotnet-install.sh
        ./dotnet-install.sh --version latest 2>>$(get_log_file dotnet) >>$(get_log_file dotnet)
        rm dotnet-install.sh
        export DOTNET_ROOT=$HOME/.dotnet
        export PATH=$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools
        update_log $ret "[+] Dotnet Installed"
fi
}
bg_install task-dotnet

###### Install gradle
task-gradle () {
        if [[ ! -x "$(command -v gradle)" || $force ]];then
                add_log_entry; update_log $ret "[~] gradle not detected... Waiting for 7z"
                wait_command "7z"
                update_log $ret "[~] gradle not detected... Installing"
                if [[ -d "/lib/gradle" ]];then
                        sudo mv /lib/gradle /lib/gradle-$(date +%y-%m-%d--%T).old
                        tmp=$ret
                        add_log_entry; update_log $ret "[*] Moved /lib/gradle to /lib/gradle-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                        ret=$tmp
                fi
                wget https://services.gradle.org/distributions/gradle-8.4-bin.zip -q
                7z x gradle-8.4-bin.zip 2>>$(get_log_file gradle) >>$(get_log_file gradle)
                rm gradle-8.4-bin.zip
                sudo mv gradle-8.4 /lib/gradle
                if [[ -f "/bin/gradle" ]];then sudo rm /bin/gradle;fi
                sudo ln -s /lib/gradle/bin/gradle /bin/gradle
                update_log $ret "[+] sublist3r Installed"
        fi
}
bg_install task-gradle

###### Install git
bg_install apt_installation "git"

###### Install krb5
bg_install apt_installation "kinit" "Kerberos" "krb5-user"


###### Install 7z

###### Install winrar


# Commands
add_log_entry; update_log $ret "[*] Getting commands..."
###### Install ftp module
bg_install pip_installation pyftpdlib

###### Install dnsutils
bg_install apt_installation "dig" "dig" "dnsutils"

###### Install google-chrome
task-chrome() {
if [[ ! -x "$(command -v google-chrome)" || $force ]];then
        add_log_entry; update_log $ret "[~] google-chrome not detected... Installing"
        wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -q
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./google-chrome-stable_current_amd64.deb -y >>$(get_log_file chrome) 2>>$(get_log_file chrome)
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
        add_log_entry; update_log $ret "[*] sublist3r not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] sublist3r not detected... Installing"
        if [[ -d "/lib/python3/dist-packages/subbrute" ]];then
                sudo mv /lib/python3/dist-packages/subbrute /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/python3/dist-packages/subbrute to /lib/python3/dist-packages/subbrute-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone https://github.com/aboul3la/Sublist3r.git --quiet >>$(get_log_file sublister) 2>>$(get_log_file sublister)
        update_log $ret "[~] sublist3r not detected... Waiting for pip"
        wait_pip
        update_log $ret "[~] sublist3r not detected... Installing requirements"
        pip install -r Sublist3r/requirements.txt -q 2>>$(get_log_file sublister) >>$(get_log_file sublister)
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
bg_install pip_installation arjun

###### Install BrokenLinkChecker
task-blc() {
if [[ ! -x "$(command -v blc)" || $force ]];then
        add_log_entry; update_log $ret "[*] BrokenLinkChecker not detected... Waiting for npm"
        wait_command "npm"
        update_log $ret "[~] BrokenLinkChecker not detected... Installing"
        sudo npm install --silent --global broken-link-checker 2>>$(get_log_file brokenlinkchecker) >>$(get_log_file brokenlinkchecker)
        update_log $ret "[+] BrokenLinkChecker Installed"
fi
}
bg_install task-blc

###### Install dirscraper
task-dirscraper() {
if [[ ! -x "$(command -v dirscraper)" || $force ]];then
        add_log_entry; update_log $ret "[*] Dirscapper not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Dirscapper not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/Cillian-Collins/dirscraper.git --quiet >>$(get_log_file dirscraper) 2>>$(get_log_file dirscraper)
        new_cont=$(echo "#! /bin/python3" && cat ./dirscraper/dirscraper.py)
        echo "$new_cont" > ./dirscraper/dirscraper.py
        sed -i 's/\r//' ./dirscraper/dirscraper.py
        chmod +x ./dirscraper/dirscraper.py
        sudo mv dirscraper/dirscraper.py /bin/dirscraper
        update_log $ret "[*] Dirscapper not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Dirscapper not detected... Installing requirements"
        pip install -r ./dirscraper/requirements.txt -q 2>>$(get_log_file dirscraper) >>$(get_log_file dirscraper)
        sudo rm -R ./dirscraper
        update_log $ret "[+] Dirscapper Installed"
fi
}
bg_install task-dirscraper

###### Install Haktrails
bg_install go_installation "haktrails" "github.com/hakluke/haktrails@latest" 

###### Install Hakrawler
bg_install go_installation "hakrawler" "github.com/hakluke/hakrawler@latest" 

###### Install linkfinder
task-linkfinder () {
        if [[ ! "$(command -v linkfinder)" || $force ]];then
                add_log_entry; update_log $ret "[~] Linkfinder not detected... Waiting for pip"
                wait_pip
                update_log $ret "[~] Linkfinder not detected... Waiting for git"
                wait_command "git"
                update_log $ret "[~] Linkfinder not detected... Installing dependencies"
                GIT_ASKPASS=true git clone https://github.com/GerbenJavado/LinkFinder.git --quiet >>$(get_log_file linkfinder) 2>>$(get_log_file linkfinder)
                cd LinkFinder
                pip install -r requirements.txt -q 2>>$(get_log_file linkfinder) >>$(get_log_file linkfinder)
                update_log $ret "[~] Linkfinder not detected... Installing"
                sudo python3 setup.py install 2>>$(get_log_file linkfinder) >>$(get_log_file linkfinder)
                sudo mv linkfinder.py /bin/linkfinder
                cd ..
                sudo rm -r LinkFinder
                update_log $ret "[+] Linkfinder Installed"
        fi
}
bg_install task-linkfinder

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
        add_log_entry; update_log $ret "[*] x8 not detected... Waiting for apt"
        wait_apt
        update_log $ret "[~] x8 not detected... Installing dependencies"
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y libssl-dev >>$(get_log_file x8) 2>>$(get_log_file x8)
        update_log $ret "[*] x8 not detected... Waiting for rust"
        wait_command "cargo"
        update_log $ret "[~] x8 not detected... Installing"
        cargo install x8 >>$(get_log_file x8) 2>>$(get_log_file x8)
        sudo mv /home/$usr/.cargo/bin/x8 /bin/x8
        update_log $ret "[+] x8 Installed"
fi
}
bg_install task-xeight

### Others
###### Install wappalyzer
task-wappalyzer() {
if [[ ! -x "$(command -v wappalyzer)" || $force ]];then
        add_log_entry; update_log $ret "[*] wappalyzer not detected... Waiting for yarn and git"
        wait_command "yarn" "git"
        update_log $ret "[~] wappalyzer not detected... Installing"
        if [[ -d "/lib/wappalyzer" ]];then
                sudo mv /lib/wappalyzer /lib/wappalyzer-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/wappalyzer to /lib/wappalyzer-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone https://github.com/lLouu/wappalyzer.git --quiet >>$(get_log_file wappalyzer) 2>>$(get_log_file wappalyzer)
        sudo mv wappalyzer /lib/wappalyzer
        workingdir=$(pwd)
        cd /lib/wappalyzer
        cd /lib/wappalyzer && yarn install --silent 2>>$(get_log_file wappalyzer) >>$(get_log_file wappalyzer)
        cd /lib/wappalyzer && yarn run link --silent 2>>$(get_log_file wappalyzer) >>$(get_log_file wappalyzer)
        cd $workingdir
        sudo chmod +x /lib/wappalyzer/src/drivers/npm/cli.js
        if [[ -f "/bin/wappalyzer" ]];then sudo rm /bin/wappalyzer;fi
        sudo ln -s /lib/wappalyzer/src/drivers/npm/cli.js /bin/wappalyzer
        update_log $ret "[+] wappalyzer Installed"
fi
}
bg_install task-wappalyzer

###### Install testssl
task-testssl() {
if [[ ! -x "$(command -v testssl)" || $force ]];then
        add_log_entry; update_log $ret "[~] Testssl not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Testssl not detected... Installing"
        if [[ -d "/lib32/testssl" ]];then
                sudo mv /lib32/testssl /lib32/testssl-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib32/testssl to /lib32/testssl-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone --depth 1 https://github.com/drwetter/testssl.sh.git --quiet >>$(get_log_file testssl) 2>>$(get_log_file testssl)
        sudo mv testssl.sh /lib32/testssl
        if [[ -f "/bin/testssl" ]];then sudo rm /bin/testssl;fi
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
        add_log_entry; update_log $ret "[*] Secretfinder not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Secretfinder not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/m4ll0k/SecretFinder.git --quiet >>$(get_log_file secretfinder) 2>>$(get_log_file secretfinder)
        chmod +x ./SecretFinder/SecretFinder.py
        sudo mv SecretFinder/SecretFinder.py /bin/secretfinder
        update_log $ret "[*] Secretfinder not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] Secretfinder not detected... Installing requirements"
        pip install -r ./SecretFinder/requirements.txt -q 2>>$(get_log_file secretfinder) >>$(get_log_file secretfinder)
        sudo rm -R ./SecretFinder
        update_log $ret "[+] Secretfinder Installed"
fi
}
bg_install task-secretfinder

###### Install wpscan
task-wpscan () {
if [[ ! -x "$(command -v wpscan)" || $force ]];then
        add_log_entry; update_log $ret "[*] WPscan not detected... Waiting for Ruby to be installed"
        wait_command "gem"
        update_log $ret "[~] WPscan not detected... Installing"
        sudo gem install wpscan >>$(get_log_file wpscan) 2>>$(get_log_file wpscan)
        update_log $ret "[+] WPscan Installed"
fi
}
bg_install task-wpscan


### Bruteforce
add_log_entry; update_log $ret "[*] Getting bruteforce tools..."
###### Install hashcat
bg_install apt_installation "hashcat"

###### Install hydra
task-hydra() {
if [[ ! -x "$(command -v hydra)" || $force ]];then
        add_log_entry; update_log $ret "[*] Hydra not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Hydra not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/vanhauser-thc/thc-hydra --quiet >>$(get_log_file hydra) 2>>$(get_log_file hydra)
        cd thc-hydra
        ./configure >>$(get_log_file hydra) 2>>$(get_log_file hydra)
        make >>$(get_log_file hydra) 2>>$(get_log_file hydra)
        sudo make install >>$(get_log_file hydra) 2>>$(get_log_file hydra)
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
        sudo ./ArmitageInstaller 2>>$(get_log_file armitage) >>$(get_log_file armitage)
        rm ArmitageInstaller
        curl -s -L https://raw.githubusercontent.com/BlackArch/msfdb/master/msfdb --output msfdb
        chmod +x msfdb
        sudo mv msfdb /bin
        update_log $ret "[+] Metasploit & Armitage Installed"
fi

if [[ ! $no_upgrade ]];then
        start_update=$(date +%s)
        add_log_entry; update_log $ret "[~] Upgrading metasploit..."
        sudo msfupdate >>$(get_log_file metasploit) 2>>$(get_log_file metasploit)
        update_log $ret "[*] Metasploit data upgraded... Took $(date -d@$(($(date +%s)-$start_update)) -u +%H:%M:%S)"
fi
}
bg_install task-metasploit

###### Install searchsploit
task-searchsploit() {
if [[ ! -x "$(command -v searchsploit)" || $force ]];then
        add_log_entry; update_log $ret "[~] Searchsploit not detected... Installing"
        GIT_ASKPASS=true git clone --depth 1 https://github.com/rad10/SearchSploit.py.git --quiet >>$(get_log_file sqlmap) 2>>$(get_log_file sqlmap)
        cd SearchSploit.py
        sed -i 's/input//g' setup.py
        python3 ./setup.py >>$(get_log_file sqlmap) 2>>$(get_log_file sqlmap)
        sudo mv searchsploit.py /bin/searchsploit
        cd ..
        sudo rm -r ./SearchSploit.py
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
        add_log_entry; update_log $ret "[*] sqlmap not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] sqlmap not detected... Installing"
        if [[ -d "/lib/sqlmap" ]];then
                sudo mv /lib/sqlmap /lib/sqlmap-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/sqlmap to /lib/sqlmap-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git --quiet >>$(get_log_file sqlmap) 2>>$(get_log_file sqlmap)
        update_log $ret "[*] sqlmap not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] sqlmap not detected... Installing" requirements
        pip install -r sqlmap/requirements.txt -q 2>>$(get_log_file sqlmap) >>$(get_log_file sqlmap)
        sudo mv sqlmap /lib/sqlmap
        new_cont=$(echo "#! /bin/python3" && cat /lib/sqlmap/sqlmap.py)
        echo "$new_cont" > /lib/sqlmap/sqlmap.py
        sudo chmod +x /lib/sqlmap/sqlmap.py
        if [[ -f "/bin/sqlmap" ]];then sudo rm /bin/sqlmap;fi
        sudo ln -s /lib/sqlmap/sqlmap.py /bin/sqlmap
        update_log $ret "[+] sqlmap Installed"
fi
}
bg_install task-sqlmap

###### Install commix
task-commix() {
if [[ ! -x "$(command -v commix)" || $force ]];then
        add_log_entry; update_log $ret "[*] commix not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] commix not detected... Installing"
        if [[ -d "/lib/commix" ]];then
                sudo mv /lib/commix /lib/commix-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/commix to /lib/commix-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone https://github.com/commixproject/commix.git --quiet >>$(get_log_file commix) 2>>$(get_log_file commix)
        sudo mv commix /lib/commix
        new_cont=$(echo "#! /bin/python3" && cat /lib/commix/commix.py)
        echo "$new_cont" > /lib/commix/commix.py
        sudo chmod +x /lib/commix/commix.py
        if [[ -f "/bin/commix" ]];then sudo rm /bin/commix;fi
        sudo ln -s /lib/commix/commix.py /bin/commix
        update_log $ret "[+] commix Installed"
fi
}
bg_install task-commix

###### Install pixload
task-pixload() {
if [[ ! -x "$(command -v pixload-png)" || $force ]];then
        add_log_entry; update_log $ret "[*] Pixload not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Pixload not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/sighook/pixload.git --quiet >>$(get_log_file pixload) 2>>$(get_log_file pixload)
        cd pixload
        make >>$(get_log_file pixload) 2>>$(get_log_file pixload)
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

###### Install ghidra
task-ghidra () {
if [[ ! -x "$(command -v ghidra)" || $force ]];then
        add_log_entry; update_log $ret "[*] ghidra not detected... Waiting for 7z"
        wait_command "7z"
        update_log $ret "[~] ghidra not detected... Installing"
        if [[ -d "/lib/ghidra" ]];then
                sudo mv /lib/ghidra /lib/ghidra-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/ghidra to /lib/ghidra-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip -q 2>>$(get_log_file ghidra) >>$(get_log_file ghidra)
        7z x ghidra_10.4_PUBLIC_20230928.zip >>$(get_log_file ghidra) 2>>$(get_log_file ghidra)
        rm ghidra_10.4_PUBLIC_20230928.zip
        sudo mv ghidra_10.4_PUBLIC /lib/ghidra
        if [[ -f "/bin/ghidra" ]];then sudo rm /bin/ghidra;fi
        sudo ln -s /lib/ghidra/ghidraRun /bin/ghidra
        update_log $ret "[+] ghidra Installed | It will ask you Java openjdk 17 directory at first launch"
fi
}
bg_install task-ghidra

###### Install gdb
bg_install apt_installation "gdb" "GDB" "libelf1=0.183-1" "libdw1=0.183-1" "gdb"

###### Install shocker
task-shocker() {
if [[ ! -x "$(command -v shocker)" || $force ]];then
        add_log_entry; update_log $ret "[~] Shocker not detected... Installing"
        wget https://raw.githubusercontent.com/nccgroup/shocker/master/shocker.py -q 2>>$(get_log_file shocker) >>$(get_log_file shocker)
        2to3 -x ./shocker.py 2>>$(get_log_file shocker) >>$(get_log_file shocker)
        chmod +x shocker.py
        sudo mv shocker.py /bin/shocker
        update_log $ret "[+] Shocker Installed"
fi
}
bg_install task-shocker


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
        if [[ -f "/bin/odat" ]];then sudo rm /bin/odat;fi
        sudo ln -s /lib32/odat_lib/odat-libc2.17-x86_64 /bin/odat
        update_log $ret "[+] odat Installed"
fi
}
bg_install task-odat

###### Install crackmapexec
task-crackmapexec() {
if [[ ! -x "$(command -v crackmapexec)" || $force ]];then
        add_log_entry; update_log $ret "[*] crackmapexec not detected... Waiting for apt upgrade"
        wait_apt
        update_log $ret "[~] crackmapexec not detected... Getting Dependencies"
        if [[ -d "/lib/crackmapexec" ]];then
                sudo mv /lib/crackmapexec /lib/crackmapexec-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/crackmapexec to /lib/crackmapexec-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y libssl-dev libffi-dev python-dev-is-python3 build-essential >>$(get_log_file cme) 2>>$(get_log_file cme)
        update_log $ret "[*] crackmapexec not detected... Waiting for poetry and git"
        wait_command "poetry" "git"
        update_log $ret "[~] crackmapexec not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/byt3bl33d3r/CrackMapExec --quiet >>$(get_log_file cme) 2>>$(get_log_file cme)
        sudo mv CrackMapExec /lib/crackmapexec
        workingdir=$(pwd)
        cd /lib/crackmapexec
        cd /lib/crackmapexec && poetry lock >>$(get_log_file cme) 2>>$(get_log_file cme)
        cd /lib/crackmapexec && poetry install >>$(get_log_file cme) 2>>$(get_log_file cme)
        update_log $ret "[~] crackmapexec not detected... Initialize"
        cd /lib/crackmapexec && poetry run crackmapexec >>$(get_log_file cme) 2>>$(get_log_file cme)
        cd $workingdir
        printf "#! /bin/sh\ncd /lib/crackmapexec\npoetry run crackmapexec \$args" > crackmapexec
        chmod +x crackmapexec
        sudo mv crackmapexec /bin/crackmapexec
        printf "#! /bin/sh\ncd /lib/crackmapexec\npoetry run crackmapexec \$args" > cme
        chmod +x cme
        sudo mv cme /bin/cme
        printf "#! /bin/sh\ncd /lib/crackmapexec\npoetry run cmedb \$args" > cmedb
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
        add_log_entry; update_log $ret "[*] mitm6 not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] mitm6 not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/dirkjanm/mitm6.git --quiet >>$(get_log_file mitm6) 2>>$(get_log_file mitm6)
        update_log $ret "[*] mitm6 not detected... Waiting for pip upgrade"
        wait_pip
        update_log $ret "[~] mitm6 not detected... Installing requirements"
        pip install -r mitm6/requirements.txt -q 2>>$(get_log_file mitm6) >>$(get_log_file mitm6)
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
        add_log_entry; update_log $ret "[*] Proxychain not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Proxychain not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/haad/proxychains.git --quiet >>$(get_log_file proxychains) 2>>$(get_log_file proxychains)
        cd proxychains
        ./configure >>$(get_log_file proxychains) 2>>$(get_log_file proxychains)
        make >>$(get_log_file proxychains) 2>>$(get_log_file proxychains)
        sudo make install >>$(get_log_file proxychains) 2>>$(get_log_file proxychains)
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
        add_log_entry; update_log $ret "[*] responder not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] responder not detected... Installing"
        if [[ -d "/lib/responder" ]];then
                sudo mv /lib/responder /lib/responder-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/responder to /lib/responder-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone https://github.com/lgandx/Responder.git --quiet >>$(get_log_file responder) 2>>$(get_log_file responder)
        sudo mv Responder /lib/responder
        new_cont=$(echo "#! /bin/python3" && cat /lib/responder/Responder.py)
        echo "$new_cont" > /lib/responder/Responder.py
        sudo chmod +x /lib/responder/Responder.py
        if [[ -f "/bin/responder" ]];then sudo rm /bin/responder;fi
        sudo ln -s /lib/responder/Responder.py /bin/responder
        update_log $ret "[+] responder Installed"
fi
}
bg_install task-responder

###### Install Evil winrm
task-evilwinrm () {
if [[ ! -x "$(command -v evil-winrm)" || $force ]];then
        add_log_entry; update_log $ret "[*] Evil WinRM not detected... Waiting for Ruby to be installed"
        wait_command "gem"
        update_log $ret "[~] Evil WinRM not detected... Installing"
        sudo gem install evil-winrm >>$(get_log_file evil-winrm) 2>>$(get_log_file evil-winrm)
        update_log $ret "[+] Evil WinRM Installed"
fi
}
bg_install task-evilwinrm

###### Install Bloody AD
task-bloodyad () {
        wait_apt
        wait_pip
        sudo apt-get -o DPkg::Lock::Timeout=600 install -y --allow-downgrades libcom-err2=1.46.2-2 libkrb5-dev >>$(get_log_file bloodyAD) 2>>$(get_log_file bloodyAD)
        pip_installation bloodyAD
}
bg_install task-bloodyad

###### Install smbmap
bg_install pip_installation smbmap

###### Install Certipy
bg_install pip_installation certipy-ad

###### Install Pydictor
task-pydictor() {
if [[ ! -x "$(command -v pydictor)" || $force ]];then
        add_log_entry; update_log $ret "[*] Pydictor not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Pydictor not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/LandGrey/pydictor.git --quiet >>$(get_log_file pydictor) 2>>$(get_log_file pydictor)
        chmod +x pydictor/pydictor.py
        if [[ -d "/lib/pydictor" ]];then
                sudo mv /lib/pydictor /lib/pydictor-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/pydictor to /lib/pydictor-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        sudo mv pydictor /lib/pydictor
        if [[ -f "/bin/pydictor" ]];then sudo rm /bin/pydictor;fi
        sudo ln -s /lib/pydictor/pydictor.py /bin/pydictor
        update_log $ret "[+] Pydictor Installed"
fi
}
bg_install task-pydictor


## Hot scripts
add_log_entry; update_log $ret "[*] Getting scripts..."
###### Install dnscat2 & dependencies
task-dnscat() {
if [[ ! -d "/lib/dnscat" || $force ]];then
        add_log_entry; update_log $ret "[*] Dnscat sourcecode not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] Dnscat sourcecode not detected... Installing"
        if [[ -d "/lib/dnscat" ]];then
                sudo mv /lib/dnscat /lib/dnscat-$(date +%y-%m-%d--%T).old
                tmp=$ret
                add_log_entry; update_log $ret "[*] Moved /lib/dnscat to /lib/dnscat-$(date +%y-%m-%d--%T).old due to forced reinstallation"
                ret=$tmp
        fi
        GIT_ASKPASS=true git clone https://github.com/iagox86/dnscat2.git --quiet >>$(get_log_file dnscat) 2>>$(get_log_file dnscat)
        sudo mv dnscat2 /lib/dnscat
        # correct minor sourcecode error
        sudo sed -i 's/return a.value.ptr == a.value.ptr/return a.value.ptr == b.value.ptr/g' /lib/dnscat/client/libs/ll.c
        update_log $ret "[+] Dnscat sourcecode Installed"
fi

if [[ ! -f "$hotscript/dnscat" || $force ]];then
        add_log_entry; update_log $ret "[*] Dnscat client not detected... Waiting for make"
        wait_command "make"
        update_log $ret "[~] Dnscat client not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        cd /lib/dnscat/client && make >>$(get_log_file dnscat) 2>>$(get_log_file dnscat)
        mv /lib/dnscat/client/dnscat $hotscript/dnscat
        cd $workingdir
        update_log $ret "[+] Dnscat client Made"
fi

if [[ ! -x "$(command -v dnscat)" || $force ]];then
        add_log_entry; update_log $ret "[*] Dnscat server not detected... Waiting for Ruby to be installed"
        wait_command "gem" "bundler"
        update_log $ret "[~] Dnscat server not detected... Making"
        workingdir=$(pwd)
        cd /lib/dnscat/server
        cd /lib/dnscat/server && sudo gem install bundler >>$(get_log_file dnscat) 2>>$(get_log_file dnscat)
        cd /lib/dnscat/server && sudo bundler install 2>>$(get_log_file dnscat) >>$(get_log_file dnscat)
        cd $workingdir
        new_cont=$(echo "#! /bin/ruby" && cat /lib/dnscat/server/dnscat2.rb)
        echo "$new_cont" > /lib/dnscat/server/dnscat2.rb
        sudo chmod +x /lib/dnscat/server/dnscat2.rb
        if [[ -f "/bin/dnscat" ]];then sudo rm /bin/dnscat;fi
        sudo ln -s /lib/dnscat/server/dnscat2.rb /bin/dnscat
        update_log $ret "[+] Dnscat server Made"
fi

if [[ ! -x "$(command -v dnscat-shell)" || $force ]];then
        add_log_entry; update_log $ret "[~] dnscat shell not detected... Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/$branch/misc/dnscat-shell.sh -q
        chmod +x dnscat-shell.sh
        sudo mv dnscat-shell.sh /bin/dnscat-shell
        update_log $ret "[+] dnscat shell Installed"
fi
}
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
        add_log_entry; update_log $ret "[*] frp not detected... Waiting for git"
        wait_command "git"
        update_log $ret "[~] frp not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/fatedier/frp.git --quiet >>$(get_log_file frp) 2>>$(get_log_file frp)
        cd frp
        ./package.sh >>$(get_log_file frp) 2>>$(get_log_file frp)
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
        add_log_entry; update_log $ret "[~] Miranda not detected... Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py -q
        mv miranda.py $hotscript/miranda.py
        chmod +x $hotscript/miranda.py
        2to3 $hotscript/miranda.py -w $hotscript/miranda.py >>$(get_log_file miranda) 2>>$(get_log_file miranda)
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
        add_log_entry; update_log $ret "[*] Mimipenguin not detected... Waiting for make and git"
        wait_command "make" "git"
        update_log $ret "[~] Mimipenguin not detected... Installing"
        GIT_ASKPASS=true git clone https://github.com/huntergregal/mimipenguin.git --quiet >>$(get_log_file mimipenguin) 2>>$(get_log_file mimipenguin)
        cd mimipenguin
        sudo make >>$(get_log_file mimipenguin) 2>>$(get_log_file mimipenguin)
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
        pip_installation wesng
        wes --update >>$(get_log_file wesng) 2>>$(get_log_file wesng)
}
bg_install task-wesng

###### Install watson

###### Install powersploit
task-powersploit () {
        if [[ ! -d "$hotscript/powersploit" || $force ]];then
                add_log_entry; update_log $ret "[~] Powersploit not detected... Installing"
                GIT_ASKPASS=true git clone https://github.com/PowerShellMafia/PowerSploit.git --quiet >>$(get_log_file powersploit) 2>>$(get_log_file powersploit)
                mv PowerSploit $hotscript/powersploit
                update_log $ret "[+] Powersploit Installed"
        fi
}
bg_install task-powersploit

###### Install evilSSDP

###### Install netcat exe
task-netcatexe () {
        if [[ ! -f "$hotscript/nc.exe" || $force ]];then
                add_log_entry; update_log $ret "[~] Netcat exe not detected... Installing"
                GIT_ASKPASS=true git clone https://github.com/int0x33/nc.exe.git --quiet >>$(get_log_file netcat) 2>>$(get_log_file netcat)
                mv nc.exe/nc.exe $hotscript/nc.exe
                mv nc.exe/nc64.exe $hotscript/nc64.exe
                sudo rm -r nc.exe
                update_log $ret "[+] Netcat exe Installed"
        fi
}
bg_install task-netcatexe

###### Install ligolo ng
task-ligolo () {
        if [[ ! -f "$hotscript/ligolo" || ! "$(command -v ligolo)" || $force ]];then
                add_log_entry; update_log $ret "[*] Ligolo not detected... Waiting for go"
                wait_command "go"
                update_log $ret "[~] Ligolo not detected... Installing"
                GIT_ASKPASS=true git clone https://github.com/nicocha30/ligolo-ng.git --quiet >>$(get_log_file ligolo) 2>>$(get_log_file ligolo)
                cd ligolo-ng
                go build -o $hotscript/ligolo cmd/agent/main.go >>$(get_log_file ligolo) 2>>$(get_log_file ligolo)
                sudo go build -o /bin/ligolo cmd/proxy/main.go >>$(get_log_file ligolo) 2>>$(get_log_file ligolo)
                cd ..
                sudo rm -r ligolo-ng
                update_log $ret "[+] Ligolo Installed"
        fi
}
bg_install task-ligolo

###### Install FullPowers
task-fullpowers () {
        if [[ ! -f "$hotscript/FullPowers.exe" || $force ]];then
                add_log_entry; update_log $ret "[~] FullPowers not detected... Installing"
                wget "https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe" -q >>$(get_log_file FullPowers) 2>>$(get_log_file FullPowers)
                mv FullPowers.exe $hotscript/FullPowers.exe
                update_log $ret "[+] FullPowers Installed"
        fi
}
bg_install task-fullpowers

###### Install GodPotatoe
task-godpotato () {
        if [[ ! -f "$hotscript/godpotatoNET2.exe" || ! -f "$hotscript/godpotatoNET4.exe" || ! -f "$hotscript/godpotatoNET35.exe" || $force ]];then
                add_log_entry; update_log $ret "[~] GodPotato not detected... Installing"
                wget "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET2.exe" -q -o "$hotscript/godpotatoNET2.exe" >>$(get_log_file godpotato) 2>>$(get_log_file godpotato)
                wget "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe" -q -o "$hotscript/godpotatoNET4.exe" >>$(get_log_file godpotato) 2>>$(get_log_file godpotato)
                wget "https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET35.exe" -q -o "$hotscript/godpotatoNET35.exe" >>$(get_log_file godpotato) 2>>$(get_log_file godpotato)
                update_log $ret "[+] GodPotato Installed"
        fi
}
bg_install task-godpotato


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
        add_log_entry; update_log $ret "[~] Nessus not detected... Installing"
        file=$(curl -s --request GET --url 'https://www.tenable.com/downloads/api/v2/pages/nessus' | grep -o -P "Nessus-\d+\.\d+\.\d+-debian10_amd64.deb" | head -n 1)
        curl -s --request GET \
               --url "https://www.tenable.com/downloads/api/v2/pages/nessus/files/$file" \
               --output 'Nessus.deb'
        sudo apt-get -o DPkg::Lock::Timeout=600 install ./Nessus.deb -y >>$(get_log_file nessus) 2>>$(get_log_file nessus)
        rm Nessus.deb
        sudo systemctl start nessusd
        update_log $ret "[~] Go to https://localhost:8834 to complete nessus installation"
fi
}
bg_install task-nessus

wait_apt
wait_pip
wait_bg

add_log_entry; update_log $ret "[~] Installation done... Took $(date -d@$(($(date +%s)-$start)) -u +%H:%M:%S)"

stop

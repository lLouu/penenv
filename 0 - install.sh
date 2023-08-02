#! /bin/sh
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
echo "Suite version : V0.1.0"
echo "Script version : V1.0"
echo ""
echo ""



# Set directory environement
usr=$(whoami)
if [[ $usr == "root" ]];then
        echo -e "[-] Running as root. Please install in rootless mode... Exiting..."
        exit 1
fi
hotscript=/home/$usr/hot-script
if [[ ! -d $hotscript ]];then
        mkdir $hotscript
fi

# Set self command
if [[ ! -x "$(command -v install_penenv)" ]];then
        echo -e "[+] install_penenv not detected as a command...Setting up"
        wget https://raw.githubusercontent.com/lLouu/penenv/main/0%20-%20install.sh > installing;rm installing
        chmod +x 0\ -\ install.sh
        sudo mv 0\ -\ install.sh /bin/install_penenv
fi

# Install autoenum & its dependencies
if [[ ! -x "$(command -v autoenum)" ]];then
        echo -e "[+] autoenum not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/main/A%20-%20autoenum.sh > installing;rm installing
        chmod +x A\ -\ autoenum.sh
        sudo mv A\ -\ autoenum.sh /bin/autoenum
        echo -e "[+] Installing autoenum dependencies"
        autoenum --first
fi

# Install start
if [[ ! -x "$(command -v start)" ]];then
        echo -e "[+] start not detected...Installing"
        wget https://raw.githubusercontent.com/lLouu/penenv/main/1%20-%20start.sh > installing;rm installing
        chmod +x 1\ -\ start.sh
        sudo mv 1\ -\ start.sh /bin/start
fi

# Install bloodhound
if [[ ! -x "$(command -v bloodhound)" ]];then
        echo -e "[+] Bloodhound not detected...Installing"
        sudo apt-get install bloodhound -y > installing;rm installing
        echo -e "[~] Go to http://localhost:7474 to set new neo4j password" 
fi

if [[ ! -x "$(find $hotscript -name Invoke-Bloodhound.ps1)" ]];then
        echo -e "[+] Invoke-Bloodhound not detected...Installing"
        wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1 > installing;rm installing
        mv SharpHound.ps1 $hotscript/Invoke-Bloodhound.ps1
fi

if [[ ! -x "$(command -v java)" ]];then
        echo -e "[+] Java not detected...Installing"
        sudo apt-get install default-jdk -y > installing;rm installing
fi

if [[ ! "$(java --version)" =~ "openjdk 11.0.18" ]];then
        echo -e "[+] Java != 11 is used... Setting it to 11.0.18"
        sudo update-alternatives --set java /usr/lib/jvm/java-11-openjdk-amd64/bin/java
fi

# Install Nessus
if [[ -f "/opt/nessus/sbin/nessusd" ]];then
        echo -e "[+] Nessus not detected...Installing"
        curl --request GET \
               --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.5.3-debian10_amd64.deb' \
               --output 'Nessus.deb' > installing;rm installing
        sudo apt-get install ./Nessus.deb -y > installing;rm installing
        rm Nessus.deb
        sudo systemctl start nessusd
        echo -e "[~] Go to http://localhost:8834 to complete nessus installation" 
fi

# Install ftp module
if [[ ! -x "$(pip list | grep pyftpdlib)" ]];then
        echo -e "[+] Pyftpdlib not detected...Installing"
        sudo pip install pyftpdlib > installing;rm installing
fi

# Install impacket
if [[ ! -d "/usr/share/doc/python-impacket" ]];then
        echo -e "[+] Impacket not detected...Installing"
        sudo pip install python3-impacket > installing;rm installing
        git clone https://github.com/fortra/impacket > installing;rm installing
        sudo cp impacket/exemple/* /bin
        sudo mv impacket /usr/share/doc/python-impacket > installing;rm installing
        printf "#! /bin/sh\nls /usr/share/doc/python-impacket/examples/" > impacket_script
        chmod +x impacket_script
        sudo mv impacket_script /bin/impacket_script
fi

# Install dns2cat & dependencies
if [[ ! -x "$(command -v make)" ]];then
        echo -e "[+] Make not detected...Installing"
        sudo apt-get install make -y > installing;rm installing
fi

if [[ ! -x "$(command -v gem)" ]];then
        echo -e "[+] Rubby not detected...Installing"
        sudo apt-get install ruby-dev -y > installing;rm installing
fi

if [[ ! -d "/lib/dnscat" ]];then
        echo -e "[+] Dnscat sourcecode not detected...Installing"
        git clone https://github.com/iagox86/dnscat2.git > installing;rm installing
        sudo mv dnscat2 /lib/dnscat
fi

if [[ ! -f "$hotscript/dnscat" ]];then
        echo -e "[+] Dnscat client not detected...Making"
        workingdir=$(pwd)
        cd /lib/dnscat/client
        make > installing;rm installing
        mv dnscat $hotscript/dnscat
        cd $workingdir
fi

if [[ ! -x "$(command -v dnscat)" ]];then
        echo -e "[+] Dnscat server not detected...Making"
        workingdir=$(pwd)
        sudo cd /lib/dnscat/server
        sudo gem install bundler
        sudo bundler install
        cd $workingdir
        
        echo -e "[+] Creating command..."
        printf "#! /bin/sh\n^sudo ruby /lib/dnscat/server/dnscat2.rb \$@" > dnscat
        chmod +x dnscat
        sudo mv dnscat /bin/dnscat
fi

# Install PEAS
if [[! -f "$hotscript/LinPEAS.sh"]];then
        echo -e "[+] LinPEAS not detected...Installing"
        curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
        mv linpeas.sh $hotscript/LinPEAS.sh
fi

if [[! -f "$hotscript/WinPEAS.ps1"]];then
        echo -e "[+] WinPEAS powershell not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1
        mv winPEAS.ps1 $hotscript/WinPEAS.ps1
fi

if [[! -f "$hotscript/WinPEAS.bat"]];then
        echo -e "[+] WinPEAS bat not detected...Installing"
        wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        mv winPEAS.bat $hotscript/WinPEAS.bat
fi

# Install miranda
if [[ ! -f "$hotscript/miranda.py" ]];then
        echo -e "[+] Miranda not detected...Installing"
        wget https://raw.githubusercontent.com/0x90/miranda-upnp/master/src/miranda.py
        mv miranda.py $hotscript/miranda.py
fi

# Install pspy
if [[ ! -f "$hotscript/pspy32" ]];then
        echo -e "[+] Pspy32 not detected...Installing"
        curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy32
        mv pspy32 $hotscript/pspy32
fi

if [[ ! -f "$hotscript/pspy64" ]];then
        echo -e "[+] Pspy64 not detected...Installing"
        curl -L https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
        mv pspy64 $hotscript/pspy64
fi

#!/bin/bash
dir=$(dirname $(readlink -f $0))
usr=$(whoami)

# TODO : implement testssl in the different fetch
# cloned from https://github.com/Gr1mmie/autoenum

echo "[+] Updating apt-get and upgrading installed packages... This may take a while"
sudo apt-get update > upgrade
sudo apt-get upgrade -y > upgrade
sudo apt-get autoremove -y > upgrade; rm upgrade
tput setaf 4;echo "[*] apt-get updated and upgraded";tput sgr0

if [ ! -x "$(command -v tput)" ];then
        echo "[+] tput not detected. installing..."
        sudo apt-get install tput -y > /dev/null
fi

if [ ! -x "$(command -v python3)" ];then
        echo "[+] python3 not detected...Installing"
        sudo apt-get install python3 -y > /dev/null
fi

if [ ! -x "$(command -v pip)" ];then
        if [ ! -x "$(command -v pip3)" ];then
                echo "[+] pip not detected...Installing"
                sudo apt-get install python3-pip -y > /dev/null
        fi
        # Check if an alias is needed
        if [ ! -x "$(command -v pip)" ];then
                echo "[+] pip3 detected...Putting pip as an alias"
                sudo alias pip="pip3"
        fi
fi

echo "[+] Upgrading pip and python packages... This may take a while"
pip install --upgrade pip -q 2> /dev/null
pip list --outdated | awk '{print($1)}' | tail -n +3 > requirements.txt
sudo pip install -r requirements.txt --upgrade -q 2> /dev/null
rm requirements.txt
tput setaf 4;echo "[*] pip and python packages upgraded";tput sgr0


if [ ! -x "$(command -v dig)" ];then
        echo "[+] dig not detected...Installing"
        sudo apt-get install dnsutils > /dev/null
fi

if [ ! -x "$(command -v sublist3r)" ];then
        echo "[+] sublist3r not detected...Installing"
        sudo git clone https://github.com/aboul3la/Sublist3r.git --quiet > /dev/null
        pip install -r Sublist3r/requirements.txt -q
        sudo mv Sublist3r/sublist3r.py /bin/sublist3r
        sudo mv Sublist3r/subbrute /lib/python3/dist-packages/subbrute
        sudo rm Sublist3r/*
        sudo rm -R Sublist3r
fi

if [ ! -x "$(command -v go)" ];then
        echo "[+] golang not detected...Installing"
        sudo apt-get install golang -y > /dev/null
fi

if [ ! -x "$(command -v git)" ];then
        echo "[+] git not detected...Installing"
        sudo apt-get install git -y > /dev/null
fi

if [ ! -x "$(command -v assetfinder)" ];then
        echo "[+] assetfinder not detected...Installing"
        go install github.com/tomnomnom/assetfinder@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/assetfinder /bin/assetfinder
fi

if [ ! -x "$(command -v amass)" ];then
        echo "[+] amass not detected...Installing"
        go install github.com/owasp-amass/amass/v4/...@master 2> /dev/null
        sudo cp /home/$usr/go/bin/amass /bin/amass
fi

if [ ! -x "$(command -v gowitness)" ];then
        echo "[+] Gowitness not detected...Installing"
        go install github.com/sensepost/gowitness@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/gowitness /bin/gowitness
fi

if [ ! -x "$(command -v subjack)" ];then
        echo "[+] Subjack not detected...Installing"
        go install github.com/haccer/subjack@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/subjack /bin/subjack
fi

if [ ! -x "$(command -v certspotter)" ];then
        echo "[+] certspotter not detected...Installing"
        go install software.sslmate.com/src/certspotter/cmd/certspotter@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/certspotter /bin/certspotter
fi

if [ ! -x "$(command -v httprobe)" ];then
        echo "[+] httprobe not detected...Installing"
        go install github.com/tomnomnom/httprobe@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/httprobe /bin/httprobe
fi

if [ ! -x "$(command -v waybackurls)" ];then
        echo "[+] waybackurls not detected...Installing"
        go install github.com/tomnomnom/waybackurls@latest 2> /dev/null
        sudo cp /home/$usr/go/bin/waybackurls /bin/waybackurls
fi

if [[ ! -x "$(command -v testssl)" ]];then
        echo -e "[+] Testssl not detected...Installing"
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git --quiet > /dev/null
        sudo mv testssl.sh /lib32/testssl
        printf "#! /bin/sh\nsudo /lib32/testssl/testssl.sh \$@" > testssl
        chmod +x testssl
        sudo mv testssl /bin/testssl
fi

if [ ! -x "$(command -v nmap)" ];then
        echo "[+] nmap not detected...Installing"
        sudo apt-get install nmap -y > /dev/null
fi

if [ ! -x "$(command -v nikto)" ];then
        echo "[+] nikto not detected. Installing..."
        sudo apt-get install nikto -y > /dev/null
fi

if [ ! -x "$(command -v gobuster)" ];then
        echo "[+] gobuster not detected. Installing..."
        sudo apt-get install gobuster -y > /dev/null
fi

if [ ! -x "$(command -v whatweb)" ];then
       echo "[+] whatweb not detected. installing..."
        sudo apt-get install whatweb -y > /dev/null
fi

if [ ! -x "$(command -v onesixtyone)" ];then
        echo "[+] onesixtyone not detected. Installing..."
        sudo apt-get install onesixtyone -y > /dev/null
fi

if [ ! -x "$(command -v rpcbind)" ];then
        echo "[+] rpcbind not detected. Installing..."
        sudo apt-get install rpcbind -y > /dev/null
fi

if [ ! -x "$(command -v snmp-check)" ];then
        echo "[+] snmp-check not detected. Installing..."
        sudo apt-get install snmpcheck -y > /dev/null
fi

if [ ! -x "$(command -v snmpwalk)" ];then
        echo "[+] snmpwalk not detected. Installing..."
        sudo apt-get install snmp -y > /dev/null
fi

if [ ! -x "$(command -v fierce)" ];then
        echo "[+] fierce not detected. Installing..."
        sudo apt-get install fierce -y > /dev/null
fi

if [ ! -x "$(command -v dnsrecon)" ];then
        echo "[+] dnsrecon not detected. Installing..."
        sudo apt-get install dnsrecon -y > /dev/null
fi

if [ ! -x "$(command -v dnsenum)" ];then
        echo "[+] dnsenum not detected. Installing..."
        sudo apt-get install dnsenum -y > /dev/null
fi

if [ ! -x "$(command -v oscanner)" ];then
        echo "[+] oscanner not detected. Installing..."
        sudo apt-get install oscanner -y > /dev/null
fi

if [ ! -x "$(command -v wafw00f)" ];then
        echo "[+] wafw00f not detected. Installing..."
        sudo apt-get install wafw00f -y > /dev/null
fi

if [ ! -x "$(command -v odat)" ];then
        echo "[+] odat not detected. installing..."
        sudo wget https://github.com/quentinhardy/odat/releases/download/5.1.1/odat-linux-libc2.17-x86_64.tar.gz -q
        sudo tar xzf odat-linux-libc2.17-x86_64.tar.gz
        sudo mv odat-libc2.17-x86_64 /lib32/odat_lib
        printf "#! /bin/sh\nsudo /lib32/odat_lib/odat-libc2.17-x86_64 \$@" > odat
        chmod +x odat
        sudo mv odat /bin/odat
fi

if [ ! -x "$(command -v jq)" ];then
        echo "[+] jq not detected. installing..."
        sudo apt-get install jq -y > /dev/null
fi


# source $dir/functions/banner.sh
banner (){
tput setaf 6
        echo '                   --                                        '
        echo '    ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___   '
        echo '   / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \  '
        echo '  / /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /  '
        echo '  \__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/   '
        echo "                                                             "
tput bold; echo "Author: Grimmie && lLou_                                  "
tput bold; echo "Version: 3.0.1 - A                                        "
        tput sgr0
        sleep 1.025
}


# source $dir/functions/upgrade.sh
upgrade (){
        tput setaf 4;echo "[*] Checking if anything requires updates, this may take a few minutes...."
	arr=('nmap' 'nikto' 'wafw00f' 'odat' 'oscanner' 'dnsenum' 'dnsrecon' 'fierce' 'onesixtyone' 'whatweb' 'rpcbind' 'gem')
	for tool in $arr[@];do
		sudo apt-get install $tool -y 2&>/dev/null &
	done
		gem install wpscan 2&>/dev/null &
	wait
        tput setaf 4;echo "[*] Done!";tput sgr0
}

# source $dir/functions/scans.sh
OS_guess (){
	guess=$(ping -c 1 -W 3 $IP | grep '64' | awk '{print($6)}' | cut -d '=' -f2)
	if [[ "$guess" == 127 ]] || [[ "$guess" == 128 ]];then
		tput setaf 4;echo "[*] This machine is probably running Windows";tput sgr0
	elif [[ "$guess" == 255 ]] || [[ "$guess" == 254 ]];then
		tput setaf 4;echo "[*] This machine is probably running Cisco/Solaris/OpenBSD";tput sgr0
	elif [[ "$guess" == 63 ]] || [[ "$guess" == 64 ]];then
		tput setaf 4;echo "[*] This machine is probably running Linux";tput sgr0
	else
		echo "[-] Could not determine OS"
	fi
	sleep 1.5
}

enum_goto (){
        if [[ -s "$loot/raw/redis_found" ]];then redis_enum;fi
        if [[ -s "$loot/raw/snmp_found" ]];then snmp_enum;fi
        if [[ -s "$loot/raw/pop3_found" ]];then pop3_enum;fi
        if [[ -s "$loot/raw/imap_found" ]];then imap_enum;fi
        if [[ -s "$loot/raw/ftp_found" ]];then ftp_enum;fi
        if [[ -s "$loot/raw/ldap_found" ]];then ldap_enum;fi
        if [[ -s "$loot/raw/smtp_found" ]];then smtp_enum;fi
        if [[ -s "$loot/raw/oracle_found" ]];then oracle_enum;fi
        if [[ -s "$loot/raw/smb_found" ]];then smb_enum;fi
        if [[ -s "$loot/raw/http_found" ]];then http_enum;fi

        if [[ -s "$loot/raw/windows_found" ]];then windows_enum;fi
        if [[ -s "$loot/raw/linux_found" ]];then linux_enum;fi

}

reg (){
        banner
        upgrade
	OS_guess
        nmap_reg="nmap -p- -O -T4 -Pn -v $IP"
        if [[ ! -d "$IP/autoenum/reg_scan/raw" ]];then mkdir -p $IP/autoenum/reg_scan/raw; fi
        if [[ ! -d "$IP/autoenum/reg_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/reg_scan/ports_and_services; fi
        tput setaf 6;echo "Checking top 1k ports...";tput sgr0
        nmap --top-ports 1000 -sV $IP | tee -a $IP/autoenum/reg_scan/top_1k
        tput setaf 6;echo -e "Scan complete. View 1k scan at $IP/autoenum/aggr_scan/top_1k\nStarting more comprehensive scan...";tput sgr0
        nmap -sV $IP -oX $IP/autoenum/reg_scan/raw/xml_out & $nmap_reg | tee $IP/autoenum/reg_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/reg_scan/raw/xml_out >> $loot/exploits/searchsploit_nmap
        searchsploit --nmap $IP/autoenum/reg_scan/raw/xml_out
        cat $loot/exploits/searchsploit_nmap | jq >> $loot/exploits/searchsploit_nmap.json
        rm $loot/exploits/searchsploit_nmap

        cat $IP/autoenum/reg_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/reg_scan/ports_and_services/services_running
        cat $IP/autoenum/reg_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/reg_scan/ports_and_services/OS_detection
        cat $IP/autoenum/reg_scan/raw/full_scan | sed -n '/PORT/,/exact/p' | sed '$d' >>  $IP/autoenum/reg_scan/ports_and_services/script_output

        cat $IP/autoenum/reg_scan/ports_and_services/services_running | grep "http" | sort -u >> $loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1;done >  $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $IP/autoenum/reg_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

aggr (){
        banner
        upgrade
	OS_guess
        nmap_aggr="nmap -n -A -T4 -p- --max-retries 1 -Pn -v $IP"
        if [[ ! -d "$IP/autoenum/aggr_scan/raw" ]];then mkdir -p $IP/autoenum/aggr_scan/raw; fi
        if [[ ! -d "$IP/autoenum/aggr_scan/ports_and_services" ]];then  mkdir -p $IP/autoenum/aggr_scan/ports_and_services; fi
	tput setaf 6;echo "Checking top 1k ports...";tput sgr0
	nmap --top-ports 1000 -sV $IP | tee -a $IP/autoenum/aggr_scan/top_1k
        tput setaf 6;echo -e "Scan complete. View 1k scan at $IP/autoenum/aggr_scan/top_1k\nStarting more comprehensive scan...";tput sgr0
        nmap -sV $IP -oX $IP/autoenum/aggr_scan/raw/xml_out & $nmap_aggr | tee $IP/autoenum/aggr_scan/raw/full_scan;searchsploit -j --nmap $IP/autoenum/aggr_scan/raw/xml_out >> $loot/exploits/aggr_searchsploit_nmap
        searchsploit --nmap $IP/autoenum/aggr_scan/raw/xml_out
        cat $loot/exploits/aggr_searchsploit_nmap | jq >> $loot/exploits/aggr_searchsploit_nmap.json;rm $loot/exploits/aggr_searchsploit_nmap

        cat $IP/autoenum/aggr_scan/raw/full_scan | grep "open" | awk -F 'Discovered' '{print $1}' | sed '/^$/d' | sed '/|/,+1 d' >> $IP/autoenum/aggr_scan/ports_and_services/services_running
        cat $IP/autoenum/aggr_scan/raw/full_scan | grep 'OS' | sed '1d' | sed '$d' | cut -d '|' -f 1 | sed '/^$/d' >> $IP/autoenum/aggr_scan/ports_and_services/OS_detection
        cat $IP/autoenum/aggr_scan/raw/full_scan | sed -n '/PORT/,/exact/p' | sed '$d' >>  $IP/autoenum/aggr_scan/ports_and_services/script_output

        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1 ;done > $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smb" > $loot/raw/smb_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "snmp" > $loot/raw/snmp_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "imap" > $loot/raw/imap_found
        cat $IP/autoenum/aggr_scan/ports_and_services/services_running | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

top_1k (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/top_1k/raw" ]];then mkdir -p $IP/autoenum/top_1k/raw; fi
        if [[ ! -d "$IP/autoenum/top_1k/ports_and_services" ]];then  mkdir -p $IP/autoenum/top_1k/ports_and_services; fi
	t1k="$IP/autoenum/top_1k"
	nmap --top-ports 1000 -sV -Pn $IP | tee -a $t1k/ports_and_services/services & nmap --top-ports 1000 -sC -Pn $IP >> $t1k/ports_and_services/scripts
	nmap --top-ports 1000 -sV $IP -oX $t1k/raw/xml_out &
	wait
	searchsploit -j --nmap $t1k/raw/xml_out >> $loot/exploits/top_1k_searchsploit_nmap;searchsploit --nmap $t1k/raw/xml_out
        cat $loot/exploits/top_1k_searchsploit_nmap | jq >> $loot/exploits/top_1k_searchsploit_nmap.json

        cat $t1k/ports_and_services/services | grep "open" |grep "http" | sort -u >> $IP/autoenum/loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f 1;done >  $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $t1k/ports_and_services/services | sort -u | grep "smb" > $loot/raw/smb_found
        cat $t1k/ports_and_services/services | sort -u | grep "snmp" > $loot/raw/snmp_found
        cat $t1k/ports_and_services/services | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $t1k/ports_and_services/services | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $t1k/ports_and_services/services | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $t1k/ports_and_services/services | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $t1k/ports_and_services/services | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $t1k/ports_and_services/services | sort -u | grep "imap" > $loot/raw/imap_found
        cat $t1k/ports_and_services/services | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

top_10k (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/top_10k/raw" ]];then mkdir -p $IP/autoenum/top_10k/raw; fi
        if [[ ! -d "$IP/autoenum/top_10k/ports_and_services" ]];then  mkdir -p $IP/autoenum/top_10k/ports_and_services; fi
	t10k="$IP/autoenum/top_10k"
	nmap --top-ports 10000 -sV -Pn --max-retries 1 $IP | tee -a $t10k/raw/services & nmap --top-ports 10000 --max-retries 1 -sC -Pn $IP >> $t10k/raw/scripts
	nmap --top-ports 10000 ---max-retries 1 sV $IP -oX $t10k/raw/xml_out &
	wait
	searchsploit -j --nmap $t10k/raw/xml_out >> $loot/exploits/top_10k_searchsploit_nmap;searchsploit --nmap $t10k/raw/xml_out
        cat $loot/exploits/top_10k_searchsploit_nmap | jq >> $loot/exploits/top_10k_searchsploit_nmap.json
	cat $t10k/raw/services | grep 'open' >> $t10k/ports_and_services/services

        cat $t10k/ports_and_services/services | grep "http" | sort -u >> $loot/raw/http_found.tmp
        for line in $(cat $loot/raw/http_found.tmp | tr ' ' '-');do echo $line | cut -d '/' -f1;done > $loot/raw/http_found;rm $loot/raw/http_found.tmp
        cat $t10k/ports_and_services/services | sort -u | grep "smb" > $loot/raw/smb_found
        cat $t10k/ports_and_services/services | sort -u | grep "snmp" > $loot/raw/snmp_found
        cat $t10k/ports_and_services/services_running | sort -u | grep "dns" > $loot/raw/dns_found
        cat $t10k/ports_and_services/services | sort -u | grep "ftp" > $loot/raw/ftp_found
        cat $t10k/ports_and_services/services | sort -u | grep "ldap" > $loot/raw/ldap_found
        cat $t10k/ports_and_services/services | sort -u | grep "smtp" > $loot/raw/smtp_found
        cat $t10k/ports_and_services/services | sort -u | grep "oracle" > $loot/raw/oracle_found
        cat $t10k/ports_and_services/services | sort -u | grep "pop3" > $loot/raw/pop3_found
        cat $t10k/ports_and_services/services | sort -u | grep "imap" > $loot/raw/imap_found
        cat $t10k/ports_and_services/services_running | sort -u | grep "rpc" > $loot/raw/rpc_found
        cat $t10k/ports_and_services/services | sort -u | grep "redis" > $loot/raw/redis_found

	enum_goto
}

udp (){
	banner
	upgrade
	OS_guess
        if [[ ! -d "$IP/autoenum/udp/raw" ]];then mkdir -p $IP/autoenum/udp/raw; fi
        if [[ ! -d "$IP/autoenum/udp/ports_and_services" ]];then  mkdir -p $IP/autoenum/udp/ports_and_services; fi
        udp="$IP/autoenum/udp"
	nmap -sU --max-retries 1 --open $IP | tee -a $udp/scan

}

vuln (){
        mkdir -p $loot/exploits/vulns
        vulns="$loot/exploits/vulns"
        cwd=$(pwd)

        if [[ ! -d "/usr/share/nmap/scripts/vulscan" ]];then
                cd
                git clone https://github.com/scipag/vulscan scipag_vulscan
                ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan
                cd $cwd
        fi

        nmap -sV --script=vulscan/vulscan.nse $IP | tee -a $vulns/vulscan
        nmap -Pn --script vuln $IP | tee -a $vulns/vuln
}


# source $dir/functions/enum.sh
redis_enum (){
        mkdir $loot/redis
	tput setaf 2;echo "[+] Starting redis enum";tput sgr0
        nmap --script redis-info -sV -p 6379 $IP | tee -a $loot/redis/redis_info
        echo "msf> use auxiliary/scanner/redis/redis_server" >> $loot/redis/manual_cmds
}

snmp_enum (){
        mkdir $loot/snmp
	tput setaf 2;echo "[+] Starting snmp enum";tput sgr0
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP | tee -a $loot/snmp/snmpenum
        snmp-check -c public -v 1 -d $IP | tee -a $loot/snmp/snmpcheck
        if grep -q "SNMP request timeout" "$loot/snmp/snmpcheck";then
                rm $loot/snmp/snmpcheck
                snmpwalk -c public -v2c $IP | tee -a $loot/snmp/uderstuff
                echo "snmpwalk -c public -v2c $IP" >> $loot/snmp/cmds_run &
                if grep -q "timeout" "$loot/snmp/uderstuff";then rm $loot/snmp/uderstuff;else mv $loot/snmp/uderstuff $loot/snmp/snmpenum;fi
        else
                mv $loot/snmp/snmpcheck $loot/snmp/snmpenum
        fi
        echo "onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $IP" >> $loot/snmp/cmds_run &
        echo "snmp-check -c public $IP" >> $loot/snmp/cmds_run &
        wait
        rm $IP/autoenum/loot/raw/snmp_found
}

rpc_enum (){
        mkdir $loot/rpc
	tput setaf 2;echo "[+] Starting rpc enum";tput sgr0
        port=$(cat $loot/raw/rpc_found | grep "rpc" | awk '{print($1)}' | cut -d '/' -f 1)
        nmap -sV -p $port --script=rpcinfo >> $loot/rpc/ports
        if grep -q "" "$loot/rpc/ports";then rm $loot/rpc/ports;fi
        rpcbind -p $IP | tee -a $loot/rpc/versions
        if grep -q "nfs" "$loot/rpc/ports";then nfs_enum;fi
        rm $loot/raw/rpc_found
}

nfs_enum (){
        mkdir $loot/nfs
	tput setaf 2;echo "[+] Starting nfs enum";tput sgr0
        nmap -p 111 --script nfs* $IP | tee $loot/nfs/scripts
        # add chunk to automount if share is found
        share=$(cat $loot/nfs/scripts | grep "|_ " -m 1 | awk '{print($2)}')
        if grep -q "mfs-showmount" "$loot/nfs/scripts";then
                mkdir $loots/nfs/mount
                # pull share location and assign it to share var
                mount -o nolock $IP:$share $loot/nfs/mount
        fi
}

pop3_enum (){
        mkdir $loot/pop3
	tput setaf 2;echo "[+] Starting pop3 enum";tput sgr0
        nmap -sV --script pop3-brute $IP | tee -a $loot/pop3/brute
        echo "telnet $IP 110" >> $loot/pop3/manual_cmds
        rm $loot/raw/pop3_found
}

imap_enum (){
        echo "[+] Work in progress"
}

ldap_enum (){
        mkdir $loot/ldap
	tput setaf 2;echo "[+] Starting ldap enum";tput sgr0
        nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP | tee -a $loot/ldap/ldap_scripts
        #ldapsearch -x -h $rhost -s base namingcontexts | tee -a $loot/ldap/ldapsearch &
        echo "nmap -vv -Pn -sV -p 389 --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' $IP" >> $loot/ldap/cmds_run &
        wait
        rm $loot/raw/ldap_found
}

dns_enum (){
        mkdir $loot/dns
        # mainly for pentesting use, not neccesary rn for oscp. retest later when adding to this
        #host $IP >> $loot/dns/host_out
        #host -t mx $IP >> $loot/dns/host_out
        #host -t txt $IP >> $loot/dns/host_out
        #host -t ns $IP >> $loot/dns/host_out
        #host -t ptr $IP >> $loot/dns/host_out
        #host -t cname $IP >> $loot/dns/host_out
        #host -t a $IP >> $loot/dns/host_out
        #for host in <list of subs>;do host -l <host> <dns server addr>;done
        #fierce -dns $IP
        #dnsenum --enum $IP
        #dnsrecon -d $IP
        #gobuster -dns $IP

        echo " "
}

ftp_enum (){
        mkdir -p $loot/ftp
        echo "[+] Starting FTP enum..."
        cat $loot/raw/ftp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/ftp/port_list
        for port in $(cat $loot/ftp/port_list);do
                nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP | tee -a $loot/ftp/ftp_scripts
        done
        echo "nmap -sV -Pn -p $port --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,ftp-syst -v $IP " >> $loot/ftp/cmds_run &
        wait
        rm $loot/ftp/port_list
        rm $loot/raw/ftp_found
        echo "[+] FTP enum complete"
}

smtp_enum (){
        mkdir $loot/smtp
	echo "[+] Starting SNMP enum..."
        cat $loot/raw/snmp_found | awk '{print($1)}' | cut -d '/' -f 1 > $loot/smtp/port_list
        for port in $(cat $loot/smtp/port_list);do
                smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port | tee -a $loot/smtp/users
        done
        if grep -q "0 results" "$loot/smtp/users";then rm $loot/smtp/users;fi
        echo "nc -nvv $IP $port" >> $loot/smtp/maunal_cmds
        echo "telnet $IP $port" >> $loot/smpt/manual_cmds
        echo "smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $IP -p $port" >> $loot/smtp/cmds_run &
        wait
        rm $loot/smtp/port_list
        rm $loot/raw/smtp_found
}

oracle_enum (){
        mkdir $loot/oracle
	echo "[+] Starting Oracle enum..."
        #swap out port with port(s) found running oracle
        nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse | tee -a $loot/oracle/nmapstuff
        oscanner -v -s $IP -P 1521 | tee -a $loot/oracle/
        echo "[+] Running ODAT..."
        odat tnscmd -s $rhost --version --status --ping 2>/dev/null | tee -a $loot/oracle/odat_tnscmd
        odat sidguesser -s $rhost 2>/dev/null | tee -a $loot/oracle/odat_enum
        rm $loot/raw/oracle_found
}

http_enum (){
        mkdir -p $IP/autoenum/loot/http
        echo "[+] http enum starting..."
	pct=$(cat $loot/raw/http_found | wc -l)
	if [[ $pct -gt 1 ]];then
		echo "[+] Multiple HTTP ports detected"
                for port in $(cat $loot/raw/http_found);do
			mkdir $loot/http/$port
                        echo "[+] Firing up nikto on port $port"
                        nikto -ask=no -h $IP:$port -T 123b | tee -a  $loot/http/$port/nitko
	                echo "[+] checking ssl for possible holes on port $port"
			sslscan --show-certificate $IP:$port | tee -a $loot/http/$port/sslinfo &
			echo "[+] Curling interesting files on port $port"
			curl -sSiK $IP:$port/index.html | tee -a $loot/http/$port/landingpage &
			curl -sSik $IP:$port/robots.txt | tee -a $loot/http/$port/robots.txt &
			echo -e "\n[+] Pulling headers/plugin info with whatweb on port $port"
			whatweb -a3 $IP:$port 2>/dev/null | tee -a $loot/http/$port/whatweb &
			wait
                        echo "[+] bruteforcing dirs on $IP:$port"
                        gobuster dir -re -t 65 -u http://$IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $loot/http/$port/dirs_found -k
                done
        elif [[ $pct == 1 ]];then
		port=$(cat $loot/raw/http_found)
                echo "[+] firing up nikto"
                nikto -ask=no -h $IP:$port >> $loot/http/nikto_out &
		#echo "[+] Running unican in background"
                #uniscan -u http://$IP -bqweds >> $loot/http/uniscan
                echo "[+] checking ssl for possible holes"
                sslscan --show-certificate $IP:$port | tee -a $loot/http/sslinfo
		echo "[+] Pulling headers/plugin info with whatweb"
		whatweb -a3 $IP:$port 2>/dev/null | tee -a $loot/http/whatweb
                echo "[+] Curling interesting files"
                curl -sSiK $IP:$port/index.html | tee -a $loot/http/landingpage &
                curl -sSik $IP:$port/robots.txt | tee -a $loot/http/robots.txt &
		wait
                echo "[+] bruteforcing dirs on $IP"
                gobuster dir -re -t 65 -u $IP:$port -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o $loot/http/dirs_found -k

        fi
                touch $loot/http/cmds_run
                echo "uniscan -u http://$IP -qweds" >> $loot/http/cmds_run &
                echo "sslscan --show-certificate $IP:80 " >> $loot/http/cmds_run &
                echo "nikto -h $IP" >> $loot/http/cmds_run &
                echo "gobuster dir -re -t 45 -u $IP -w /usr/share/wordlists/dirb/common.txt" >> $loot/http/cmds_run &
                echo "curl -sSiK $IP" >> $loot/http/cmds_run &
                echo "curl -sSiK $IP/robots.txt" >> $loot/http/cmds_run &
                echo "whatweb -v -a 3 $IP" >> $loot/http/cmds_run &
                wait
                echo "[+] http enum complete!"
}

smb_enum (){
        echo "[+] Starting SMB enum..."
        mkdir -p $loot/smb
        mkdir -p $loot/smb/shares
        # checks for eternal blue and other common smb vulns
        nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP | tee -a $loot/smb/eternalblue
        if ! grep -q "smb-vuln-ms17-010:" "auotenum/loot/smb/eternalblue";then rm $loot/smb/eternalblue;fi
        nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP | tee -a $loot/smb/08-067
        if ! grep -q "smb-vuln-ms08-067:" "autoenum/loot/smb/08-067";then rm $loot/smb/08-067;fi
        nmap --script smb-vuln* -p 139,445 $IP | tee -a $loot/smb/gen_vulns
        #shares n' stuff
        nmap --script smb-enum-shares -p 139,445 $IP | tee -a $loot/smb/shares/nmap_shares
        smbmap -H $IP -R | tee -a $loot/smb/shares/smbmap_out
        smbclient -N -L \\\\$IP | tee -a $loot/smb/shares/smbclient_out
        if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then smbclient -N -H \\\\\\$IP | tee -a $loot/smb/shares/smbclient_out;fi
        if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then smbclient -N -H \\$IP | tee -a $loot/smb/shares/smbclient_out;fi
        if grep -q "Not enough '\' characters in service" "$loot/smb/shares/smbclient_out";then rm $loot/smb/shares/smbclient_out; echo "smbclient could not be auotmatically run, rerun smbclient -N -H [IP] manauly" >> $loot/smb/notes;fi
        if grep -q "Error NT_STATUS_UNSUCCESSFUL" "$loot/smb/shares/smbclient_out";then rm $loot/smb/shares/smbclient;fi
        if [[ -s "$loot/smb/shares/smbclient_out" ]];then echo "smb shares open to null login, use rpcclient -U '' -N [ip] to run rpc commands, use smbmap -u null -p '' -H $IP -R to verify this" >> $loot/smb/notes;fi
        find ~ -path '*/$IP/autoenum/loot/smb/*' -type f > $loot/smb/files
        for file in $(cat $loot/smb/files);do
                if grep -q "QUITTING!" "$file" || grep -q "ERROR: Script execution failed" "$file" || grep "segmentation fault" "$file";then rm $file;fi
        done
        touch $loot/smb/cmds_run
        echo "nmap --script smb-vuln-ms17-010.nse --script-args=unsafe=1 -p 139,445 $IP " >> $loot/smb/cmds_run &
        echo "nmap --script smb-vuln-ms08-067.nse --script-args=unsafe=1 -p 445 $IP" >> $loot/smb/cmds_run &
        echo "nmap --script smb-vuln* -p 139,445 $IP" >> $loot/smb/cmds_run &
        echo "nmap --script smb-enum-shares -p 139,445 $IP" >> $loot/smb/cmds_run &
        echo "smbmap -H $IP -R " >> $loot/smb/cmds_run &
        echo "smbclient -N -L \\\\$IP " >> $loot/smb/cmds_run &
        wait
        rm $loot/smb/files
        rm $loot/raw/smb_found
        echo "[+] SMB enum complete!"
}

linux_enum (){
        #get exact snmp version
        echo "[-] Work in Progress"
}

windows_enum (){
        # get exact snmp version
        # pull entire MIB into sections
        echo "[-] Work in Progress"
}

# source $dir/functions/sumrecon.sh
recon (){
        if [ ! $URL ];then
                echo "[-] $IP has no found domain name to recon for..."
                return
        fi

        if [ ! -d "$recon/3rd-lvls" ];then
                mkdir $recon/3rd-lvls
        fi
        if [ ! -d "$recon/httprobe" ];then
                mkdir $recon/httprobe
        fi
        if [ ! -d "$recon/potential_takeovers" ];then
                mkdir $recon/potential_takeovers
        fi
        if [ ! -d "$recon/wayback" ];then
                mkdir $recon/wayback
        fi
        if [ ! -d "$recon/wayback/params" ];then
                mkdir $recon/wayback/params
        fi
        if [ ! -d "$recon/wayback/extensions" ];then
                mkdir $recon/wayback/extensions
        fi
        if [ ! -d "$recon/domains" ];then
                mkdir $recon/domains
        fi
        if [ ! -f "$recon/httprobe/alive.txt" ];then
                touch $recon/httprobe/alive.txt
        fi
        if [ ! -f "$recon/final.txt" ];then
                touch $recon/final.txt
        fi
        if [ ! -f "$recon/3rd-lvl-domains.txt" ];then
                touch $recon/3rd-lvl-domains.txt
        fi
        
        echo "[+] Harvesting subdomains with assetfinder..."
        assetfinder $URL | grep ".$URL" | sort -u | tee -a $recon/final1.txt
        
        echo "[+] Double checking for subdomains with amass and certspotter... This might take a while..."
        amass enum -d $URL | awk '{print($1)}' | grep ".$URL" | tee -a $recon/final1.txt
        certspotter -watchlist $recon/final1.txt -stdout | tee -a $recon/certs.txt
        cat $recon/certs.txt | grep "DNS Name =" | awk '{print($4)}' | sort -u | tee -a $recon/final1.txt
        sort -u $recon/final1.txt >> $recon/final.txt
        rm $recon/final1.txt
        
        echo "[+] Compiling 3rd lvl domains..."
        cat ~/$recon/final.txt | grep -Po '(\w+\.\w+\.\w+)$' | sort -u >> ~/$recon/3rd-lvl-domains.txt
        #write in line to recursively run thru final.txt
        for line in $(cat $recon/3rd-lvl-domains.txt);do echo $line | sort -u | tee -a $recon/final.txt;done
        
        echo "[+] Harvesting full 3rd lvl domains with sublist3r..."
        for domain in $(cat $recon/3rd-lvl-domains.txt);do sublist3r -d $domain -o $recon/3rd-lvls/$domain.txt;done

        echo "[+] Probing for alive domains..."
        cat $recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> $recon/httprobe/alive.txt
        sort -u $
        echo "[+] Checking for possible subdomain takeover..."
        if [ ! -f "$recon/potential_takeovers/domains.txt" ];then
                touch $recon/potential_takeovers/domains.txt
        fi
        if [ ! -f "$recon/potential_takeovers/potential_takeovers1.txt" ];then
                touch $recon/potential_takeovers/potential_takeovers1.txt
        fi
        for line in $(cat ~/$recon/final.txt);do echo $line |sort -u >> ~/$recon/potential_takeovers/domains.txt;done
        subjack -w $recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> $recon/potential_takeovers/potential_takeovers1.txt
        sort -u $recon/potential_takeovers/potential_takeovers1.txt >> $recon/potential_takeovers/potential_takeovers.txt
        rm $recon/potential_takeovers/potential_takeovers1.txt
        
        echo "[+] Running a dig, whatweb and gowitness on compiled domains..."
        for domain in $(cat ~/$recon/httprobe/alive.txt);do
                if [ ! -d  "$recon/domains/$domain" ];then
                mkdir $recon/domains/$domain
                fi
                if [ ! -d "$recon/domains/$domain/output.txt" ];then
                touch $recon/domains/$domain/output.txt
                fi
                if [ ! -d "$recon/whaweb/$domain/plugins.txt" ];then
                touch $recon/domains/$domain/plugins.txt
                fi
                if [ ! -d "$recon/domains/$domain/dig.txt" ];then
                touch $recon/domains/$domain/dig.txt
                fi
                tput setaf 4;echo "[*] Digging DNS data from 8.8.8.8 on $domain $(date +'%Y-%m-%d %T') ";tput sgr0
                dig @8.8.8.8 $domain any > $recon/domains/$domain/dig.txt
                tput setaf 4;echo "[*] Pulling plugins data on $domain $(date +'%Y-%m-%d %T') ";tput sgr0
                whatweb --info-plugins -t 50 -v $domain >> $recon/domains/$domain/plugins.txt; sleep 3
                tput setaf 4;echo "[*] Running whatweb on $domain $(date +'%Y-%m-%d %T')";tput sgr0
                whatweb -t 50 -v $domain >> $recon/domains/$domain/output.txt; sleep 3
                tput setaf 4;echo "[*] Running gowitness on $domain $(date +'%Y-%m-%d %T')";tput sgr0
                gowitness single -o ~/$recon/domains/$domain/$(date +'%Y-%m-%d %T - gowitness') $domain
        done
        
        echo "[+] Scraping wayback data..."
        cat $recon/final.txt | waybackurls | tee -a  $recon/wayback/wayback_output1.txt
        sort -u $recon/wayback/wayback_output1.txt >> $recon/wayback/wayback_output.txt
        rm $recon/wayback/wayback_output1.txt
        
        echo "[+] Pulling and compiling all possible params found in wayback data..."
        cat $recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $recon/wayback/params/wayback_params.txt
        for line in $(cat $recon/wayback/params/wayback_params.txt);do echo $line'=';done
        
        echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output..."
        for line in $(cat $recon/wayback/wayback_output.txt);do
                ext="${line##*.}"
                if [[ "$ext" == "js" ]];then
                echo $line | sort -u | tee -a  $recon/wayback/extensions/js.txt
                fi
                if [[ "$ext" == "html" ]];then
                echo $line | sort -u | tee -a $recon/wayback/extensions/jsp.txt
                fi
                if [[ "$ext" == "json" ]];then
                echo $line | sort -u | tee -a $recon/wayback/extensions/json.txt
                fi
                if [[ "$ext" == "php" ]];then
                echo $line | sort -u | tee -a $recon/wayback/extensions/php.txt
                fi
                if [[ "$ext" == "aspx" ]];then
                echo $line | sort -u | tee -a $recon/wayback/extensions/aspx.txt
                fi
        done
} 

# source $dir/functions/help_general.
cleanup (){
        echo "[+] Cleaning up..."
        find $IP/autoenum/ -type d -empty -delete
        find $IP/autoenum/ -type f -empty -delete
        if [[ -f "installed" ]];then rm installed;fi
}

get_ip (){
        echo -e
        echo "Enter a target IP or hostname "
        tput bold;tput setaf 1; echo -en "Autoenum > ";tput sgr0;read unchecked_IP
        if [ $nr ];then
                if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then
                        IP="$unchecked_IP";sleep 1
                        tput setaf 4;echo -e "[+] IP set to $IP";tput sgr0;echo -e
                fi
        else
                if [[ $unchecked_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]];then
                        IP="$unchecked_IP";sleep 1
                        tput setaf 4;echo -e "[+] IP set to $IP";tput sgr0
                        if [[ $(resolveip $unchecked_IP | head -n1 | awk '{print($1)}') != "resolveip" ]];then
                                URL=$(resolveip $unchecked_IP | head -n1 | awk '{print($6)}')
                                URL=${URL::-1}
                                tput setaf 4;echo -e "[+] Reverse dns found $URL";tput sgr0;echo -e
                        else
                                URL=0
                                tput setaf 3;echo -e "[-] Reverse dns didn't find any URL using $IP ; recon cannot be used";tput sgr0;echo -e
                        fi
                        cwd=$(pwd);ping -c 1 -W 3 $IP | head -n2 | tail -n1 > $cwd/tmp
                        if ! grep -q "64 bytes" "tmp";then
                                echo -e "[-] IP failed to resolve\n[-] Exiting..."
                                exit
                        fi
                        rm $cwd/tmp
                elif [[ $unchecked_IP =~ [a-z,A-Z,0-9].[a-z]$ ]] || [[ $unchecked_IP =~ [a-z].[a-z,A-Z,0-9].[a-z]$ ]];then
                        URL="$unchecked_IP"
                        IP=$(resolveip $unchecked_IP | head -n1 | awk '{print($6)}')
                        tput setaf 4;echo -e "[+] $unchecked_IP resolved to $IP\n";tput sgr0
                else
                        tput setaf 8
                        echo "[-] Invalid IP or hostname detected."
                        echo -e "[-] Example:\n\t[>] 192.168.1.5\n\t[>] google.com"
                        tput sgr0
                        get_ip
                fi
        fi
}

shell_preserve (){
        echo "[+] You have entered shell mode. use done to exit"
        while true ;do
                echo -en "[+] Command > ";read cmd
                if [[ "$cmd" =~ "done" ]];then
                        $cmd  2>/dev/null;echo -e
                        break
		elif [[ "$cmd" =~ "exit" ]];then
			echo -en "[-] Exit shell mode? [y/n] > ";read opt
			if [[ "$opt" == "y" ]];then
				echo -e "[-] Exiting shell mode\n"
				break
			fi
                else
                        $cmd 2>/dev/null
                fi
        done
}

halp_meh (){
        tput smul;echo "General Commands:";tput rmul
        tput setaf 4;echo "[*] ping";tput sgr0
        tput setaf 4;echo "[*] help";tput sgr0
        tput setaf 4;echo "[*] banner";tput sgr0
        tput setaf 4;echo "[*] clear";tput sgr0
        tput setaf 4;echo "[*] reset";tput sgr0
        tput setaf 4;echo "[*] commands";tput sgr0
        tput setaf 4;echo "[*] shell";tput sgr0
        tput setaf 4;echo "[*] upgrade";tput sgr0
        tput setaf 4;echo "[*] set target";tput sgr0
        tput setaf 4;echo "[*] exit";tput sgr0
        echo -e
        tput smul;echo "Scan Profiles:";tput rmul
        tput setaf 6;echo -e "[~] Main:";tput sgr0
        tput setaf 4;echo "[*] recon";tput sgr0
        tput setaf 4;echo "[*] aggr";tput sgr0
        tput setaf 4;echo "[*] reg";tput sgr0
	tput setaf 4;echo "[*] top 1k";tput sgr0
	tput setaf 4;echo "[*] top 10k";tput sgr0
        tput setaf 4;echo "[*] aggr+vuln";tput sgr0
        tput setaf 4;echo "[*] reg+vuln";tput sgr0
	tput setaf 4;echo "[*] top 1k+vuln";tput sgr0
	tput setaf 4;echo "[*] top 10k+vuln";tput sgr0
	tput setaf 4;echo "[*] udp";tput sgr0
        echo -e
        tput setaf 6;echo -e "[~] Auxiliary:";tput sgr0
        tput setaf 4;echo "[*] vuln";tput sgr0
        tput setaf 4;echo "[*] quick";tput sgr0
	echo -e;sleep 0.5
}

halp_meh_pws (){
        tput smul;echo "General Commands:";tput rmul
        tput setaf 4;echo "[*] ping - Verify host is up/accepting ping probes";tput sgr0
        tput setaf 4;echo "[*] help - displays this page";tput sgr0
        tput setaf 4;echo "[*] banner - display banner";tput sgr0
        tput setaf 4;echo "[*] clear - clears screen";tput sgr0
        tput setaf 4;echo "[*] reset - run this if text is unviewable after a scan";tput sgr0
        tput setaf 4;echo "[*] commands - shows all avaliable commands";tput sgr0
        tput setaf 4;echo "[*] shell - allows you to run commands as if in a terminal";tput sgr0
        tput setaf 4;echo "[*] upgrade - checks to see if any dependencies require an update";tput sgr0
        tput setaf 4;echo "[*] set target - opens prompt to change target IP";tput sgr0
        echo -e
        tput smul;echo "Scan Profiles:";tput rmul
        tput setaf 6;echo "[~] Main - These scans are 'the works', enumerate further depending on services discovered ";tput sgr0
        tput setaf 4;echo "[*] recon - do recon with minimal interactions";tput sgr0
        tput setaf 4;echo "[*] aggr - scans all ports aggressively";tput sgr0
        tput setaf 4;echo "[*] reg - scans all ports normally, no scripts and checks only for OS";tput sgr0
	tput setaf 4;echo "[*] top 1k - run a number of scans on the first 1000 ports";tput sgr0
	tput setaf 4;echo "[*] top 10k - runs a number of scans on the first 10000 ports";tput sgr0
        tput setaf 4;echo "[*] aggr+vuln - aggr scan. Also fires off NSE on discovered services searching for known exploits";tput sgr0
        tput setaf 4;echo "[*] reg+vuln - reg scan. Also firing off NSE on discovered services searching for known exploits";tput sgr0
	tput setaf 4;echo "[*] top 1k+vuln - runs the top 1k scans and vuln scan";tput sgr0
	tput setaf 4;echo "[*] top 10k+vuln - runs the top 10k scans and vuln scan";tput sgr0
	tput setaf 4;echo "[*] udp - checks for udp ports";tput sgr0
        echo -e
        tput setaf 6;echo "[~] Auxiliary - These scans can be run standalone, do not enumerate beyond";tput sgr0
        tput setaf 4;echo "[*] quick - scans with scripts enabled for quick script enumeration";tput sgr0
        tput setaf 4;echo "[*] vuln - searches for services and checks for known exploits";tput sgr0
        echo -e;sleep 0.5
}

# source $dir/functions/menu.sh
menu (){

WHITE='\033[01;37m'
CLEAR='\033[0m'
# https://medium.com/bugbountywriteup/fasten-your-recon-process-using-shell-scripting-359800905d2a

if [[  "$module" == "" ]];then
        cli="Autoenum($IP) > "
fi

tput bold;tput setaf 1;echo -en "$cli";tput sgr0;read arg
while true && [[ ! "$IP" == " " ]];do
                # add more color
                # add more banners (?)...grimmie want more banners :(

        mkbasedirs (){
        echo "[+] Checking for base dirs..."
        if [[ ! -d "$IP/autoenum" ]];then mkdir -p $IP/autoenum;fi
        if [[ ! -d "$IP/autoenum/recon" ]];then mkdir -p $IP/autoenum/recon;fi;recon="$IP/autoenum/recon"
        if [[ ! -d "$IP/autoenum/loot/raw" ]];then mkdir -p $IP/autoenum/loot/raw; loot="$IP/autoenum/loot";else loot="$IP/autoenum/loot";fi
        if [[ ! -d "$loot/exploits" ]];then mkdir -p $loot/exploits;fi
        echo "[+] Done!"
        }
        case $arg in
                "")
                        menu
                        break
                        ;;
                "home")
                        cli="Autoenum($IP) > "
                        menu
                        break
                        ;;
                "commands")
                        halp_meh
                        menu
                        break
                        ;;
                "shell")
                        shell_preserve
                        menu
                        break
                        ;;
                "reset")
                        reset
                        menu
                        break
                        ;;
                "upgrade")
                        upgrade
                        menu
                        break
                        ;;
                "clear")
                        clear
                        menu
                        break
                        ;;
                "banner")
                        banner
                        menu
                        break
                        ;;
                "ping")
			if [[ "$IP" == "dev" ]];then
				echo "[-] set an IP. use set target to do this"
			else
                        	ping $IP -c 1;echo -e
			fi
			menu
                        break
                        ;;
		"udp")
			tput setaf 6;echo "[~] SCAN MODE: udp";sleep 2;echo -e;tput sgr0
			mkbasedirs
			udp
			menu
			break
			;;
                "vuln")
                        tput setaf 6;echo "[~] SCAN MODE: vuln";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        vuln
                        menu
                        break
                        ;;
                "recon")
                        tput setaf 6;echo "[~] SCAN MODE: recon";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        recon
                        menu
                        break
                        ;;
                "aggr")
                        tput setaf 6;echo "[~] SCAN MODE: aggr";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        aggr
                        cleanup
                        menu
                        break
                        ;;
                "reg")
                        tput setaf 6;echo "[~] SCAN MODE: reg";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        reg
                        cleanup
                        menu
                        break
                        ;;
                "quick")
                        tput setaf 6;echo "[~] SCAN MODE: quick";sleep 2;echo -e;tput sgr0
                        nmap -sC -sV -T4 -Pn $IP
                        menu
                        break
                        ;;
		"top 1k" | "top1k")
			tput setaf 6;echo "[~] SCAN MODE: top 1k";sleep 2;echo -e;tput sgr0
			mkbasedirs
			top_1k
			cleanup
			menu
			break
			;;
		"top 10k" | "top10k")
			tput setaf 6;echo "[~] SCAN MODE: top 10k";sleep 2;echo -e;tput sgr0
			mkbasedirs
			top_10k
			cleanup
			menu
			break
			;;
		"top 1k+vuln" | "top1k+vuln")
			tput setaf 6;echo "[~] SCAN MODE: top 1k+vuln";sleep 2;echo -e;tput sgr0
			mkbasedirs
			top_1k
			vuln
			cleanup
			menu
			break
			;;
		"top 10k+vuln" | "top10k+vuln")
			tput setaf 6;echo "[~] SCAN MODE: top 10k+vuln";sleep 2;echo -e;tput sgr0
			mkbasedirs
			top_10k
			vuln
			cleanup
			menu
			break
			;;
                "aggr+vuln")
                        tput setaf 6;echo "[~] SCAN MODE: aggr+vuln";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        aggr
                        vuln
                        cleanup
                        menu
                        break
                        ;;
                "reg+vuln")
                        tput setaf 6;echo "[~] SCAN MODE: reg+vuln";sleep 2;echo -e;tput sgr0
                        mkbasedirs
                        reg
                        vuln
                        cleanup
                        menu
                        break
                        ;;
                "help")
                        halp_meh_pws
                        menu
                        break
                        ;;
                "set target")
                        get_ip
                        menu
                        break
                        ;;

                "exit")
                        tput setaf 8;echo "[-] Terminating session..."
                        tput sgr0
                        sleep 1.5
			exit 1
                        ;;
                *)
                        tput setaf 8;echo "[-] Invalid input detected"
                        tput sgr0
                        menu
                        break
                        ;;
        esac
done
}

if [[ $1 == '--first' ]];then
        echo -e "[+] autoenum dependencies installed"
        exit 1
fi

if [[ $1 == '-nr' ]];then nr=1;fi
clear
banner
if [ $nr ];then tput setaf 2;echo -en "\n[*] autoenum set to noresolve mode";tput sgr0;sleep 0.5;fi
get_ip
halp_meh
menu

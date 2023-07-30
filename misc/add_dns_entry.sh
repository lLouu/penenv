if [[ $1 == '-h' ]];then
        echo -e "add_dns_entry <ip> <domain>  -  this command will add dns and reverse dns entries to /etc/hosts"
        exit 1
fi

IP=$1
HOST=$2

if [[ ! $IP || ! $HOST ]];then
        echo -e "[-] Wrong synthaxe used : add_dns_entry <ip> <domain>... Exiting"
        exit 1
fi

if [[ ! $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "[-] $IP is not a valid IP address... Exiting"
        exit 1
fi

echo -e "[*] Adding $IP > $HOST to /etc/hosts"
printf "$IP\t$HOST" | sudo tee -a /etc/hosts;echo -e "";echo -e ""

RIP=$(echo $IP | awk -F. '{print $4"."$3"." $2"."$1}')

echo -e "[*] Adding $HOST > $RIP.in-addr.arpa to /etc/hosts"
printf "$HOST\t$RIP.in-addr.arpa" | sudo tee -a /etc/hosts;echo -e "";echo -e ""

echo -e "[+] Successfully added $IP as $HOST locally"

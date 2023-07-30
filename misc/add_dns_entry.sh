if [[ $1 == '-h' ]];then
        echo -e "add_dns_entry <ip> <domain>  -  this command will add dns and reverse dns entries to /etc/hosts"
        exit
fi

IP=$1
HOST=$2

if [[ ! IP || ! HOST ]];then
        echo -e "[-] Wrong synthaxe used : add_dns_entry <ip> <domain>"
        exit
fi

if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo -e "[-] $IP is not a valid IP address"
fi

echo -e "[*] Adding $IP > $HOST to /etc/hosts"
printf "$IP\t$HOST" | sudo tee -a /etc/hosts

RIP=$(echo $IP | awk -F. '{print $4"."$3"." $2"."$1}')

echo -e "[*] Adding $HOST > $RIP.in-addr.arpa to /etc/hosts"
printf "$HOST\t$RIP.in-addr.arpa" | sudo tee -a /etc/hosts

echo -e "[+] Successfully added $IP as $HOST locally"

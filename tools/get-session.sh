#! /bin/bash

echo "    ____             ______          ";
echo "   / __ \___  ____  / ____/___ _   __";
echo "  / /_/ / _ \/ __ \/ __/ / __ \ | / /";
echo " / ____/  __/ / / / /___/ / / / |/ / ";
echo "/_/    \___/_/ /_/_____/_/ /_/|___/  ";
echo "                                     ";
echo ""
echo "Author : lLou_"
echo "Suite version : V0.3.0"
echo "Script version : V1.1"
echo ""
echo ""

session_dir=$(echo ~/.session)
if [[ ! -d $session_dir || ! "$(ls $session_dir)" ]];then echo "[-] No sessions are available... Exiting"; exit 1; fi

sessions=$(ls $session_dir | cut -d'.' -f1 | sort -u)
n=$(ls $session_dir | cut -d'.' -f1 | sort -u | wc -l)

escape_char=$(printf "\u1b")

choice=1
choosing="1"
output=-1

stop () {
   tput cnorm
   if [[ $output -ne -1 ]];then kill $output; fi
   echo ""
   echo "[!] User exited session"
   exit 1
}
trap stop INT

show_options () {
   echo "[~] Available options :"
   echo ""
   k=1
   for i in $sessions;do
      chr="-"
      if [[ $k -eq $choice ]];then chr=">";fi
      k=$((k+1))
      echo "[$chr] $i"
   done
}

tput civis

while [[ $choosing ]];do
   echo "$(tput cup 0 0)$(tput ed)$(show_options)"

   read -rsn1 c
   if [[ $c == $escape_char ]]; then
      read -rsn2 c
   fi
   case $c in
      '[A'|'z'|'w')
         if [[ $choice -gt 1 ]];then choice=$((choice - 1));fi
         ;;
      '[B'|'s')
         if [[ $choice -lt $n ]];then choice=$((choice + 1));fi
         ;;
      *) choosing="" ;;
   esac
done

tput cnorm

k=1
choice_name=""
for i in $sessions;do
   if [[ $k -eq $choice ]];then choice_name=$i;fi
   k=$((k+1))
done
echo ""
echo "[+] Loading $choice_name"
if [[ ! -f $session_dir/$choice_name.stdout ]];then echo "[!] No stdout is available for $choice_name session"
else
   echo ""
   tail -f -n+1 $session_dir/$choice_name.stdout &
   output=$!
fi
if [[ ! -f $session_dir/$choice_name.stdin ]];then echo "[!] No stdin is available for $choice_name session"; fi

cmd=""
while [[ "1" ]];do
   if [[ -f $session_dir/$choice_name.stdin ]];then
      read -N1 s
      if [[ $s == $escape_char ]]; then
         read -rsn2 c
         echo -ne "$s$c" >> $session_dir/$choice_name.stdin
      elif [[ $s == $'\n' ]]; then
         echo "$cmd" >> $session_dir/$choice_name.stdin
         cmd=""
      else
         cmd="$cmd$s"
      fi
   else
      sleep 1000
   fi
done
#! /bin/bash
echo "shscanner"
echo "Author : lLou_"
echo "---"

brute=""
range=10000
to=0.01

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      echo "shscanner [options]"
      echo ""
      echo "  -b  | --brute   : enable bruteforcing ip"
      echo "  -r  | --range   : edit port range (default 10000)"
      echo "  -to | --timeout : edit port timeout (default .01)"
      ;;
    -b|--brute|--bruteforce)
      brute="1"
      shift
      ;;
    -r|--range)
      if [[ $2 =~ \d+ ]];then echo "$2 is not a valid number... Exiting"; exit 1;fi
      range=$2
      shift
      shift
      ;;
    -to|--timeout)
      if [[ $2 =~ \d+ || $2 =~ \d+\.\d+ ]];then echo "$2 is not a valid number... Exiting"; exit 1;fi
      to=$2
      shift
      shift
      ;;
    -*|--*)
      tput setaf 1;echo "[-] Unknown option $1... Exiting";tput sgr0
      exit 1
      ;;
    *)
      ;;
  esac
done



homedir="$(echo ~)"
workingdir="$homedir/.shscanner"

mkdir $workingdir
if [[ ! -d "$workingdir" ]];then
   echo "[!] Failed to create a working directory at $workingdir ; trying to get a temporary folder"
   workingdir="${TMPDIR-/tmp}/.shscanner"
   mkdir $workingdir
   if [[ ! -d "$workingdir" ]];then
      echo "[-] Failed to create a working directory at $workingdir"
      exit
   fi
fi
chmod 700 $workingdir

echo "[+] Working dir created at $workingdir"

echo "[*] Getting ips from arp tables"
for ip in $(arp | tail -n+2 | awk '{print($1)}'); do
   touch $workingdir/$ip
done

if [[ $brute ]];then
   echo "[*] Getting ips from ping scan"

   int_to_ip() {
      buf=$1
      k=16777216

      a=$((buf/k))
      buf=$((buf-$((a*k))))
      k=65536

      b=$((buf/k))
      buf=$((buf-$((b*k))))
      k=256

      c=$((buf/k))
      buf=$((buf-$((c*k))))

      echo "$a.$b.$c.$buf"
   }

   pingscan() {
      ip=$((star+$1))
      k=$(ping -c 1 -W 1 $(int_to_ip $ip) | grep "bytes from" | cut -d ' ' -f4 | tr -d ':')
      if [[ $k ]];then
         touch $workingdir/$k
      fi
   }

   inets=$(ifconfig | grep 'inet ' | grep -v '127')
   n=$(echo "$inets" | wc -l)
   for i in $(seq 1 $n);do
      inet=$(echo "$inets" | tail -n+$i | head -n+$i)
      base="$(echo $inet | awk '{print($2)}')"
      mask="$(echo $inet | awk '{print($4)}')"
      IFS=. read -r a b c d <<< "$base"
      IFS=. read -r e f g h <<< "$mask"
      start=$(($((a & e)) * 256 ** 3 + $((b & f)) * 256 ** 2 + $((c & g)) * 256 + $((d & h))))
      range=$(($((255 - e)) * 256 ** 3 + $((255 - f)) * 256 ** 2 + $((255 - g)) * 256 + $((255 - h))))
      echo "[*] Scanning inet $(int_to_ip $start) for its $range addresses"
      for i in $(seq 1 $range); do
         pingscan $i &
      done
      sleep 1.1
   done
fi

echo "[~] Found a total of $(ls $workingdir | wc -l) ips"
echo ""
echo "[*] Scanning $range ports using tcp scanning"

for addr in $(ls $workingdir); do
   for i in $(req 1 $range); do
      timeout $to /bin/bash -c "</dev/tcp/$addr/$port" 2>/dev/null && echo $port >> $workingdir/$addr
   done
   echo "[+] Found $(cat $workingdir/$addr | wc -l) open ports at $addr"
done

echo ""
echo "[+] Scan ended... Data located in $workingdir"


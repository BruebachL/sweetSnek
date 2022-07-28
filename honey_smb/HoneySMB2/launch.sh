#!/bin/bash
echo "$PWD"
source honey_smb/HoneySMB2/bin/activate
cd honey_smb/HoneySMB2/ || exit
python2.7 smbserver.py
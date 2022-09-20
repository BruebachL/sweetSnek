#!/bin/bash
source honey_smb/HoneySMB2/env/bin/activate
cd honey_telnet/ || exit
python2.7 telnet_server.py -p 23 --high-interaction
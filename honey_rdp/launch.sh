#!/bin/bash
source honey_smb/HoneySMB2/env/bin/activate
cd honey_rdp/ || exit
python2.7 rdp_server.py -p 3389 --high-interaction
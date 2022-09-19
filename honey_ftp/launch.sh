#!/bin/bash
source env/bin/activate
cd honey_ftp/ || exit
python3.10 ftp_server.py
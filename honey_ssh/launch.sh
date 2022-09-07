#!/bin/bash
source env/bin/activate
cd honey_ssh/ || exit
python3.10 ssh_server.py -p 22 --high-interaction
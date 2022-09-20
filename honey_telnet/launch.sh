#!/bin/bash
source env2/bin/activate
cd honey_telnet/ || exit
python2.7 telnet_server.py -p 23 --high-interaction
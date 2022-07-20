
SweetSnek
===========

**A high interactive SMB and RDP Honeypot with Nmap OS Obfuscation**

*Author: Lukas Brübach lukas.bruebach@student.fhws.de*

Description: This software is intended to be run on a Linux Server. When deployed, it presents itself as the operating
system defined in template when scanned with Nmap. It also exposes emulated SMB and RDP protocols. Actions are logged and
forwarded to a central collection point.

Prerequisites:

- Linux (tested with Arch/Ubuntu 20.10)
- Python 3.10+
- python-nfqueue=0.6 (apt install python-nfqueue python-libnetfilter python3.10 python3.10-dev [possibly additional python3 packages]) 
- requirements.txt

Recorded logs are stored to `/root/sweetSnek/osfingerprinting/example.log`

Usage:

    python3.10 os_obfuscation.py
        --template path to the nmap fingerprint, either absolute or relative to the execution folder  the iptables to access over ssh. the ssh port should either be changed to 63712 or the port number in stack_packet/helper.py
        --public_ip either fetches the server public ip or gets the ip set for the interface 
        --interface the network interface
        --debug debugging output

**Note: This script flushes iptables before and after usage!**

# Installation

## Ubuntu

Ubuntu 20.04 does not ship with Python 3.10.
To install Python 3.10, first install the required dependency for adding custom PPAs.

    sudo apt install software-properties-common -y

Then add the deadsnakes PPA to the APT package manager sources list.

    sudo add-apt-repository ppa:deadsnakes/ppa

Now you may install python3.10 (note that all calls WILL be to 'python3.10 OPTIONS' not 'python3 OPTIONS')

    sudo apt install python3.10

## Arch

Python 3.10 is available in the official arch repo and aliased as 'python3'. Lucky us.

    sudo pacman -S python310

SweetSnek
===========

**A high interactive FTP, SSH, Telnet, HTTP, SMB, and RDP Honeypot with Nmap OS Obfuscation**

*Author: Lukas Brübach lukas.bruebach@student.fhws.de*

Description: This software is intended to be run on a Linux Server. When deployed, it presents itself as the operating
system defined in template when scanned with Nmap. It also exposes FTP, SSH, Telnet, HTTP, emulated SMB (with DCERPC support) and RDP protocols. Actions are logged and
forwarded to a central collection point.

Prerequisites:

- Linux (tested with Arch/Ubuntu 20.10)
- Python 3.10+
- python-nfqueue=0.6 (apt install python-nfqueue python-libnetfilter python3.10 python3.10-dev python3.10-venv [possibly additional python3 packages]) 
- requirements.txt

Recorded logs are stored to `/root/sweetSnek/osfingerprinting/example.log`

NMap Scan output:

    Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-21 22:22 CEST
    Nmap scan report
    Host is up (0.091s latency).
    Not shown: 994 closed tcp ports (conn-refused)
    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    23/tcp   open  telnet
    80/tcp   open  http
    445/tcp  open  microsoft-ds
    3389/tcp open  ms-wbt-server

    Nmap done: 1 IP address (1 host up) scanned in 2.53 seconds

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

## Virtual Environment

You are strongly encouraged to create a virtual environment for this project. To do so, type:

    python3.10 -m venv env

afterwards activate the environment with

    source env/bin/activate

This ensures a clean slate for dependency management through the pip package manager.

## Installing Python Module dependencies with pip

Navigate to the project root (/root/sweetSnek/) and issue

    python3.10 -m pip install -e .

This should install any required dependencies listed in requirements.txt and setup.py (the requirements listed in both should be identical).
This is required for each fresh virtual environment. In most cases, only one virtual environment needs to be created.

## Python 2

This project also runs python 2.7 code as a submodule. This means some additional setup is required.
Install pip for python 2.7 and the virtualenv module.

    wget https://bootstrap.pypa.io/pip/2.7/get-pip.py && sudo python2.7 get-pip.py

    python2.7 -m pip install virtualenv

Create and activate a python2.7 virtual environment.

    python2.7 -m virtualenv smb/env

    source smb/env/bin/activate

Install the requirements inside the smb virtual environment.

    python2.7 -m pip install -e smb/.
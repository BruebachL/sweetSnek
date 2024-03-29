#!/bin/bash
# Add custom repo to install Python 3.10.
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa
# Install Python 3.10 needed for Logging Server and most submodules.
sudo apt install python3.10
# Create and activate virtual environment.
python3.10 -m venv env
source env/bin/activate
# Install required dependencies and project as editable module.
python3.10 -m pip install -e .
deactivate
# Ubuntu comes with Python 2.7 but Python itself does not come with pip, required to install dependencies, so we explicitly install it.
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py && sudo python2.7 get-pip.py
# Install Python 2.7 development headers required by dependencies.
sudo apt install python-dev
# Virtual environment module isn't provided by default in Python 2.7, so we need to explicitly install it.
python2.7 -m pip install virtualenv
# Create and activate virtual environment.
python2.7 -m virtualenv honey_smb/HoneySMB2/env
source honey_smb/HoneySMB2/env/bin/activate
# Honey SMB depends on the honey log package of the main module so we need to install a mock version here.
# Shuffle setup files around.
mv setup.py setup3.10.py
mv setup2.7.py setup.py
mv requirements.txt requirements3.10.txt
mv requirements2.7.txt requirements.txt
# Install mock main module.
pip install -e .
# Shuffle setup files back.
mv setup.py setup2.7.py
mv setup3.10.py setup.py
mv requirements.txt requirements2.7.txt
mv requirements3.10.txt requirements.txt
# Install required dependencies and Honey SMB submodules as editable module.
python2.7 -m pip install -e honey_smb/HoneySMB2/.
deactivate
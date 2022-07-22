from setuptools import setup, find_packages

import smb

setup(
    name=smb.__title__,
    version=smb.__version__,
    author="Lukas Brübach",
    author_email="Lukas.Bruebach@Student.FHWS.de",
    classifiers=[
        "Development Status :: 0 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Security",
    ],
    package_data={
        "": ["*.txt", "*.md"],
    },
    packages=find_packages(),
    python_requires=">=2.7",
    install_requires=[
        "netifaces==0.11.0",
        "scapy @ git+https://github.com/secdev/scapy@2c92b0350ab5df8ea0adc164fb4441c979bec568#egg=scapy",
        "NetfilterQueue",
        "asgiref",
        "Flask",
    ],
    include_package_data=True,
    long_description=open("README.md").read(),
    url="https://github.com/BruebachL/sweetSnek",
    description="HoneySMB submodule of sweetSnek",
    zip_safe=False
)

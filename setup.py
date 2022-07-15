from setuptools import setup, find_packages

import osfingerprinting

setup(
    name=osfingerprinting.__title__,
    version=osfingerprinting.__version__,
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
    python_requires=">=3.9",
    install_requires=[
        "requests==2.28.1",
        "netifaces==0.11.0",
        "scapy @ git+https://github.com/secdev/scapy@2c92b0350ab5df8ea0adc164fb4441c979bec568#egg=scapy",
        "NetfilterQueue",
        "aiohttp",
        "asgiref"
    ],
    include_package_data=True,
    long_description=open("README.md").read(),
    url="https://github.com/mushorg/oschameleon",
    description="OS Fingerprint Obfuscation for modern Linux Kernels",
    zip_safe=False
)

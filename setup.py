from setuptools import setup, find_packages

setup(
name="recon-tool",
version="2.0.0",
description="Website Reconnaissance & Vulnerability Scanner",
author="Aviraj Shinde",
license="MIT",
packages=find_packages(),
install_requires=[
"requests>=2.28.0",
"dnspython>=2.4.0",
"python-nmap>=0.7.1",
"python-whois>=0.8.0",
"shodan>=1.30.0",
"beautifulsoup4>=4.12.0",
"colorama>=0.4.6",
"reportlab>=4.0.0",
"urllib3>=1.26.0"
],
entry_points={
"console_scripts": [
"recon-tool=recon-tool.main:main"
]
},
python_requires=">=3.8",
)

[metadata]
name = recon-scanner
version = 2.0
author = Aviraj Shinde
description = CLI Website Reconnaissance & Vulnerability Scanner
long_description = file: README.md
long_description_content_type = text/markdown
license = MIT
license_files = LICENSE
classifiers =
    Programming Language :: Python :: 3
    License :: OSI Approved :: MIT License
    Operating System :: OS Independent
    Intended Audience :: Information Technology
    Topic :: Security

[options]
packages = find:
python_requires = >=3.8
install_requires =
    requests>=2.31.0
    dnspython>=2.4.2
    python-nmap>=0.7.1
    python-whois>=0.8.0
    beautifulsoup4>=4.12.2
    colorama>=0.4.6
    reportlab>=4.0.7
    urllib3>=2.0.7

[options.entry_points]
console_scripts =
    recon-scanner = recon_scanner.scanner:main

[options.package_data]
* = *.txt, *.md

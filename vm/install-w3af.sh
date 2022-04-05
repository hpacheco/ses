#!/bin/bash
apt -y install git python-pip
git clone https://github.com/andresriancho/w3af.git --depth 1
chmod +x w3af/w3af_*

# installation for w3af_console
apt -y install libssl1.0-dev graphviz python-lxml
apt -y build-dep python-lxml
sed -i "s/'pyOpenSSL', '0.15.1'/'pyOpenSSL', '16.2.0'/g" w3af/w3af/core/controllers/dependency_check/requirements.py
pip install pyClamd==0.3.15 PyGithub==1.21.0 GitPython==2.1.3 pybloomfiltermmap==0.3.14 esmre==0.3.1 phply==0.9.1 nltk==3.0.1 chardet==2.1.1 tblib==0.2.0 pdfminer==20140328 futures==2.1.5 ndg-httpsclient==0.3.3 lxml==3.4.4 scapy-real==2.2.0-dev guess-language==0.2 cluster==1.1.1b3 msgpack-python==0.4.4 python-ntlm==1.0.1 halberd==0.2.4 darts.util.lru==0.5 Jinja2==2.7.3 vulndb==0.0.19 markdown==2.6.1 psutil==2.2.1 mitmproxy==0.13 ruamel.ordereddict==0.4.8 Flask==0.10.1 tldextract==1.7.2 pyOpenSSL==16.2.0

# installation for w3af_gui
pip install xdot==0.6
apt -y install python-gtk2-dev python-gtksourceview2 libwebkitgtk-1.0-0
wget http://ftp.cn.debian.org/debian/pool/main/p/python-support/python-support_1.0.15_all.deb
wget http://ftp.cn.debian.org/debian/pool/main/p/pywebkitgtk/python-webkit_1.1.8-3_amd64.deb
wget http://ftp.cn.debian.org/debian/pool/main/p/pywebkitgtk/python-webkit-dev_1.1.8-3_all.deb
dpkg -i python-support_1.0.15_all.deb
dpkg -i python-webkit_1.1.8-3_amd64.deb
dpkg -i python-webkit-dev_1.1.8-3_all.deb
rm *.deb

sudo apt install -y zaproxy niktos npm
pip install semgrep
echo 'export PATH=$PATH:/home/kali/.local/bin' >> ~/.profile
source ~/.profile
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
sudo npm install -g snyk snyk-to-html
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
wget https://github.com/jeremylong/DependencyCheck/releases/download/v6.5.3/dependency-check-6.5.3-release.zip
unzip dependency-check-6.5.3-release.zip  
